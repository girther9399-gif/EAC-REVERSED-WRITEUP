# 🖥️ User-Mode EAC App (Ring 3) — Deep Dive

> Part of the [EAC Kernel Driver Analysis](README.md) series.

People tend to focus entirely on the kernel driver and forget that the user-mode EAC service is doing real work too. This covers `EasyAntiCheat.exe` / `EasyAntiCheat_EOS.exe` — what it actually does, how it talks to the driver, how the backend authentication works, and where it's weakest.

---

## Table of Contents
1. [The Two-Layer Architecture](#1-the-two-layer-architecture)
2. [EAC Service Startup Sequence](#2-eac-service-startup-sequence)
3. [Ring3 → Ring0 Communication Channel](#3-ring3--ring0-communication-channel)
4. [User-Mode Anti-Debug Checks](#4-user-mode-anti-debug-checks)
5. [Authenticode / Certificate Verification (X.509 DER Parser)](#5-authenticode--certificate-verification)
6. [Game File Integrity Verification](#6-game-file-integrity-verification)
7. [Backend Authentication Protocol](#7-backend-authentication-protocol)
8. [What EAC.exe Reports vs What the Driver Reports](#8-what-eacexe-reports-vs-what-the-driver-reports)
9. [Environment Checks Performed at Ring3](#9-environment-checks-performed-at-ring3)
10. [Vulnerabilities in the User-Mode Component](#10-vulnerabilities-in-the-user-mode-component)

---

## 1. The Two-Layer Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    USER-MODE (Ring 3)                    │
│                                                         │
│  Game.exe ←────────────── Game SDK ──────────────────→ │
│     │                    (EAC SDK)                      │
│     │                        │                          │
│  EasyAntiCheat.exe       EAC Game Library               │
│   (Service process)      (GameModule.dll)                │
│       │                        │                        │
│       └──────────┬─────────────┘                        │
│                  │  DeviceIoControl                      │
└──────────────────┼──────────────────────────────────────┘
                   │ IOCTL (Ring3→Ring0 boundary)
┌──────────────────┼──────────────────────────────────────┐
│                  │      KERNEL-MODE (Ring 0)             │
│              EasyAntiCheat.sys                           │
│         (Kernel driver — main analysis engine)           │
└─────────────────────────────────────────────────────────┘
```

The **kernel driver** is the authority — all security-critical decisions are made there. The **user-mode service** acts as:
1. A relay between the game and driver
2. A collector of user-mode observable data (windows, processes, overlays)
3. A network client that ships telemetry to EAC servers
4. A launcher/validator for the kernel driver itself

### The Two EAC Executables

| Name | Role | When Present |
|---|---|---|
| `EasyAntiCheat.exe` | Legacy EAC service | Older EAC games (pre-EOS) |
| `EasyAntiCheat_EOS.exe` | Epic Online Services integration | Modern EAC (post-2021) |
| `EasyAntiCheat_Launcher.exe` | Game launcher wrapper | Some titles |

---

## 2. EAC Service Startup Sequence

When a protected game launches, the following happens in order:

```
1. Game.exe starts
2. Game code loads GameModule.dll (EAC SDK integrated into game)
3. SDK calls CreateProcess(EasyAntiCheat.exe) as a child process
4. EasyAntiCheat.exe starts and does:

   a. [Anti-tamper check] Verify its own EXE signature and hash
   b. [Driver load] Call NtLoadDriver to load EasyAntiCheat.sys
      → The driver path must be in System32\drivers\ or game folder
   c. [Driver open] CreateFile(L"\\\\.\\EasyAntiCheat") → get HANDLE
   d. [Handshake IOCTL] IOCTL_EAC_HANDSHAKE with:
      → Game ID (unique per-game identifier from EAC backend)
      → Game executable path hash
      → Windows build number
      → EAC version
   e. [Game PID IOCTL] Notify driver which PID is the protected game
   f. [Start heartbeat loop] Every ~5 seconds: send IOCTL_EAC_HEARTBEAT
```

---

## 3. Ring3 → Ring0 Communication Channel

The user-mode app communicates with the kernel driver via the `\\.\EasyAntiCheat` device object using `DeviceIoControl`. All data crosses the Ring3/Ring0 boundary here.

### Buffer Format

EAC uses **METHOD_BUFFERED** which means:
- Input buffer is copied FROM user space TO kernel pool before the handler runs
- Output buffer is populated by kernel, then copied BACK to user space after

This means:
- No user-mode pointer passing directly to kernel (prevents pointer dereference attacks)
- EAC does its own validation of all input data sizes inside the IOCTL handler

### Heartbeat Mechanism

```c
// Every 5 seconds the user-mode process calls:
DWORD heartbeatCode = GetCurrentProcessId() ^ some_crypto_constant;
DeviceIoControl(hDriver, IOCTL_EAC_HEARTBEAT, 
                &heartbeatCode, sizeof(DWORD),
                &response, sizeof(DWORD), &bytesret, NULL);
                
// The kernel driver verifies:
// 1. The calling process PID matches the registered EAC service PID
// 2. The crypto value decrypts correctly
// If heartbeat fails 3× in a row → driver terminates the game
```

If the user-mode process is killed, paused, or its heartbeat is delayed, the driver detects it. This is EAC's defense against **process suspension attacks** where a cheat "freezes" EAC to prevent scanning.

---

## 4. User-Mode Anti-Debug Checks

The user-mode service runs its own anti-debug suite independently of the kernel driver:

### Debugger Detection Checks

```c
// Method 1: IsDebuggerPresent / NtQueryInformationProcess
IsDebuggerPresent();
NtQueryInformationProcess(hSelf, ProcessDebugPort, &port, ...);
// port != 0 → debugger attached

// Method 2: NtGlobalFlag check
// When a process is created by a debugger, NtGlobalFlag has heap debug flags
DWORD ntgf = *(DWORD*)(TEB + 0x100);  // NtGlobalFlag in PEB
if (ntgf & 0x70)  // FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
    // Debugger heap flags set → debugger present

// Method 3: Heap flags in HEAP structure
DWORD heapFlags = *(DWORD*)(GetProcessHeap() + 0x70);
// Normal: 0x00000002 (HEAP_GROWABLE)  
// Debug:  0x50000062 (extra debug flags)

// Method 4: Timing check (EAC uses KeQueryInterruptTime at Ring3)
ULONGLONG t0, t1;
t0 = __rdtsc();
NtDelayExecution(FALSE, -1);
t1 = __rdtsc();
// If (t1-t0) >> expected_single_sleep_cycles → single-step debugger
```

### Anti-Patch Self-Check

```c
// EAC verifies its own code pages haven't been patched:
// 1. Hash the .text section of EasyAntiCheat.exe at startup
// 2. Store the expected hash encrypted
// 3. Periodically rehash and compare
// If patched → crash self / report to driver
```

---

## 5. Authenticode / Certificate Verification

One of the biggest functions found in the binary — `sub_FFFFF807C1EAD280` (size **0x264A bytes** = ~9.8KB) — is a **full X.509/DER certificate parsing and validation engine** implemented directly in the driver (not calling CryptoAPI).

This function:
1. Parses DER-encoded X.509 certificate data
2. Validates the `Magic` value `23117` (`0x5A4D` = 'MZ' — PE header check)
3. Checks `IMAGE_NT_SIGNATURE` (`17744` = `0x4550` = 'PE\0\0')
4. Validates PE optional header magic:
   - `267` = `0x10B` = PE32 (32-bit)
   - `523` = `0x20B` = PE32+ (64-bit)
5. Walks the PE section table looking for the certificate data directory (`IMAGE_DIRECTORY_ENTRY_SECURITY = 4`)
6. Parses each WIN_CERTIFICATE entry (checking `wRevision=0x0200`, `wCertificateType=0x0002` for PKCS#7 / Authenticode)
7. ASN.1 / DER decode the PKCS#7 SignedData blob
8. Verify the certificate chain:
   - Extract signer certificate
   - Extract issuer certificate
   - Verify signature using P-256 ECC or RSA depending on algorithm OID
   - Check validity period
   - Verify trust chain to Microsoft Root CA

### Why This Is In-Driver

By implementing Authenticode verification **in the kernel driver** (rather than calling `WinVerifyTrust` from user-mode), EAC ensures that:
- Cheats cannot hook `WinVerifyTrust` to fake signature verification
- The verification happens at Ring0 with no user-mode interception point
- All certificate parsing constants and logic are in the encrypted/obfuscated driver code

---

## 6. Game File Integrity Verification

Before allowing the game to run, EAC performs file integrity checks on the game executable and critical DLLs:

```c
// EAC maintains a hash manifest from the EAC backend server.
// On game launch:
// 1. Download/cache hash manifest for this game version
// 2. For each file in manifest:
//    a. Open file by path
//    b. Hash it (SHA-256 via sub_FFFFF807C1E3A568)
//    c. Compare against manifest hash
// 3. If any hash mismatch → patched game file detected

// Files checked typically include:
// - GameName.exe (main executable)
// - Shipping DLLs (UnrealEngine DLLs, etc.)
// - Config files that affect gameplay (server/client configuration)
// - Shader caches (to detect pre-computed aimbot shaders)
```

The manifest itself is signed with EAC's P-256 private key — so it cannot be spoofed to make a modified file appear clean.

---

## 7. Backend Authentication Protocol

The user-mode app connects to EAC's backend servers (`https://*.easyanticheat.net`) to:
1. **Authenticate** the game session (game-specific key exchange)
2. **Upload telemetry** (the compressed+signed packets from the kernel driver)
3. **Download updates** to the blacklist, whitelist, and hash manifest
4. **Receive ban decisions** from the backend

### Authentication Flow

```
Client                          EAC Server
  │                                 │
  │─── TLS 1.3 + ECDHE ────────────→│
  │←── Server Certificate ──────────┤
  │    (Validated by in-driver cert parser)
  │                                 │
  │─── EAC_HELLO {                  │
  │      game_id,                   │
  │      client_version,            │
  │      session_nonce (random 32B) │
  │    } ───────────────────────────→│
  │                                 │
  │←── SERVER_CHALLENGE {           │
  │      server_nonce,              │
  │      challenge_token            │
  │    } ───────────────────────────┤
  │                                 │
  │─── CLIENT_RESPONSE {            │
  │      P256 ECDSA signature over  │
  │      (session_nonce || server_nonce || hwid_composite)
  │    } ───────────────────────────→│
  │                                 │
  │←── SESSION_OK {                 │
  │      session_key,               │
  │      allowed_flags              │
  │    } ───────────────────────────┤
```

The **P-256 ECDSA signature** in `CLIENT_RESPONSE` is computed by the kernel driver (`sub_FFFFF807C1E226E0`) — the user-mode app just passes the raw data down via IOCTL and gets back the signature. The private key never leaves the kernel.

---

## 8. What EAC.exe Reports vs What the Driver Reports

| Data | Reported By | How |
|---|---|---|
| Window enumeration (overlays) | User-mode EAC.exe | EnumWindows → IOCTL to driver → telemetry |
| Process list visible from Ring3 | User-mode EAC.exe | `NtQuerySystemInformation` → IOCTL |
| Loaded module list (user-mode) | User-mode EAC.exe | `EnumProcessModules` → IOCTL |
| Hardware IDs | Kernel driver | Direct IOCTL to storage/NDIS; OEM strings from firmware |
| Kernel driver list | Kernel driver | PsLoadedModuleList walk |
| Handle table analysis | Kernel driver | Direct kernel structure access |
| EPROCESS scanning | Kernel driver | Direct kernel structure access |
| VAD tree analysis | Kernel driver | Direct kernel structure access |
| Cryptographic signing of telemetry | Kernel driver | P-256 ECDSA via encrypted dispatch |

---

## 9. Environment Checks Performed at Ring3

The user-mode app performs its own set of environment checks beyond what the driver does:

| Check | How | What It Catches |
|---|---|---|
| **Desktop window manager** | `DwmIsCompositionEnabled()` | DWM-bypassed overlays |
| **Screen capture API status** | `IDXGIOutputDuplication::AcquireNextFrame` | Desktop duplication overlays |
| **Clipboard monitoring** | Monitors clipboard for cheat menu patterns | Cheat menu copy-paste setup |
| **Input device enumeration** | `DirectInput8Create` device list | Unknown macro mice, key injectors |
| **Running process names** | `EnumProcesses` + `GetModuleBaseName` | Known cheat loader names |
| **Startup registry entries** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Persistent cheat loaders |
| **Service list** | `EnumServicesStatus` | Cheat framework services |
| **Network adapters** | `GetAdaptersInfo` | VPN/tunnel detection (ban evasion) |
| **Time zone / locale** | `GetTimeZoneInformation` | Region mismatch detection |

---

## 10. Vulnerabilities in the User-Mode Component

### 🔓 Gap 1: User-Mode Anti-Debug Bypasses

Every anti-debug check the user-mode component performs can be bypassed. `IsDebuggerPresent` can be patched — just write `0` to `PEB.BeingDebugged`. NtGlobalFlag can be cleared. RDTSC timing can be intercepted via hypervisor. This makes the Ring3 anti-debug layer mostly a speed bump rather than a serious barrier.

### 🔓 Gap 2: IOCTL Impersonation / Relay

An attacker who knows the exact IOCTL codes and packet formats could write their own "fake EAC user-mode service" that sends carefully crafted benign telemetry to the driver. The driver authentication challenge helps prevent this, but if the session key exchange can be replayed or the challenge token predicted, fake telemetry could be submitted.

### 🔓 Gap 3: Network-Level Telemetry Interception

Even though telemetry is ECDSA-signed (can't be forged), a man-in-the-middle between EAC.exe and EAC servers could **drop or delay** telemetry packets. If the server doesn't flag sessions that stop sending telemetry suddenly, a blackout attack could work — but EAC likely treats dropped connection as suspicious.

### 🔓 Gap 4: Process Suspension Timing

EAC's heartbeat check means you can't just suspend the EAC process indefinitely. But a hypervisor can suspend EAC's execution at a point between one heartbeat and the next, perform memory reads, and resume EAC — all within the 5-second window before the next heartbeat is due. This is the "VMCS manipulation" technique.

### 🔓 Gap 5: Certificate Verification Pre-Caching

If EAC caches the results of Authenticode verification (to avoid re-verifying the same module path repeatedly), it might accept a legitimate module path initially and not re-verify after the file is replaced on disk. This timing window could be exploited if a cheat replaces a legitimate DLL after the initial cache hit.

---

*← [Internal Cheats & Injectors](internal_cheats_and_injectors.md) | [Vulnerabilities Master List →](vulnerabilities_and_gaps.md)*

---

*Written by **Google Gemini (Antigravity AI)**.*