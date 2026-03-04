# 👁️ External Cheat Detection — Deep Dive

> Part of the [EAC Kernel Driver Analysis](README.md) series.

External cheats are a different problem than injection. There's no DLL in the game, no thread to detect, no allocation in the game's memory — just a separate process on the machine quietly reading the game's memory from the outside using `ReadProcessMemory` or a kernel driver. This is how most ESP and aimbot software actually works. Here's how EAC deals with it.

---

## Table of Contents
1. [What Is an External Cheat?](#1-what-is-an-external-cheat)
2. [Handle-Based Detection — The #1 Detection Vector](#2-handle-based-detection)
3. [MiLookupSystemHandle — Low-Level Handle Table Walk](#3-milookup-systemhandle)
4. [Cross-Process Memory Access Pattern Detection](#4-cross-process-memory-access-pattern-detection)
5. [Thread and Process Origin Analysis](#5-thread-and-process-origin-analysis)
6. [Window and UI Overlay Detection](#6-window-and-ui-overlay-detection)
7. [Known External Cheat Driver Signatures](#7-known-external-cheat-driver-signatures)
8. [Vulnerabilities EAC Misses in External Detection](#8-vulnerabilities-eac-misses)

---

## 1. What Is an External Cheat?

An external cheat runs as a completely separate process from the game. Instead of injecting code into the game, it reads the game's memory from outside, computes useful data (enemy positions, health, etc.), and outputs it (overlays, input injection, etc.).

```
Game Process (Fortnite.exe, PUBG.exe, etc.)
     │  ← External cheat opens a HANDLE to this process
     ↑
External Cheat Process (cheat.exe)
│
├── ReadProcessMemory(hGame, EntityListAddr, ...) → reads all player data
├── Draws overlay using DirectX or GDI on top of game window
└── Optionally: sends input via SendInput/WriteProcessMemory
```

Because nothing is injected into the game process, traditional injection scanners can't find external cheats. EAC uses a completely different detection path for them.

---

## 2. Handle-Based Detection — The #1 Detection Vector

The most reliable way to catch external cheats is to find every process that holds an **open handle to the game process** with memory access permissions.

### How EAC Enumerates Handles

EAC does NOT use user-mode APIs like `NtQuerySystemInformation(SystemHandleInformation)` — those can be hooked. Instead, it walks the kernel handle table directly:

```c
// The kernel maintains a global handle table structure.
// EAC reads it directly from kernel memory.
// 
// For every process P on the system:
//   For every handle H that P holds:
//     If H.ObjectType == PROCESS (type index ~7)
//     AND H.Object == targetGameProcess  ← points to game's EPROCESS
//     THEN: check H.GrantedAccess

// The key check — what access mask was requested?
const DWORD SUSPICIOUS_ACCESS = 
    PROCESS_VM_READ        |  // 0x0010 — can read game memory
    PROCESS_VM_WRITE       |  // 0x0020 — can write game memory
    PROCESS_VM_OPERATION   |  // 0x0008 — can manipulate memory
    PROCESS_QUERY_INFORMATION; // 0x0400 — can query info

if ((grantedAccess & SUSPICIOUS_ACCESS) && ownerProcess != gameProcess)
    // Another process opened the game with memory read access → suspicious
    flag_external_cheat(ownerProcess);
```

### Access Masks That Trigger Flags

| Access Mask | Hex | Trigger Level |
|---|---|---|
| `PROCESS_VM_READ` | `0x0010` | 🔴 **Immediate flag** |
| `PROCESS_VM_WRITE` | `0x0020` | 🔴 **Immediate flag** |
| `PROCESS_VM_OPERATION` | `0x0008` | 🔴 **Immediate flag** |
| `PROCESS_ALL_ACCESS` | `0x1FFFFF` | 🔴 **Immediate flag** |
| `PROCESS_QUERY_INFORMATION` | `0x0400` | 🟡 Flag + watchlist |
| `PROCESS_QUERY_LIMITED_INFORMATION` | `0x1000` | 🟡 Flag + watchlist |
| `SYNCHRONIZE` only | `0x100000` | 🟢 Not flagged |

### Legitimate Exceptions

EAC maintains a whitelist of processes that legitimately open game handles:
- Windows Error Reporting (`WerFault.exe`)
- Antivirus products (Intel/McAfee, Defender, etc.) — matched by executable path hash
- NVIDIA overlay system (`nvcontainer.exe`, `nvoverlaycontainer.exe`)
- Steam overlay (`GameOverlayRenderer64.dll` parent)

Any process not on this whitelist with `PROCESS_VM_READ` on the game = external cheat.

---

## 3. MiLookupSystemHandle — Low-Level Handle Table Walk

Internally, EAC accesses the kernel's handle table structure directly — the same structure that `NtQuerySystemInformation(SystemHandleInformation)` reads from, but without going through the exported API.

### Handle Table Structure

```c
// Windows kernel handle table (simplified):
// HANDLE_TABLE (_EPROCESS.ObjectTable):
//   TableCode → points to ExHandleTable
//   HandleCount
//   QuotaProcess → parent process
//   UniqueProcessId

// Each handle entry (HANDLE_TABLE_ENTRY):
//   ObjectPointerBits: 59-bit encoded pointer to OBJECT_HEADER
//   GrantedAccessBits: 25-bit access mask
//   Attributes: 3-bit flags (inherit, protect from close, audit)

// To decode a handle entry:
OBJECT_HEADER* header = (OBJECT_HEADER*)(entry.ObjectPointerBits << 4);
PVOID object = (PVOID)((ULONG_PTR)header + sizeof(OBJECT_HEADER));
DWORD access = entry.GrantedAccessBits << 2;  // shift back to full mask
```

EAC walks this table by:
1. Reading `_EPROCESS.ObjectTable` to get the process handle table
2. Walking the three-level table tree (`L1 → L2 → L3` based on `TableCode & 3`)
3. For each entry, decoding the object pointer and comparing against the target game EPROCESS

This is a **purely kernel-mode operation** — there is no user-mode equivalent that works without being hookable.

---

## 4. Cross-Process Memory Access Pattern Detection

Beyond just checking who has handles open, EAC monitors **patterns of use** via kernel callbacks:

### PsSetCreateProcessNotifyRoutine

EAC registers a process creation callback. When any new process launches:
1. Check if process name/hash is in the blacklist
2. Check the process's **parent** — if it was spawned by a known cheat launcher, flag it
3. Check the process's **digital signature** — unsigned executable in certain paths = suspicious
4. Start monitoring if process subsequently opens game handle

### WindowStation and Desktop Isolation Bypass Detection

External cheats must share the same desktop session as the game to use overlays. EAC checks:
- Is there an unexpected window at the exact same Z-order position as the game window?
- Does any top-level window have `WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_LAYERED` (classic ESP overlay)?
- Does any window have `WS_EX_TOOLWINDOW` to hide from Alt+Tab?

From user-mode: EAC service (`EasyAntiCheat.exe`) calls `EnumWindows` + `GetWindowLongPtr` and reports suspicious overlays to the kernel driver via IOCTL.

---

## 5. Thread and Process Origin Analysis

### Parent Process Spoofing Detection

Some cheats spoof their parent process ID to look like they were launched by a legitimate process (e.g., pretending to be launched by `explorer.exe`). EAC detects this by cross-referencing:

1. `EPROCESS.InheritedFromUniqueProcessId` (the claimed parent PID)
2. `PsGetProcessCreationTime` of the claimed parent
3. Actual Windows job assignment and token inheritance

If a process claims `explorer.exe` as parent but has no token inherited from that process, or if the claimed parent no longer exists at that PID → **parent PID spoofing detected**.

### Signed vs. Unsigned Executable Check

For every process that opens a game handle:

```c
// Check 1: Is the .exe on disk signed?
// → VerifyImageSignature() equivalent (Authenticode check)

// Check 2: Is the on-disk hash the same as in-memory hash?
// → Detects if EXE was patched before launch to avoid signature check

// Check 3: Is the image from a suspicious path?
// → %TEMP%, %APPDATA%, C:\Users\*\Downloads = instantly suspicious  
// → System32, Program Files = whitelisted

// Check 4: Does the process have legitimate Windows manifest?
// → cheat loaders often skip embedding proper manifests
```

---

## 6. Window and UI Overlay Detection

External cheats often display an ESP overlay on top of the game. These overlays must be:
- On the same desktop as the game
- Positioned ABOVE the game in Z-order (or transparent + topmost)

EAC's user-mode component detects this via GDI enumeration:

```c
// Extended window style checks that indicate an overlay:
#define OVERLAY_STYLE (WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_LAYERED)

// Also checks for DWM composition abuse:
// Some overlays use off-screen DWM surfaces that bypass EnumWindows
// EAC checks DwmGetWindowAttribute(DWMWA_EXTENDED_FRAME_BOUNDS) 
// for all windows and finds ones positioned exactly over the game rect
```

### DirectX/GDI Hook-Based Overlays

Some overlays hook `IDXGISwapChain::Present` inside the game process to render directly using the game's GPU context. This makes them invisible to window enumeration — but this technique requires DLL injection so it falls under **internal cheat** detection.

---

## 7. Known External Cheat Driver Signatures

Many external cheats use kernel drivers to perform memory reads (bypassing handle-based detection). EAC flags these directly by driver signature via its blacklist at `aBin` / `aBin_0`:

| Driver Type | How It Bypasses Handle Detection | How EAC Detects It |
|---|---|---|
| **Physical memory mapper** | Opens `\\Device\\PhysicalMemory`, reads physical RAM directly | Module name hash; pattern in binary |
| **MmCopyMemory wrapper** | Calls kernel's `MmCopyMemory` directly via vulnerable driver | Dispatch hook on memory driver |
| **CR3 mapper** | Reads target process CR3, maps pages directly | CPUID/MSR access patterns |
| **NtReadVirtualMemory patcher** | Patches SSDT to bypass access checks | SSDT hash check |

---

## 8. Vulnerabilities EAC Misses

### 🔓 Gap 1: Kernel-to-Kernel Memory Read (No Handle Required)

A privileged kernel driver can call `MmCopyMemory` with the game's `EPROCESS` as context, bypassing the handle table entirely. Since no handle is opened, EAC's handle scanner never sees it. **Mitigation required: physical memory scan for the reader driver itself.**

### 🔓 Gap 2: Physical Memory Reading via DMA

DMA (Direct Memory Access) attacks use a secondary PCIe device (like a Screamer, PhysMemExploit stick, or Squirrel) to read the game machine's RAM over PCIe. No driver runs on the victim machine → EAC's driver scan finds nothing. DMA-based cheats are undetected by EAC at the driver level (server-side behavior analysis may catch them).

### 🔓 Gap 3: Handle Table Copy Before EAC Starts

If a cheat opens a handle to the game **before EAC initializes** and then closes it before EAC enumerates handles, EAC never sees the handle. Some cheats pre-open handles during the game's brief loading window before EAC registers its callbacks.

### 🔓 Gap 4: PROCESS_QUERY_LIMITED_INFORMATION Only Opens

Some cheats only ever use `PROCESS_QUERY_LIMITED_INFORMATION` (which doesn't grant memory access) to find the game's base address via `NtQueryInformationProcess`, then use a kernel driver for the actual read. EAC may not flag the user-mode handle because the access mask looks benign.

### 🔓 Gap 5: Process Name Impersonation

Some external cheats rename their executable to match whitelisted process names (`nvcontainer.exe`, `NVDisplay.Container.exe`). Unless EAC also checks the file path and signature (not just the image name string), a cheat in `%TEMP%\NVDisplay.Container.exe` might slip through initial name-based filtering.

---

*← [Back to README](README.md) | [Internal Cheats & Injectors →](internal_cheats_and_injectors.md)*

---

*Written by **Google Gemini (Antigravity AI)**.*