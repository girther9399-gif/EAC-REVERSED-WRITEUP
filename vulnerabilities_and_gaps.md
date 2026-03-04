# 🔓 EAC Vulnerabilities & Detection Gaps — Master Reference

> Part of the [EAC Kernel Driver Analysis](README.md) series.
>
> **Note:** This is a research and educational document. These are weaknesses identified through static binary analysis of the driver — documenting gaps in detection logic, not a guide to exploit them.

Honestly, EAC is one of the better anti-cheats out there. But no anti-cheat is perfect, and the gaps here are real — some of them fundamental to the kernel architecture EAC runs in. This is a full rundown of every weakness we found across every subsystem, with severity ratings and an honest look at how hard each one is to actually exploit.

---

## Severity Legend

| Rating | Meaning |
|---|---|
| 🔴 **CRITICAL** | Completely bypasses EAC detection; practical to exploit |
| 🟠 **HIGH** | Bypasses a specific detection layer; requires some skill to exploit |
| 🟡 **MEDIUM** | Bypasses one check but other checks remain; partial evasion |
| 🟢 **LOW** | Theoretical or requires exotic hardware/privileges |

---

## Table of Contents
1. [External Cheat Gaps](#1-external-cheat-gaps)
2. [Internal Cheat / Injector Gaps](#2-internal-cheat--injector-gaps)
3. [Spoofer Detection Gaps](#3-spoofer-detection-gaps)
4. [User-Mode EAC App Gaps](#4-user-mode-eac-app-gaps)
5. [Kernel Driver Architecture Gaps](#5-kernel-driver-architecture-gaps)
6. [Cryptographic & Protocol Gaps](#6-cryptographic--protocol-gaps)
7. [General Analysis Observations](#7-general-analysis-observations)

---

## 1. External Cheat Gaps

### 🔴 GAP-EXT-01: DMA (Direct Memory Access) Hardware Attacks
**Summary**: A PCIe device (FPGA or dedicated DMA hardware) can read the host machine's physical RAM over the PCIe bus directly. No software runs on the victim machine — no driver, no handle, no kernel module.

**Why EAC Misses It**:
- No kernel driver to detect (DMA device doesn't appear in `PsLoadedModuleList`)
- No process handle opened (handle table scanner finds nothing)
- No network footprint on the victim machine (commands sent via PCIe to a second computer)

**Evidence from IDA**: EAC's entire detection suite assumes software execution on the victim machine. There is no anti-DMA hardware enumeration found in the analyzed binary.

**Mitigation EAC Could Add**: Server-side behavior analysis (abnormal aim patterns, impossible reaction times).

---

### 🔴 GAP-EXT-02: Driver-Level Kernel Memory Read (No Process Handle)
**Summary**: An attacker with a loaded kernel driver can call `MmCopyMemory(targetProcess, ...)` to read any process's memory without opening a process handle. `MmCopyMemory` accepts an EPROCESS pointer directly.

**Why EAC Misses It**:
- `MmCopyMemory` doesn't create a handle entry → handle scanner finds nothing
- If the reader driver is itself unlisted from `PsLoadedModuleList` (DKOM), it's invisible to module scanner
- DKOM + MmCopyMemory = effectively undetectable without physical memory scan  

**Mitigation EAC Has**: Physical memory scan for hidden PE images (`EAC DKOM counter-measure` in `detection_methods.md`). However, a driver that perfectly cleans its PE header from physical memory can still evade this.

---

### 🟠 GAP-EXT-03: Handle Pre-Open Before EAC Initializes
**Summary**: If an attacker opens a handle to the game process before EAC starts monitoring and closes it immediately after reading needed data, EAC's periodic handle table scan never sees the handle.

**Exploitation Difficulty**: Medium — requires knowing exactly when EAC initializes relative to game startup and having code ready to execute in that window.

---

### 🟠 GAP-EXT-04: Process Name Whitelisting Bypass
**Summary**: EAC whitelists certain known-good processes (NVIDIA overlay, etc.) by image name. A cheat that names its executable to match a whitelisted name may avoid initial flagging.

**Incomplete Mitigation**: EAC likely also checks the full module path and signature, but if the path check is not implemented or caches results, impersonation may work briefly.

---

### 🟡 GAP-EXT-05: PROCESS_QUERY_LIMITED_INFORMATION Only
**Summary**: Opening the game process with `PROCESS_QUERY_LIMITED_INFORMATION` alone doesn't grant memory access. A cheat could use this to find the game's module base via `NtQueryInformationProcess(ProcessBasicInformation)` and then use a kernel driver for the actual memory read — splitting the attack across two techniques that each look less suspicious individually.

---

## 2. Internal Cheat / Injector Gaps

### 🔴 GAP-INJ-01: VAD Node DKOM (Kernel VAD Manipulation)
**Summary**: A kernel driver can directly manipulate VAD tree nodes — unlinking an injected region from the VAD tree entirely, or changing its type from "private executable" to "mapped image." An injected region that appears to be a legitimate file-backed image with a valid section object will pass EAC's VAD scan.

**Exploitation Difficulty**: Very high — incorrect VAD manipulation causes immediate BSOD. However, sophisticated attackers have demonstrated this works with careful implementation.

**Severity**: CRITICAL because it defeats the primary internal detection mechanism.

---

### 🟠 GAP-INJ-02: Early Injection Window (Before EAC First Scan)
**Summary**: EAC initializes during game startup, but there is a window between when the Windows loader maps game DLLs and when EAC completes its initial scan. An injector that completes before this window closes gets scanned — but if the injected DLL is a legitimate signed binary containing a subsequent secondary payload load, the initial scan passes.

---

### 🟠 GAP-INJ-03: Thread Pool Execution Hijacking
**Summary**: Instead of creating a new thread (which fires `PsSetCreateThreadNotifyRoutine`), an attacker can queue work to an existing thread pool thread. Thread pool threads have valid, whitelisted start addresses (inside ntdll/kernelbase). EAC's thread creation callback never fires.

**Mitigation EAC Has**: Periodic scanning of running threads' instruction pointers, but this has a polling gap.

---

### 🟠 GAP-INJ-04: APC Injection After-Execution
**Summary**: User-mode APCs execute when a thread enters an alertable wait. By the time EAC polls and finds no pending APCs, the APC has already executed, loaded the DLL, and the queue is empty. EAC then must rely on the module-appeared-in-PEB detection, which catches it — but only after the injection has already succeeded.

---

### 🟡 GAP-INJ-05: Signed DLL Exploit Chain (ROP/Heap Spray)
**Summary**: Load an entirely legitimate, signed DLL that happens to have an exploitable vulnerability. Use a ROP chain or heap spray within that DLL's code to achieve code execution. From EAC's perspective, only legitimate DLLs are loaded — no injection signature.

---

### 🟡 GAP-INJ-06: Section Object Replacement (File-on-Disk Swap)
**Summary**: Create a memory-mapped section backed by a crafted file. The file passes Authenticode because it's legitimately signed. After the section is created and cached, replace the file on disk with cheat code. If EAC re-reads the file for hash verification, it reads the cached section (not the new file). The injected code runs from a "signed" section.

**Mitigation**: If EAC does file hash checks on open file handles (not cached paths), this is blocked. Unknown from static analysis alone.

---

## 3. Spoofer Detection Gaps

### 🔴 GAP-SPF-01: DMA-Based Firmware Reprogramming (Offline Spoofer)
**Summary**: Physically reflash the storage device's firmware (common with M.2 NVMe drives using custom firmware tools) to return a custom serial number at the ATA level. EAC's raw ATA IDENTIFY command gets the fake value — there's no higher layer to catch it because the lie happens in drive firmware.

**Evidence from IDA**: EAC reads raw ATA serial via `IOCTL_ATA_PASS_THROUGH`, trusting it completely. There's no cross-reference to firmware integrity or signed drive certificate.

---

### 🟠 GAP-SPF-02: SMBIOS Emulation via Hypervisor
**Summary**: A Type-1 hypervisor (running below Windows/EAC) can intercept and modify the firmware table query (`SystemFirmwareTableInformation`) at the hypervisor level before EAC ever sees the result. Even EAC's MmMapIoSpace physical-memory read of ACPI tables can be intercepted by a hypervisor that controls EPT (Extended Page Tables).

**Exploitation Difficulty**: Requires setting up a custom hypervisor — very sophisticated but well-documented (examples: HVPP, SimpleSvm).

---

### 🟠 GAP-SPF-03: GPU PnP Instance ID Not Cross-Verified
**Summary**: EAC reads the GPU PnP Instance ID from the Windows device tree (`DEVPKEY_Device_InstanceId`). This value comes from PnP manager's registry cache — not directly from PCI config space. A driver that modifies the correct registry key (HKLM\SYSTEM\CurrentControlSet\Enum\PCI\...) before EAC reads it could feed a fake GPU ID.

**Mitigation**: Registry writes may require SYSTEM privileges and restart to take effect; and the PnP manager may not immediately reflect changes during a live session.

---

### 🟡 GAP-SPF-04: NDIS PERMANENT_ADDRESS on Some Adapters
**Summary**: EAC specifically asks for `OID_802_3_PERMANENT_ADDRESS` (burned-in MAC) rather than `OID_802_3_CURRENT_ADDRESS` (software-settable). However, some USB WiFi adapters and many virtual adapters store their "permanent" address in EEPROM that IS writable via the adapter's own management software — making `PERMANENT_ADDRESS` spoofable on those platforms.

---

### 🟡 GAP-SPF-05: Volume GUID Registry Persistence
**Summary**: The volume GUID stored in `HKLM\SYSTEM\MountedDevices` is writable with SYSTEM privileges. An offline spoofer could modify this value matching whatever ATA serial spoofed value is returned, eliminating the cross-source inconsistency that EAC looks for.

---

## 4. User-Mode EAC App Gaps

### 🔴 GAP-UM-01: All Ring3 Anti-Debug Trivially Bypassed
**Summary**: Every user-mode anti-debug check (PEB.BeingDebugged, NtGlobalFlag, heap flags, RDTSC timing) can be bypassed. `PEB.BeingDebugged` can be patched to 0. ScyllaHide and similar tools do this automatically.

**Impact**: Ring3 EAC can be debugged freely without ring0 consequences — useful for reconnaissance of IOCTL protocol and behavior.

---

### 🟠 GAP-UM-02: Process Suspension Within Heartbeat Window
**Summary**: EAC's heartbeat is every ~5 seconds. A hypervisor or kernel driver can pause EAC for 4.99 seconds, perform a scan pass with an external tool, then resume EAC before the next heartbeat deadline.

---

### 🟠 GAP-UM-03: User-Mode Window Enumeration Hookable
**Summary**: EAC's overlay detection uses `EnumWindows` which calls user-mode callbacks. A cheat that hooks `EnumWindows` (or the underlying `NtUserBuildHwndList`) in the EAC process could hide overlay windows from EAC's enumeration.

**Complication**: EAC may verify its own function hooks periodically; and kernel-mode window enumeration exists as a fallback.

---

### 🟡 GAP-UM-04: IOCTL Protocol Analysis via Emulation
**Summary**: Since the EAC user-mode app can be debugged (see GAP-UM-01), an attacker can trace all `DeviceIoControl` calls to learn the exact IOCTL codes and packet formats. This enables building a custom relay that sends exactly the "clean" telemetry the server expects.

---

## 5. Kernel Driver Architecture Gaps

### 🟠 GAP-KRN-01: PatchGuard Timing Window
**Summary**: PatchGuard (Kernel Patch Protection) validates critical structures periodically (random interval, roughly every 3-10 minutes). Between validations, kernel structures can be temporarily modified and restored. EAC's periodic scanning also has a polling gap.

**Combined Attack**: Modify VAD node between EAC's scan + PatchGuard validation → read/write game memory → restore before either catches it.

---

### 🟠 GAP-KRN-02: Physical Memory Scan Has Coverage Limits
**Summary**: EAC scans physical memory pages looking for hidden PE images (DKOM-hidden drivers). However, this scan is computationally expensive and likely only covers pages in specific ranges (kernel non-paged pool, driver section range). A driver that loads outside the typical address range or uses paged pool may avoid the scan.

---

### 🟡 GAP-KRN-03: Encrypted API Call Constants Are Static Per-Build
**Summary**: EAC's encrypted function dispatch uses constants like `0x936ACF702E4281A9` that are compile-time constants baked into the binary. Once extracted from one binary build, an attacker knows exactly which constant corresponds to which API. This knowledge persists until EAC rebuilds with new constants.

**Impact**: Makes reverse engineering significantly easier once any single build has been analyzed (like this one).

---

### 🟡 GAP-KRN-04: Callback Table Registration Is Visible
**Summary**: EAC registers callbacks via `PsSetCreateProcessNotifyRoutine`, `PsSetCreateThreadNotifyRoutine`, etc. These callback registrations are visible to other kernel code — a sophisticated attacker could enumerate the callback table and find EAC's callback function addresses, potentially patching them to no-ops.

**Mitigation**: PatchGuard monitors the callback tables — patching them risks a BSOD/bugcheck.

---

## 6. Cryptographic & Protocol Gaps

### 🟡 GAP-CRY-01: P-256 Private Key Extraction via Hypervisor
**Summary**: EAC's P-256 private key never leaves kernel address space and is never written to disk. However, a hypervisor with EPT control can set breakpoints at EAC's `P256_ScalarMul` function and extract the scalar (private key) from CPU registers during execution.

**Difficulty**: Requires a custom hypervisor that doesn't trigger EAC's hypervisor detection (EAC checks the CPUID hypervisor bit and vendor string).

---

### 🟡 GAP-CRY-02: Telemetry Replay Not Verifiable Client-Side
**Summary**: EAC's telemetry signature prevents forgery, but once a valid signed packet is sent, the server has no way to know if that packet represents current state or was replayed from a previous "clean" scan. If an attacker freezes EAC's telemetry dispatch and replays old clean signatures, the server may not flag the session.

**Mitigation EAC Has**: Timestamps (`KUSER_SHARED_DATA.TickCountLow` + `KeQuerySystemTime`) are signed with each packet — replayed packets have stale timestamps. The server should reject packets with timestamps more than N seconds old.

---

## 7. General Analysis Observations

### What EAC Does Very Well
| Strength | Why It's Strong |
|---|---|
| **Multi-source HWID** | Cross-source inconsistency detection makes partial spoofers detectable |
| **In-kernel Authenticode** | No user-mode hook can fake driver signature verification |
| **Encrypted function dispatch** | Makes static analysis of API usage significantly harder |
| **P-256 signed telemetry** | Server can verify telemetry hasn't been tampered with |
| **VAD tree scanning** | Catches manual maps without relying on PEB module list |
| **Physical memory PE scan** | Catches DKOM-hidden drivers |
| **Hard-coded timestamp cross-reference** | Two independent time sources makes time manipulation detectable |

### What Requires Attacker Skill to Bypass
| Defense | Skip Difficulty |
|---|---|
| VAD scanning | Requires kernel driver + risky VAD manipulation |
| Handle table inspection | Requires DMA hardware OR kernel driver DKOM |
| Module signature verification | Requires BYOVD or leaked signing cert |
| Heartbeat timing | Requires hypervisor-level process control |
| HWID cross-source check | Requires spoofing 4+ independent hardware sources simultaneously |

### The Winning Attack Pattern (For Research Context)
The most sophisticated attack chain that could reliably evade EAC would require:
1. **A custom Type-1 hypervisor** (to intercept SMBIOS/firmware queries and handle EAC's hypervisor detection bypass)
2. **A BYOVD exploit** or hardware-flashed storage firmware (for HWID spoofing at the hardware level)
3. **DMA hardware** (for game memory reading without any software footprint on the victim machine)
4. **No DKOM** (don't hide any drivers — too risky with EAC's physical memory scan + PatchGuard)

This combination sidesteps virtually every detection vector analyzed in this binary. The cost and complexity of this combination is why EAC is considered one of the stronger anti-cheats — defeating it comprehensively requires hardware-level resources.

---

*← [User-Mode EAC App](usermode_eac_app.md) | [Back to README](README.md)*

---

*Written by **Google Gemini (Antigravity AI)**.*