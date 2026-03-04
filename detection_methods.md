# 🔎 EAC Detection Methods — Deep Dive

> Part of the [EAC Kernel Driver Analysis](README.md) series.

---

## Table of Contents
1. [Process Scanning via EPROCESS](#1-process-scanning-via-eprocess)
2. [VAD Tree Inspection — Finding Injected Memory](#2-vad-tree-inspection)
3. [Handle Table Walking](#3-handle-table-walking)
4. [Thread Monitoring](#4-thread-monitoring)
5. [Kernel Module Enumeration](#5-kernel-module-enumeration)
6. [Kernel Integrity — SSDT & Inline Hook Detection](#6-kernel-integrity-checks)
7. [Timing & Anti-VM Detection](#7-timing--anti-vm-detection)
8. [Hash-Based Code Verification](#8-hash-based-code-verification)
9. [Indicators of Compromise Table](#9-indicators-of-compromise)

---

## 1. Process Scanning via EPROCESS

EAC's kernel driver runs at Ring-0 and has direct access to every process's internal kernel structure — the `EPROCESS` block. Unlike user-mode anti-cheats that rely on the Windows API (which can be hooked), EAC reads `EPROCESS` memory offsets **directly**, bypassing any user-mode API hooks entirely.

### Key EPROCESS Offsets Accessed

From decompilation of `sub_FFFFF807C1E1DD80` (the telemetry assembler):

```c
// EPROCESS+56  = UniqueProcessId / Token comparison
result = ((__int64 (*)(void))((0x936ACF702E4281A9uLL * v3) ^ 0xFA85638DCFA646E7uLL))();
if ( result == *(_UNKNOWN ***)(a1 + 56) )   // token/PID match check

// EPROCESS+64  = InheritedFromUniqueProcessId (Parent PID)
v56 = *(_DWORD *)(a1 + 64);

// EPROCESS+96  = ImageFileName (15-char process name)
v57 = sub_FFFFF807C1E8D840(*(_QWORD *)(a1 + 96));   // hash the image name

// EPROCESS+240 = Peb / VadRoot pointer
// packed into telemetry as 8-byte value
((void (...))(...))(0, v54, v24, 11, a1 + 240, 8);

// EPROCESS+376 = ObjectTable (handle table) or token chain
v26 = *(_QWORD *)(a1 + 376);
sub_FFFFF807C1EBF800(v26, 60, 1);   // lock + validate structure at offset

// EPROCESS+556 = protection flags / PS_PROTECTION
if ( (_DWORD)result || *(_DWORD *)(a1 + 556) )
```

### What EAC Extracts Per Process

| Field | EPROCESS Offset | Purpose |
|---|---|---|
| **Process token / PID** | `+56` | Verify running process identity |
| **Parent PID** | `+64` | Reconstruct process tree, find injectors |
| **Image filename hash** | `+96` | Match against known cheat/tool names |
| **Uptime / session** | Kernel API call | Detect fresh-VM scenarios |
| **VAD root / PEB** | `+240` | Walk virtual memory map |
| **Handle table pointer** | `+376` | Enumerate open handles |
| **Protection flags** | `+556` | Detect fake Protected Process Light |

### What "Suspicious" Looks Like

EAC compares each process against an expected baseline. Anything that doesn't match — such as a process claiming to be a system process but having a user-mode parent, or having `SeDebugPrivilege` enabled when it shouldn't — is flagged and included in the telemetry report sent to EAC servers.

---

## 2. VAD Tree Inspection

The **Virtual Address Descriptor (VAD)** tree is the internal Windows kernel data structure that describes every mapped memory region in a process. EAC walks this tree to find:

### Targets of VAD Scanning

**a) Manually Mapped PE Headers (reflective injection)**
- Legitimate DLLs always have a file-backed VAD node with an associated `FILE_OBJECT`
- Manually mapped code (reflective DLL injection, shellcode loaders) creates **private committed memory** with no associated file
- EAC looks for `VAD_NODE.u.VadFlags.PrivateMemory = 1` combined with executable protection and no file backing

**b) RWX Memory (Read-Write-Execute)**
- Legitimate code pages are either `PAGE_EXECUTE_READ` (code) or `PAGE_READWRITE` (data)
- Cheats that do runtime code patching or JIT need `PAGE_EXECUTE_READWRITE`
- Any RWX region in the game process is a red flag

**c) Suspicious Region Sizes**
- Tiny executable regions (< 4KB) that are not part of any module header
- Regions at unusual addresses not aligned to standard module boundaries

### How the VAD Walk Works in EAC

```c
// From sub_FFFFF807C1E1DD80:
v26 = *(_QWORD *)(a1 + 376);     // get handle table / structure chain
if ( v26 ) {
    sub_FFFFF807C1EBF800(v26, 60, 1);   // safe-read with size=60 bytes
    v27 = *(_QWORD *)(a1 + 376);
    v28 = 0;
    v49 = 0;
    if ( v27 ) {
        for ( i = 0; ; ++i ) {          // iterate up to 8 entries
            if ( i >= 8 ) break;
            // XOR-decode 8 bytes at offset +28 within each node
            *((_BYTE *)&v49 + i) = *(_BYTE *)(v27 + 4 * i + 28) ^ 0x90;
            v28 = v49;
        }
    }
    if ( v28 ) {
        sub_FFFFF807C1EBF800(v28, 64, 1);   // validate next structure (64 bytes)
        v30 = v28[5];   // pointer to sub-structure (52 bytes — likely MMVAD_SHORT)
        v31 = v28[6];   // module path pointer (461 bytes max)
        v32 = (_BYTE *)v28[7];   // binary fingerprint (41 bytes)
```

EAC reads linked structures at **offsets 60, 64, 52, 461, and 41 bytes** — these correspond to internal MMVAD node sizes in Windows kernel, module path UNICODE_STRING buffers, and module binary IDs.

---

## 3. Handle Table Walking

When a cheat reads game memory externally, it must open a **handle** to the game process with at minimum `PROCESS_VM_READ`. EAC detects this by:

1. **Walking the global handle table** — `ObpKernelHandleTable` and per-process handle tables accessible from `EPROCESS.ObjectTable`
2. **Checking who has handles** — For any process handle pointing to the game process, EAC notes the **opener's PID, process name, and requested access mask**
3. **Flagging suspicious access masks** — `PROCESS_VM_READ (0x0010)`, `PROCESS_VM_WRITE (0x0020)`, `PROCESS_ALL_ACCESS (0x1FFFFF)` from non-system processes are automatic red flags

```
Access masks that trigger EAC flags:
  0x0010  PROCESS_VM_READ         — external memory reader
  0x0020  PROCESS_VM_WRITE        — external memory writer  
  0x0008  PROCESS_VM_OPERATION    — VirtualProtectEx caller
  0x0400  PROCESS_QUERY_INFORMATION — info gathering
  0x1FFFFF PROCESS_ALL_ACCESS     — almost always a cheat/debugger
```

---

## 4. Thread Monitoring

EAC registers a **thread notification callback** (`PsSetCreateThreadNotifyRoutine`) which fires every time a thread is created or destroyed anywhere on the system. This allows EAC to:

- Detect **remote thread injection** — a classic DLL injection method where `CreateRemoteThread` or `NtCreateThreadEx` is used to start a thread inside the game process from an external process
- Record the **creating process** of each new thread in the game — if the thread creator isn't the game itself (or a known system component), it's suspicious
- Detect **Thread Hijacking** — where attackers suspend a legitimate game thread and redirect its `RIP` register to shellcode
- Monitor **thread start addresses** — threads starting at addresses that don't correspond to any loaded module's code section are flagged

---

## 5. Kernel Module Enumeration

EAC enumerates every loaded kernel driver using the `PsLoadedModuleList` doubly-linked list maintained by the Windows kernel. For each driver, EAC checks:

### Per-Driver Checks

| Check | What It Detects |
|---|---|
| **Digital signature** | Unsigned or self-signed drivers (cheat drivers bypass DSE) |
| **Path on disk** | Drivers loaded from temp folders, RAM disks, or unusual paths |
| **Module name hash** | Compared against a compiled-in blacklist |
| **Base address range** | Drivers loaded at suspicious addresses |
| **Image size vs. section count** | Manually-mapped "driverless" kernel code |
| **Dispatch routine pointer** | Points outside the driver's own image (hooked) |

### DKOM (Direct Kernel Object Manipulation) Detection

Some advanced cheats **unlink their driver from `PsLoadedModuleList`** so it doesn't appear in the list. EAC counters this by:

1. Scanning **all kernel memory pages** for PE headers (the `MZ` / `PE` magic bytes) independently of the module list
2. Comparing the set of discovered PE images against `PsLoadedModuleList` — any unlisted PE image is a hidden driver
3. Checking **MmSystemRange** module tracking structures for anomalies

---

## 6. Kernel Integrity Checks

This is one of EAC's most powerful capabilities. It verifies that critical kernel functions haven't been hooked or patched.

### SSDT Hook Detection

The **System Service Descriptor Table (SSDT)** maps system call numbers to kernel function addresses. Rootkits and kernel-mode cheats hook this table to intercept calls like `NtReadVirtualMemory`. EAC:

1. Reads the raw SSDT entries from `KeServiceDescriptorTable`
2. Verifies each entry points into `ntoskrnl.exe`'s legitimate code section
3. Any entry pointing outside `ntoskrnl.exe`'s known range is a hook

### Inline Hook Detection

EAC computes checksums over the first N bytes of critical kernel functions using its SIMD hash routines:

```c
// sub_FFFFF807C1E11C00 — Huffman/entropy frequency table builder
// This runs on kernel code bytes to build a frequency histogram
// If the histogram deviates from the expected pattern, code was patched

// The AVX2 variant (sub_FFFFF807C1E13100) processes 15 bytes per iteration:
// vpinsrb, vmovdqu, vpaddq — all 256-bit AVX2 SIMD
// Processes forward and backward streams simultaneously for speed
```

### Driver Dispatch Hook Detection

For every loaded driver, EAC checks that the `MajorFunction[IRP_MJ_*]` pointers in the `DRIVER_OBJECT` point **within that driver's own memory range**. A pointer that jumps to another driver's code is a hook on the dispatch routine — a technique used to intercept IOCTL calls or storage driver requests.

---

## 7. Timing & Anti-VM Detection

### KUSER_SHARED_DATA Timing

```c
// From sub_FFFFF807C1E1DD80:
v48 = MEMORY[0xFFFFF78000000014];   // KUSER_SHARED_DATA.TickCountLow
```

`0xFFFFF78000000014` is `KUSER_SHARED_DATA.TickCountLow` — a monotonically increasing tick counter updated by the Windows kernel every ~15ms. EAC:

1. **Timestamps every telemetry record** with this value
2. **Detects time manipulation** — if a cheat or VM pauses time (via `KeSetSystemTime` hook or hypervisor manipulation), the tick count will lag behind the actual wall-clock time
3. **Cross-references** the tick count with the encrypted kernel time API call (`0xE462A05B3E35A30F * v9 ^ 0x7D67C96867B51F90LL` — almost certainly `KeQuerySystemTime` or `KeQueryInterruptTime`)

### VM Detection Signals

| Signal | How EAC Reads It |
|---|---|
| CPUID hypervisor bit | Via encrypted CPUID dispatch |
| Near-zero system uptime | `KUSER_SHARED_DATA.TickCountLow` very small |
| Suspicious disk model | Via storage IOCTL to disk driver |
| Mismatched hardware IDs | Cross-source comparison |
| Missing ACPI tables | Firmware table scan |

---

## 8. Hash-Based Code Verification

`sub_FFFFF807C1E3A4C0` is EAC's **hash algorithm selector**. It initializes one of several hash contexts based on a selector value:

```c
switch (selector - 1):
  case 0:  // SHA-1 (output size = 20 bytes)
    init: 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

  case 1:  // MD5 (output size = 16 bytes)  
    init: 1732584193, -271733879, -1732584194, 271733878

  case 2:  // SHA-1 variant (output size = 20 bytes)
    init: same SHA-1 constants + zeroed extra state

  case 3:  // SHA-224 (output size = 28 bytes)
    init: 0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939...

  case 4:  // SHA-256 (output size = 32 bytes)
    init: 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A...
    
  case 5:  // SHA-384 (output size = 48 bytes)
    sub_FFFFF807C1E3BCCC(context)

  case 6:  // SHA-512 (output size = 64 bytes)
    sub_FFFFF807C1E3BB98(context)
```

These are used to hash:
- **Loaded module files on disk** — comparing against known-good hashes
- **In-memory code sections** — to detect runtime patches
- **Telemetry packet contents** — before signing with ECC

---

## 9. Indicators of Compromise

This is what EAC considers **suspicious or immediately bannable**:

| Indicator | Category | Risk Level |
|---|---|---|
| RWX memory region in game process | Memory | 🔴 Critical |
| PE header in memory with no file backing | Memory | 🔴 Critical |
| Thread created in game process from external process | Injection | 🔴 Critical |
| SSDT entry pointing outside ntoskrnl.exe | Kernel hook | 🔴 Critical |
| Unsigned kernel driver loaded | Driver | 🔴 Critical |
| Driver unlinked from PsLoadedModuleList (DKOM) | Driver | 🔴 Critical |
| Kernel driver dispatch routine pointed outside its image | Hook | 🔴 Critical |
| Process opened with PROCESS_VM_READ by suspicious process | Handle | 🟠 High |
| SeDebugPrivilege enabled in non-developer context | Privilege | 🟠 High |
| KUSER_SHARED_DATA tick count inconsistency | Timing | 🟠 High |
| Hardware IDs inconsistent across multiple sources | HWID | 🟠 High |
| Process with PPL protection that shouldn't have it | Spoofing | 🟠 High |
| Driver loaded from temp/unusual path | Driver | 🟡 Medium |
| Process name matches known cheat tool | Process | 🟡 Medium |
| Hypervisor bit set in CPUID | VM | 🟡 Medium |
| Inline hook detected in kernel function | Kernel hook | 🔴 Critical |

---

*← [Back to README](README.md) | [IOCTL & Driver Tracking →](ioctl_and_driver_tracking.md)*

---

*Written by **Google Gemini (Antigravity AI)**.*