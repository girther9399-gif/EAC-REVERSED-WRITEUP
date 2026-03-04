# 💉 Internal Cheats & DLL Injectors — Deep Dive

> Part of the [EAC Kernel Driver Analysis](README.md) series.

Internal cheats are the hardest thing for any anti-cheat to catch reliably. The cheat DLL is running inside the game's own process — same address space, same privileges, access to everything. Getting it in there undetected is the injector's job. This covers every injection method we know of and exactly what EAC does to detect each one.

---

## Table of Contents
1. [What Makes Internal Cheats Different](#1-what-makes-internal-cheats-different)
2. [LoadLibrary Injection Detection](#2-loadlibrary-injection-detection)
3. [Manual Mapping Detection](#3-manual-mapping-detection)
4. [APC (Asynchronous Procedure Call) Injection Detection](#4-apc-injection-detection)
5. [Thread Hijacking Detection](#5-thread-hijacking-detection)
6. [Process Hollowing / Doppelgänging Detection](#6-process-hollowing--doppelgänging-detection)
7. [Kernel-Mode DLL Injection Detection](#7-kernel-mode-dll-injection-detection)
8. [VAD Tree — The Core Internal Detection Mechanism](#8-vad-tree--the-core-internal-detection-mechanism)
9. [PEB Module List Integrity](#9-peb-module-list-integrity)
10. [Code Cave and Shellcode Detection](#10-code-cave-and-shellcode-detection)
11. [Vulnerabilities EAC Misses in Injector Detection](#11-vulnerabilities-eac-misses)

---

## 1. What Makes Internal Cheats Different

Internal cheats run **inside the game's address space** — they're loaded as DLLs or shellcode inside `Fortnite.exe`/`PUBG.exe`/etc. This gives them:
- Direct access to all game memory without `ReadProcessMemory`
- Ability to hook game functions at the assembly level (inline hooks, vtable hooks)
- Access to the game's DirectX/Vulkan context for rendering

But it also means they leave evidence **inside the game process** that EAC can find.

---

## 2. LoadLibrary Injection Detection

### The Technique

```c
// Injector process:
LPVOID addr = VirtualAllocEx(hGame, NULL, strlen(dllPath)+1, MEM_COMMIT, PAGE_READWRITE);
WriteProcessMemory(hGame, addr, dllPath, strlen(dllPath)+1, NULL);
CreateRemoteThread(hGame, NULL, 0, LoadLibraryA, addr, 0, NULL);
```

This is the oldest and most well-known injection technique. EAC detects it through multiple vectors:

### Vector 1: Thread Creation Callback

EAC registers `PsSetCreateThreadNotifyRoutine`. When a new thread starts in the game process:

```c
// EAC's thread creation callback:
VOID ThreadNotifyCallback(HANDLE pid, HANDLE tid, BOOLEAN create) {
    if (!create) return;
    if (pid != gamePID) return;  // only care about game threads
    
    // Get the new thread's start address
    PVOID startAddr = PsGetThreadStartAddress(..);
    
    // Is the start address inside a known, loaded module?
    if (!IsInKnownModule(startAddr)) {
        // Thread starts in an unknown region → injector detected
        flag_suspicious_thread(tid, startAddr);
    }
    
    // Does start address == LoadLibraryA / LoadLibraryW?
    // Classic remote thread injection signature
    if (startAddr == cached_LoadLibraryA || startAddr == cached_LoadLibraryW) {
        flag_loadlibrary_injection(pid, tid);
    }
}
```

### Vector 2: Handle Inspection

The injector process must open the game with `PROCESS_CREATE_THREAD | PROCESS_VM_WRITE`. Both of these are caught by EAC's handle table scanner (see [External Cheat Detection](external_cheat_detection.md#2-handle-based-detection)).

### Vector 3: Post-Load Module List Scan

After a thread is created, EAC checks the game's `PEB.Ldr.InLoadOrderModuleList` via `EPROCESS` access. Any new module that appeared since the last scan is checked for:
- Is it on disk? (Fileless injections have no backing file)
- Is it signed?
- Is its DiskHash == InMemoryHash?

---

## 3. Manual Mapping Detection

Manual mapping is the most sophisticated injection technique. Instead of calling `LoadLibrary`, the injector manually replicates what the Windows loader does:

```
Injector:
1. Allocate RWX memory in game process (size = DLL virtual size)
2. Copy PE headers + sections into allocated memory
3. Apply relocations manually (patch all absolute addresses)
4. Resolve imports manually (look up all DLL exports, patch IAT)
5. Call DllMain directly via CreateRemoteThread
6. Optionally: erase PE headers from mapped memory (anti-scan)
```

The result is a DLL that runs **inside the game process but has no entry in the PEB module list and no backing file on disk**.

### How EAC Detects Manual Maps

#### Detection 1: VAD Tree Scan (Primary)

This is the most powerful and reliable detection. The VAD (Virtual Address Descriptor) tree tracks every allocated memory region. EAC walks the game process's full VAD tree via `EPROCESS+240`:

```c
// Walk the game process VAD tree:
PMMVAD node = *(PMMVAD*)(gameEPROCESS + 240);  // VadRoot
PMMVAD stack[256];  // DFS traversal stack
int depth = 0;

while (node || depth > 0) {
    // Examine each VAD node:
    ULONG_PTR startVA = node->StartingVpn << PAGE_SHIFT;
    ULONG_PTR endVA   = node->EndingVpn   << PAGE_SHIFT;
    ULONG     protect = node->u.VadFlags.Protection;  // page protection
    ULONG     type    = node->u.VadFlags.VadType;     // 0=private, 1=mapped, 2=section
    
    // SUSPICIOUS: Private, executable, not backed by a file section object
    if (type == 0 &&                          // VadNone (private)
        (protect & PAGE_EXECUTE_READWRITE ||
         protect & PAGE_EXECUTE_READ) &&
        !node->SubSection) {                  // no file backing
        // Executable private memory → shellcode / manual map
        scan_region(startVA, endVA);
    }
    
    // SUSPICIOUS: Executable section but no entry in module list
    if (type == 1 /*mapped*/ && is_pe_image(startVA) && !in_module_list(startVA)) {
        flag_hidden_module(startVA, endVA);
    }
}
```

#### Detection 2: PE Header Scan in Private Memory

Even if an injector erases the MZ/PE header after mapping, EAC still recognizes the mapped DLL because:
- Section boundaries are at predictable, page-aligned offsets
- Import tables leave fingerprints (arrays of resolved function pointers)
- `.text` sections have characteristic entropy patterns
- Export directory bytes may still be partially present

EAC uses SIMD-based entropy estimation and pattern matching to identify PE images even without headers.

#### Detection 3: RWX Memory Region Flagging

`PAGE_EXECUTE_READWRITE` (`0x40`) is a massive red flag. Legitimate code is never `RWX` — it's either `RX` (executable code) or `RW` (writable data), never both. Any `RWX` region in the game process is:
- Immediately flagged  
- Scanned for PE signatures
- Reported in telemetry even if no PE is found (the RWX alone is reportable)

---

## 4. APC Injection Detection

APC (Asynchronous Procedure Call) injection queues an APC to a thread in the target process. The APC function runs when the thread enters an alertable wait state (e.g., calling `SleepEx`).

```c
// Injector:
QueueUserAPC((PAPCFUNC)LoadLibraryA, hThread, (ULONG_PTR)remoteDllPath);
// Or kernel-mode:
KeInsertQueueApc(apc, kernelRoutine, rundownRoutine, normalRoutine, normalCtx, mode);
```

### EAC Detection

```c
// EAC can inspect each thread's APC queue via ETHREAD:
// ETHREAD.ApcState.UserApcPending
// ETHREAD.ApcState.ApcListHead[UserMode] 

// A queued APC pointing to LoadLibraryA or a non-module address = injection
// EAC also looks at OriginalApcContext which reveals the DLL path if still present
```

The weakness: by the time EAC checks, the APC may have already executed and the queue is empty. This makes APC injection harder to catch after-the-fact — it's mostly caught by the subsequent module list change.

---

## 5. Thread Hijacking Detection

Thread hijacking modifies an existing thread's execution context (registers, instruction pointer) to redirect it to the injected code.

```c
// Injector:
SuspendThread(hThread);
GetThreadContext(hThread, &ctx);
ctx.Rip = (DWORD64)shellcodeAddr;  // redirect instruction pointer
SetThreadContext(hThread, &ctx);
ResumeThread(hThread);
```

### EAC Detection

The thread creation callback (`PsSetCreateThreadNotifyRoutine`) does NOT fire for thread hijacking — no new thread is created. Instead EAC relies on:

1. **Periodic thread scan**: Walk all threads in game EPROCESS (`EPROCESS.ActiveThreads`), check each thread's current `Rip` at time of scan — if Rip is outside all known modules, the thread was hijacked (or is currently executing injected code).

2. **Exception/trap callbacks**: `KiSetSystemAffinityThread` and trap frame examination during context switches can expose when threads are executing at unexpected addresses.

3. **Post-hijack artifact**: After hijack, the new code eventually calls `LoadLibrary` or allocates memory, which EAC's other scanners catch.

---

## 6. Process Hollowing / Doppelgänging Detection

**Process Hollowing**: Launch a legitimate process in suspended state, unmap its code, replace it with cheat code, resume it.

**Process Doppelgänging**: Same concept but uses NTFS transactions to create a phantom file that Windows loader maps and then rolls back, leaving no trace on disk.

### EAC Detection

```c
// Process hollowing leaves a VAD entry mapped from a section that doesn't
// match the process's image file path. EAC detects this by:

// 1. Read EPROCESS.SectionObject → get the mapped section
// 2. Read the section's FileObject path
// 3. Compare against EPROCESS.SeAuditProcessCreationInfo.ImageFileName
// If they differ → process hollowing

// For doppelgänging:
// The NTFS transaction is rolled back, so the backing file technically doesn't exist.
// EAC detects this as: file-backed VAD section whose file object has no valid 
// MftFileRecord → phantom file section
```

---

## 7. Kernel-Mode DLL Injection Detection

Some advanced injectors bypass ALL user-mode injection detection by using a **kernel driver** to directly inject a DLL:

```c
// Kernel injector technique:
// 1. Suspend all game threads (via kernel thread manipulation)
// 2. Allocate memory in game process via MmAllocateVirtualMemory on target EPROCESS
// 3. Copy DLL bytes directly
// 4. Manually fix relocations in kernel
// 5. Queue user-mode APC to game's main thread to call the DLL entry point
// 6. Resume all threads
```

### EAC Detection

This is where EAC's **DKOM and kernel driver enumeration** become critical. If a kernel injector driver is running:

1. EAC's module scan (`PsLoadedModuleList` + physical memory PE scan) finds the injector driver
2. The injector driver's dispatch table may be hooked or unusual
3. The injector often calls `ObReferenceObjectByName` on the target process — EAC can monitor object manager callbacks

The injected DLL still shows up in the VAD tree and PEB scan, giving EAC two independent detection paths.

---

## 8. VAD Tree — The Core Internal Detection Mechanism

The **Virtual Address Descriptor** tree is the single most important data structure for detecting internal cheats. EAC accesses it directly at `EPROCESS+240` (`VadRoot`).

### What EAC Checks in Each VAD Node

```
For every VAD node in the game process:
├── VadFlags.Protection:
│   ├── PAGE_EXECUTE_READWRITE (0x40) → 🔴 RWX = immediate flag
│   ├── PAGE_EXECUTE_WRITECOPY (0x80) → 🔴 suspicious  
│   ├── PAGE_EXECUTE_READ (0x20) → check further
│   └── PAGE_NOACCESS (0x01) → whitelisted
│
├── VadFlags.VadType:
│   ├── VadNone (0) = private allocation
│   │   └── If executable AND no backing section → shellcode / manual map
│   ├── VadImageMap (2) = mapped image (legitimate DLL)
│   │   └── If not in PEB module list → hidden injection
│   └── VadAwe (3) = AWE memory (unusual for games)
│
├── SubSection pointer:
│   ├── NULL → no file backing (private alloc or manually mapped)
│   └── Non-NULL → check ControlArea.FileObject.FileName
│       └── File path not in whitelist → suspicious module
│
└── Size check:
    └── Very large private executable regions (> 10MB) → flag
```

### Why This Is Hard to Beat

To completely evade VAD scanning, an attacker would need to:
1. Remove/modify the VAD node for their injected region
2. This requires kernel privileges  
3. But having kernel privileges means EAC's driver scanner should find the attacker's driver
4. Creating a circular dependency that's very difficult to win

Some researchers have demonstrated VAD node manipulation but it requires extremely precise kernel object manipulation that tends to bluecreen.

---

## 9. PEB Module List Integrity

The Windows PEB (Process Environment Block) maintains three doubly-linked lists of loaded modules:
- `Ldr.InLoadOrderModuleList` — ordered by load time
- `Ldr.InMemoryOrderModuleList` — ordered by memory address
- `Ldr.InInitializationOrderModuleList` — ordered by init order

Cheats sometimes unlink themselves from these lists to hide. EAC cross-validates:

```c
// EAC reads the PEB via EPROCESS.Peb (user-mode accessible structure):
PPEB peb = *(PPEB*)(gameEPROCESS + PEB_OFFSET);

// Walk InLoadOrderModuleList:
PEB_LDR_DATA* ldr = peb->Ldr;
LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
LIST_ENTRY* cur  = head->Flink;

while (cur != head) {
    LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
    
    // Does this module's base address match the VAD tree?
    if (!FindVadNode(entry->DllBase)) {
        // Module in PEB list but no VAD node → corrupted PEB entry
        flag_peb_tampering();
    }
    
    cur = cur->Flink;
}

// ALSO: walk VAD tree looking for IMAGE type nodes not in PEB list
ForEachImageVad { 
    if (!FindPebEntry(vadBase)) {
        // Image in VAD tree but not in PEB list → hidden injection
        flag_hidden_module();
    }
}
```

---

## 10. Code Cave and Shellcode Detection

**Code caves** are unused byte sequences inside legitimate modules (gaps between functions, padding sections) that injectors fill with shellcode. This avoids allocating new memory — the code runs inside an already-whitelisted region.

### EAC Detection

```c
// For each loaded module, EAC computes region hashes:
// 1. Load the on-disk version of each DLL from \Windows\System32
// 2. Hash specific memory ranges (not entire DLL — too slow)
//    Specifically: .text section, IAT, export table, entry point ±512 bytes
// 3. Compare in-memory hash vs on-disk hash
// If mismatch → code was modified (code cave, inline hook, or patch)

// The hash algorithm is selected by sub_FFFFF807C1E3A4C0 (SHA-256 for critical modules)
// The hash is computed via SIMD (sub_FFFFF807C1E3A568) for performance
```

### What Code Caves Look Like

```
Legitimate function padding:
  48 8B C4          mov rax, rsp
  ...function body...
  C3                ret
  CC CC CC CC CC CC  ← padding NOPs/INT3s
  
Code cave injection:
  48 8B C4          mov rax, rsp
  ...function body...
  C3                ret
  48 B8 XX XX XX XX  ← MOV RAX, cheatCodeAddress (injector placed this)
  XX XX XX XX     
  FF E0               JMP RAX → jumps to cheat code
```

The `INT3` (`0xCC`) bytes being replaced and/or entropy changing in otherwise-uniform padding regions is a detectable signal.

---

## 11. Vulnerabilities EAC Misses

### 🔓 Gap 1: VAD Manipulation (DKOM for Memory Regions)

An attacker with kernel privileges can directly modify the VAD tree — unlinking a VAD node or changing its type from `VadNone` to `VadImageMap` with a spoofed section reference. This would make RWX shellcode look like a legitimate mapped image. **Very difficult and risks BSOD**, but not impossible.

### 🔓 Gap 2: PatchGuard Timing Window

PatchGuard (KPP) periodically validates kernel structures. Between PatchGuard checks, a sophisticated attack could briefly modify VAD nodes, extract game data, and restore them before PatchGuard or EAC notice. Estimated window: several seconds. This is the basis of some "hypervisor cheats."

### 🔓 Gap 3: Thread Pool Hijacking

Instead of creating a new thread or queuing an obvious APC, some injectors hijack **existing thread pool threads** (which EAC whitelists because they're normal `ntdll!TpCallbackMayRunLong` threads). The **start address** of pool threads is inside ntdll — only the actual work item callback is suspicious, and that's harder to scan.

### 🔓 Gap 4: Section-Backed Shellcode (No RWX Needed)

An attacker can create a memory-mapped section with `PAGE_EXECUTE_READ` backed by a crafted file, map it into the game, and execute it. The VAD shows a legitimate-looking file-backed executable section. EAC would need to check the actual file contents on disk to catch this. Files at unusual paths (temp directories) would still be flagged, but files placed in legitimate-looking paths could slip through.

### 🔓 Gap 5: Legitimate Signed DLL Abuse

Some cheats load entirely legitimate, signed DLLs (like a math library or compression library) and then exploit a vulnerability WITHIN that DLL to execute arbitrary code via ROP chains. The injected DLL itself passes all signature checks — the exploit code is data, not flagged as executable injection.

### 🔓 Gap 6: Early-Launch Injection (Before PE Headers Are Verified)

EAC initializes at game start, but there's a brief window between when the game's own loader maps DLLs and when EAC begins scanning. If an injector can get code into the game during this window (before EAC's first scan), it gets a free pass until EAC's hash checks run. The injected DLL simply needs to pass hash verification — which means it must be a legitimate, signed DLL that then loads a cheat payload from within.

---

*← [External Cheat Detection](external_cheat_detection.md) | [User-Mode EAC App Analysis →](usermode_eac_app.md)*

---

*Written by **Google Gemini (Antigravity AI)**.*