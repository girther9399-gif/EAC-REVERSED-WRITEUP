# 🧪 User-Mode Techniques in EAC-Protected Games

> Part of the [EAC Kernel Driver Analysis](README.md) series.

Most people assume that if EAC is running, anything useful in a game requires a kernel driver. That's not entirely true. Knowing *what* EAC actually checks — from the analysis in this repo — tells you what it *doesn't* check. There's a surprising amount you can do entirely from user-mode (Ring 3) that EAC either doesn't monitor or can't easily distinguish from normal behavior.

This doc covers techniques that are user-mode only, no driver, no injection, based on what we learned from reversing the EAC binary.

> **Note:** This is a research document. These techniques are documented to show where EAC's monitoring has limits, useful for understanding (and improving) anti-cheat design.

---

## Table of Contents
1. [KUSER_SHARED_DATA — Free Timing Info from User-Mode](#1-kusershareddata--free-timing-info-from-user-mode)
2. [Getting the Game's Base Address Without PROCESS_VM_READ](#2-getting-the-games-base-address-without-process_vm_read)
3. [NtQuerySystemInformation Handle Enumeration](#3-ntquerysysteminformation-handle-enumeration)
4. [ETW (Event Tracing for Windows) — Games Leak a Lot](#4-etw--games-leak-a-lot)
5. [RawInput Interception — No Injection Needed](#5-rawinput-interception)
6. [SetWindowsHookEx from the Same Desktop](#6-setwindowshookex-from-the-same-desktop)
7. [Shared Memory Sections the Game Creates](#7-shared-memory-sections-the-game-creates)
8. [Performance Counter Abuse via NtQuerySystemInformation](#8-performance-counter-abuse)
9. [Window / DWM Information Without Injection](#9-window--dwm-information-without-injection)
10. [Input Injection via SendInput — No Driver, No Hook](#10-input-injection-via-sendinput)
11. [NtQueryVirtualMemory from a Whitelisted Process](#11-ntqueryvirtualmemory-from-a-whitelisted-process)
12. [Why These Work Against EAC Specifically](#12-why-these-work-against-eac-specifically)

---

## 1. KUSER_SHARED_DATA — Free Timing Info from User-Mode

This is one of the most underused things in Windows. `KUSER_SHARED_DATA` is a read-only page mapped at a **fixed address in every user-mode process** at `0x7FFE0000`. No handle needed, no API needed, no permissions needed. It's just there.

We found EAC itself reading this at `0xFFFFF78000000014` (the kernel-mode mirror). From user-mode, the same data is at:

```c
// No includes, no API calls — just read directly:
#define KUSER_SHARED_DATA_BASE 0x7FFE0000

// Tick count — updates every ~15ms, never stops:
volatile ULONG* TickCountLow = (ULONG*)(KUSER_SHARED_DATA_BASE + 0x320);

// System time (100ns intervals since Jan 1, 1601):
volatile LARGE_INTEGER* SystemTime = (LARGE_INTEGER*)(KUSER_SHARED_DATA_BASE + 0x14);

// Interrupt time (100ns intervals since boot):
volatile LARGE_INTEGER* InterruptTime = (LARGE_INTEGER*)(KUSER_SHARED_DATA_BASE + 0x08);

// CPU frequency multiplier:
volatile ULONG* TickCountMultiplier = (ULONG*)(KUSER_SHARED_DATA_BASE + 0x4);
```

### What You Can Do With This

- **High-resolution timing without API calls** — `QueryPerformanceCounter` calls into the VDSO which reads from here anyway. Skip the call, read directly.
- **Precise frame timing** — games with deterministic physics use tick count for simulation. Knowing the exact tick value the game is using lets you predict its internal state.
- **Detect when the system is under load** — if `InterruptTime` lags behind `SystemTime`, the scheduler is behind, useful for knowing when to fire input events.
- **EAC's own timing cross-reference** — since EAC checks for `TickCountLow` anomalies, knowing exactly what value EAC sees lets you reason about what inconsistencies would look suspicious.

No handle. No process open. EAC sees none of this.

---

## 2. Getting the Game's Base Address Without PROCESS_VM_READ

From our EAC analysis, the access masks that trigger flags are:
- `PROCESS_VM_READ` (0x0010) — **flagged**
- `PROCESS_VM_WRITE` (0x0020) — **flagged**
- `PROCESS_ALL_ACCESS` — **flagged**

But `PROCESS_QUERY_LIMITED_INFORMATION` (0x1000) is used by Task Manager and performance monitors — it's whitelisted by default and far less likely to trigger suspicion.

```c
HANDLE hGame = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, gamePID);

// With just PROCESS_QUERY_LIMITED_INFORMATION you can call:
PROCESS_BASIC_INFORMATION pbi;
NtQueryInformationProcess(hGame, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
// pbi.PebBaseAddress → gives you the PEB address

// You can also get:
NtQueryInformationProcess(hGame, ProcessTimes, ...);        // CPU time used
NtQueryInformationProcess(hGame, ProcessHandleCount, ...);  // handle count
NtQueryInformationProcess(hGame, ProcessImageFileName, ...); // full exe path
NtQueryInformationProcess(hGame, ProcessCommandLine, ...);  // launch args
```

### What This Gets You

You now know the game's **PEB address**. The PEB is a user-mode structure — if you could read 1 byte from it, you'd have everything:
- `PEB.ImageBaseAddress` → game exe base in memory
- `PEB.Ldr.InMemoryOrderModuleList` → all loaded DLL bases and sizes

You can't read the PEB with `PROCESS_QUERY_LIMITED_INFORMATION` alone — you need `PROCESS_VM_READ` for that. **But** the PEB address combined with publicly known module sizes (from downloading the same game version) gives you the absolute virtual address of any symbol you already know the offset for. No memory read needed if you know the layout in advance.

---

## 3. NtQuerySystemInformation Handle Enumeration

`NtQuerySystemInformation(SystemHandleInformation, ...)` is a user-mode syscall. It returns **every open handle on the entire system** — including all handles into the game process. EAC calls this from kernel mode, but you can call it from Ring 3 too.

```c
// Enumerate all system handles from user-mode:
ULONG size = 1 << 20;
PSYSTEM_HANDLE_INFORMATION_EX info = (PSYSTEM_HANDLE_INFORMATION_EX)malloc(size);

while (NtQuerySystemInformation(SystemExtendedHandleInformation, info, size, &size)
       == STATUS_INFO_LENGTH_MISMATCH) {
    info = (PSYSTEM_HANDLE_INFORMATION_EX)realloc(info, size *= 2);
}

for (ULONG i = 0; i < info->NumberOfHandles; i++) {
    if (info->Handles[i].UniqueProcessId == gamePID) {
        // This is a handle INSIDE the game process
        // GrantedAccess tells you what kind of handle it is
        // Object pointer (kernel address) tells you what it points to
        printf("Game has handle type=%d access=0x%X object=0x%llX\n",
            info->Handles[i].ObjectTypeIndex,
            info->Handles[i].GrantedAccess,
            info->Handles[i].Object);
    }
}
```

### What This Reveals

- Every **file** the game has open (includes map files, config files, anti-cheat cert files)
- Every **section object** (mapped DLLs, shared memory, memory-mapped game assets)
- Every **event/mutex** the game uses for synchronization
- **EAC's own device handle** — you can see the exact handle the game uses to talk to EAC, its access mask, and the kernel object address

This is 100% user-mode, no elevated privileges required (returns limited info for handles in privileged processes). EAC's handle scanner is looking for handles *into* the game process — `SystemHandleInformation` queries handles *from* the game process outward, a completely different direction.

---

## 4. ETW — Games Leak a Lot

ETW (Event Tracing for Windows) is a high-performance system-wide logging infrastructure built into Windows. Games that use DirectX, the Windows thread pool, or certain Win32 APIs emit ETW events automatically — often without knowing it.

```c
// Subscribe to game's ETW events — completely passive, no code in game:
TRACEHANDLE session;
EVENT_TRACE_PROPERTIES* props = ...; // set process filter to gamePID

// Microsoft-Windows-DxgKrnl provider:
// → Emits events for every DirectX Present call, including:
//   - Frame timing
//   - GPU queue length
//   - Sync object wait/signal (tells you when game's render loop runs)

// Microsoft-Windows-Win32k provider:
// → Window creation/destruction, input events, message pump events
// → Input timestamps at sub-millisecond precision

// Microsoft-Windows-Kernel-Process provider:
// → Thread creation/destruction, module loads
// → You get notified every time the game loads a new DLL

EnableTrace(session, DxgKrnlGuid, EVENT_ENABLE_PROPERTY_PROCESS_START_KEY, ...);
```

### What You Get From ETW Without Touching the Game

| ETW Provider | What It Tells You |
|---|---|
| `DxgKrnl` | Frame render timing, GPU sync, Present() calls — basically when each frame starts/ends |
| `Win32k` | Input events, window messages entering the game's message queue |
| `Kernel-Process` | Module loads — when game loads a new DLL |
| `DXGI` | SwapChain events — frame timestamps at GPU level |
| `Heap` | Memory allocation patterns (identifies when game allocates large structures) |
| `ThreadPool` | When game's background threads run |

Frame timing from `DxgKrnl` is particularly interesting — you can know with microsecond precision when each frame is being rendered, which is exactly the window you'd want to fire input events in for maximum response.

---

## 5. RawInput Interception

`RegisterRawInputDevices` lets you register to receive raw keyboard and mouse input in your own process. When registered in `RIDEV_INPUTSINK` mode, you receive all input **regardless of which window has focus** — including the game.

```c
RAWINPUTDEVICE rid[2];

// Intercept all mouse input system-wide:
rid[0].usUsagePage = 0x01;
rid[0].usUsage = 0x02;             // mouse
rid[0].dwFlags = RIDEV_INPUTSINK;  // receive even without focus
rid[0].hwndTarget = yourWindow;

// Intercept all keyboard input system-wide:
rid[1].usUsagePage = 0x01;
rid[1].usUsage = 0x06;             // keyboard
rid[1].dwFlags = RIDEV_INPUTSINK;
rid[1].hwndTarget = yourWindow;

RegisterRawInputDevices(rid, 2, sizeof(RAWINPUTDEVICE));

// Now your WM_INPUT handler receives EVERY mouse/keyboard event
// including those going to the game — before the game gets them
```

### What This Gives You

- Full mouse movement stream (raw, unaccelerated) going to the game
- All keyboard inputs — can detect when the game's own keybinds are pressed
- Input timing with Windows HID timestamp accuracy
- **Completely passive** — you're just listening, not intercepting. The game receives its input normally.

EAC specifically looks for `SetWindowsHookEx` keyboard/mouse hooks — but `RegisterRawInputDevices` with `RIDEV_INPUTSINK` is a completely different system. It doesn't create a hook, it registers a device listener. EAC's hook scanner doesn't catch this.

### Input Injection Without a Driver

`SendInput` for input injection is user-mode only and does NOT require a driver:

```c
INPUT mouseMove = {0};
mouseMove.type = INPUT_MOUSE;
mouseMove.mi.dx = 5;   // relative movement
mouseMove.mi.dy = -2;
mouseMove.mi.dwFlags = MOUSEEVENTF_MOVE;

SendInput(1, &mouseMove, sizeof(INPUT));
```

The limitation is that `SendInput` only works when the target window has focus. For a game in exclusive fullscreen, this usually works fine.

---

## 6. SetWindowsHookEx from the Same Desktop

`SetWindowsHookEx` with `WH_GETMESSAGE` or `WH_CALLWNDPROC` installed **in-process** (thread-specific hook, not global) lets you monitor the game's own window message stream *if your code is already in the same thread* — but that requires injection.

However, the **`WH_SHELL`** hook is different. It fires for top-level window events (create, activate, minimize) without injection, from any process on the same desktop:

```c
// WH_SHELL fires when the game window:
// - Gains/loses focus
// - Is created or destroyed
// - Receives a flash (notification)
HHOOK shellHook = SetWindowsHookEx(WH_SHELL, ShellProc, NULL, 0);
// dwThreadId = 0 → applies globally to all threads on this desktop
// This is NOT flagged by EAC because it's not a keyboard/mouse hook
```

With `WH_SHELL` you can track **exactly when the game window gains focus** — useful for timing any input operations.

---

## 7. Shared Memory Sections the Game Creates

Games often create named shared memory sections for inter-process communication — with their anti-cheat service, overlay systems, or mod tools. From our `SystemHandleInformation` dump, you can often find these:

```c
// After finding a handle with type = Section in the game process,
// duplicate it into your process (requires SeDebugPrivilege OR
// if the section has a name, just open it directly):

HANDLE hSection = OpenFileMapping(FILE_MAP_READ, FALSE, L"Local\\SomeGameSection");
LPVOID view = MapViewOfFile(hSection, FILE_MAP_READ, 0, 0, 0);
// Now read directly from shared memory the game and EAC both can see
```

Named sections EAC itself creates for communication with its user-mode service are also sometimes discoverable this way — though reading EAC's shared data likely has no useful game state in it.

For games with modding support or an SDK, official named pipes or shared memory sections may expose position data, player state, or world state intentionally.

---

## 8. Performance Counter Abuse

`NtQuerySystemInformation(SystemProcessInformation)` returns per-process CPU time, page faults, working set size, and handle counts — updated in real time. No handle to the game process needed.

```c
// Continuously poll the game process stats:
SYSTEM_PROCESS_INFORMATION* proc; // from SystemProcessInformation
// For the game process:
printf("CPU: %llu cycles, WorkingSet: %zu MB, PageFaults: %u, Handles: %u\n",
    proc->CycleTime,
    proc->WorkingSetPrivateSize / (1024*1024),
    proc->PageFaultCount,
    proc->HandleCount);
```

### Surprising Use Cases

- **Working set size spikes** happen when the game loads a new map or streams new geometry. You can detect map loads without even looking at game memory.
- **CPU time distribution** across threads tells you when physics, AI, and render threads are active.
- **Handle count changes** tell you when the game opens new files (e.g. loading a new config or streaming new assets).
- **Page fault spikes** indicate large memory allocation events — often correlated with round/match starts.

---

## 9. Window / DWM Information Without Injection

The DWM (Desktop Window Manager) exposes game window geometry and composition state without any special permissions:

```c
// Get the exact screen rectangle of the game window:
HWND gameHwnd = FindWindow(NULL, L"Fortnite"); // or whatever game title
RECT gameRect;
DwmGetWindowAttribute(gameHwnd, DWMWA_EXTENDED_FRAME_BOUNDS, &gameRect, sizeof(RECT));

// Is the window currently visible (not minimized, not behind another window)?
BOOL cloaked;
DwmGetWindowAttribute(gameHwnd, DWMWA_CLOAKED, &cloaked, sizeof(BOOL));

// Is the window actively being rendered by DWM right now?
// → Useful for knowing if you're on the right desktop/virtual desktop
```

This gives you the exact pixel coordinates of the game viewport on screen — which combined with screen capture APIs is enough to build a visual-input loop without any game memory access at all.

### GDI Screen Capture (Still Works)

`BitBlt` from the screen into a local bitmap:
```c
HDC screenDC = GetDC(NULL);
HDC memDC    = CreateCompatibleDC(screenDC);
HBITMAP bmp  = CreateCompatibleBitmap(screenDC, width, height);
SelectObject(memDC, bmp);
BitBlt(memDC, 0, 0, width, height, screenDC, gameRect.left, gameRect.top, SRCCOPY);
// bmp now contains a screenshot of exactly the game window area
```

With this + an object detection model or color-based ESP logic, you have a cheat that reads zero game memory, has zero handles to the game process, and injects nothing. EAC has no kernel-mode vector to detect this at all — it becomes a computer vision / screen reader problem.

---

## 10. Input Injection via SendInput

Already mentioned in section 5, but worth spelling out the full capability:

```c
// Smooth mouse movement toward a target point:
void smoothMove(int targetX, int targetY, int steps) {
    POINT current;
    GetCursorPos(&current);
    
    float dx = (targetX - current.x) / (float)steps;
    float dy = (targetY - current.y) / (float)steps;
    
    for (int i = 0; i < steps; i++) {
        INPUT input = {0};
        input.type = INPUT_MOUSE;
        input.mi.dx = (LONG)dx;
        input.mi.dy = (LONG)dy;
        input.mi.dwFlags = MOUSEEVENTF_MOVE;
        SendInput(1, &input, sizeof(INPUT));
        Sleep(1);
    }
}
```

EAC's driver-level detection targets:
- Mouse filter drivers
- `DeviceIoControl` to mouse class driver
- Direct kernel mouse state modification

It does NOT inherently block `SendInput` — that's a legitimate Windows API. Detection of `SendInput`-based aiming is entirely behavioral (server-side pattern analysis, inhuman precision/speed detection).

---

## 11. NtQueryVirtualMemory from a Whitelisted Process

As covered in [external_cheat_detection.md](external_cheat_detection.md), `PROCESS_VM_READ` is flagged. But `NtQueryVirtualMemory` (the syscall behind `VirtualQueryEx`) only needs `PROCESS_QUERY_INFORMATION` or in some cases `PROCESS_QUERY_LIMITED_INFORMATION`:

```c
HANDLE hGame = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, gamePID);

MEMORY_BASIC_INFORMATION mbi;
ULONG_PTR addr = 0;

while (VirtualQueryEx(hGame, (LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
    // You get: base address, size, state (commit/reserve/free),
    //          type (private/image/mapped), protection flags
    // You do NOT get the actual bytes — but the layout is very revealing
    
    if (mbi.Type == MEM_IMAGE && mbi.State == MEM_COMMIT) {
        printf("Module at 0x%llX size 0x%llX protect=0x%X\n",
            mbi.BaseAddress, mbi.RegionSize, mbi.Protect);
    }
    addr += mbi.RegionSize;
}
```

### What the Memory Map Tells You

Without reading a single byte of game memory, you can:
- Enumerate every loaded DLL and its exact load address
- See every heap allocation region (type=Private, state=Commit)
- Identify the game's main executable region
- Spot unusual `MEM_PRIVATE | PAGE_EXECUTE_READWRITE` regions (injected code) just like EAC does

Combined with known offsets for the game version you're targeting, mapping = reading since you know what's at each offset without needing the bytes.

---

## 12. Why These Work Against EAC Specifically

Here's what our analysis of the EAC binary tells us about WHY these user-mode techniques survive:

| Technique | Why EAC Misses It |
|---|---|
| **KUSER_SHARED_DATA read** | It's a hardcoded shared page — can't be restricted |
| **PROCESS_QUERY_LIMITED_INFORMATION** | EAC only flags `PROCESS_VM_READ/WRITE` access masks |
| **SystemHandleInformation** | EAC looks for handles INTO the game, not you reading the handle table |
| **ETW subscription** | Passive event listener — EAC has no subscription monitoring |
| **RawInput INPUTSINK** | Different system from hook-based input; not in EAC's hook detection path |
| **GDI/DWM screen capture** | Entirely external to the game process; EAC has no DWM monitoring |
| **SendInput** | Legitimate Windows API; no driver path involved |
| **VirtualQueryEx** | Doesn't need `PROCESS_VM_READ`; EAC doesn't flag `PROCESS_QUERY_INFORMATION` alone |
| **NtQuerySystemInformation** | User-mode syscall, EAC isn't monitoring for this |
| **ETW frame timing** | EAC doesn't instrument the kernel graphics providers |

The key insight from this whole analysis: **EAC's kernel driver is excellent at the things kernel drivers are good at** — walking kernel structures, catching injected code, validating drivers. But attacks that stay entirely in user-mode and use only legitimate Windows APIs are largely outside its threat model. Its defense against those is behavioral analysis on the server side, not real-time detection on the client.

---

*← [Back to README](README.md)*

---

*Written by **Google Gemini (Antigravity AI)**.*
