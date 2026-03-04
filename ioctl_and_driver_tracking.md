# 🔌 IOCTL Dispatch & Driver Tracking — Deep Dive

> Part of the [EAC Kernel Driver Analysis](README.md) series.

---

## Table of Contents
1. [The EAC Device Object & IOCTL Architecture](#1-the-eac-device-object--ioctl-architecture)
2. [How IOCTL Commands Flow Ring3 → Ring0](#2-how-ioctl-commands-flow-ring3--ring0)
3. [Encrypted Function Dispatch — How EAC Hides Its Calls](#3-encrypted-function-dispatch)
4. [Kernel Driver Enumeration & Blacklisting](#4-kernel-driver-enumeration--blacklisting)
5. [Dispatch Table Hook Detection](#5-dispatch-table-hook-detection)
6. [Filter Driver & Stack Detection](#6-filter-driver--stack-detection)
7. [Storage Driver IOCTL Interception for HWID](#7-storage-driver-ioctl-for-hwid)

---

## 1. The EAC Device Object & IOCTL Architecture

When the EAC kernel driver loads, `DriverEntry` calls `IoCreateDevice` to create a **named device object**. This device is the communication channel between the Ring-3 EAC service and the Ring-0 kernel driver.

```
User Mode                        Kernel Mode
──────────────────               ──────────────────────────────────
EasyAntiCheat.exe
  │
  │  CreateFile(L"\\\\.\\EasyAntiCheat")
  ▼
  [HANDLE to device]
  │
  │  DeviceIoControl(handle, IOCTL_CODE, inBuf, inSize, outBuf, outSize)
  ▼
  [Windows I/O Manager]
  │
  │  Builds IRP (I/O Request Packet)
  │  Routes to EAC driver's MajorFunction[IRP_MJ_DEVICE_CONTROL]
  ▼
  [EAC Kernel Driver dispatch handler]
    → Reads IoStackLocation->Parameters.DeviceIoControl.IoControlCode
    → Dispatches to appropriate sub-handler
    → Fills output buffer
    → Completes IRP
```

The device name is obfuscated in the binary (stored as an encoded byte sequence, not a plain UTF-16 string), so it cannot be trivially found via string searches.

---

## 2. How IOCTL Commands Flow Ring3 → Ring0

EAC uses **METHOD_BUFFERED** IOCTL transfers, which means:
- Input data is copied from user-mode buffer to a kernel pool allocation
- Output data is written to a kernel pool allocation and then copied back to user-mode
- This prevents user-mode from directly passing pointers into kernel space

### IOCTL Control Code Structure

Windows IOCTL codes are 32-bit values encoded as:
```
Bits 31-16: DeviceType
Bits 15-14: Access (00=any, 01=read, 10=write, 11=read+write)
Bits 13-2:  Function code (0x000–0x7FF = Microsoft, 0x800–0xFFF = vendor)
Bits 1-0:   Transfer method (00=buffered, 01=in direct, 10=out direct, 11=neither)
```

Based on the IDA analysis, EAC uses custom function codes in the **vendor range (0x800+)**. The IOCTL dispatch handler performs a large `switch()` on the function code extracted from the IRP stack location.

### Known IOCTL Categories (Reconstructed)

| Category | Direction | Purpose |
|---|---|---|
| `INIT / HANDSHAKE` | Ring3 → Ring0 | Initial authentication, session key exchange |
| `SCAN_REQUEST` | Ring3 → Ring0 | User mode asks driver to perform a specific scan |
| `SCAN_RESULT` | Ring0 → Ring3 | Driver returns binary scan result data |
| `MODULE_LIST` | Ring0 → Ring3 | Driver returns list of loaded kernel modules |
| `TELEMETRY_COLLECT` | Ring3 → Ring0 | Trigger telemetry packet assembly |
| `TELEMETRY_FETCH` | Ring0 → Ring3 | Return compressed+encrypted telemetry blob |
| `HEARTBEAT` | Ring3 → Ring0 | Periodic keep-alive / anti-debug check |
| `GAME_PID_SET` | Ring3 → Ring0 | Tell driver which PID is the protected game |

---

## 3. Encrypted Function Dispatch

This is one of EAC's most clever defenses. **Every single Windows kernel API call** goes through a runtime decryption layer rather than a static import table. This is why EAC has **no import table** — it resolves everything itself.

### The Dispatch Mechanism

```c
// sub_FFFFF807C1ED4320 — the encrypted pointer resolver
// Takes a pointer to an encrypted function pointer slot
// Returns the decrypted raw function address

// Example usage in sub_FFFFF807C1E1DD80:
v3 = sub_FFFFF807C1ED4320(&unk_FFFFF807C2068E78);
result = ((__int64 (*)(void))((0x936ACF702E4281A9uLL * v3) ^ 0xFA85638DCFA646E7uLL))();
//        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//        Multiply encrypted value by constant A, XOR with constant B, call result as fn ptr
```

### How It Works Step by Step

1. **Storage**: Function pointers are stored in a data table (`0xFFFFF807C2068E78` and nearby slots) in an **encrypted form**. The raw bytes are not a valid address.

2. **Resolution**: `sub_FFFFF807C1ED4320` reads the encrypted slot and does some preliminary transformation (likely XOR with a session key or base address).

3. **Decryption**: The result is then transformed by `(CONSTANT_A * value) XOR CONSTANT_B` where each API has its own unique pair of 64-bit constants:

| Constant A | Constant B | Likely Resolved Function |
|---|---|---|
| `0x936ACF702E4281A9` | `0xFA85638DCFA646E7` | `PsGetCurrentProcess` or equivalent |
| `0xF3EC14C2131FEE4F` | `0xBE0DAFCD89B39CD1` | `PsGetProcessSessionId` |
| `0xE462A05B3E35A30F` | `0x7D67C96867B51F90` | `KeQuerySystemTime` / `KeQueryInterruptTime` |
| `0xE615DAFE9811D559` | `0x00A559FABE750D69` | Generic serializer / packet writer |

4. **Calling**: The decrypted value is immediately cast to a function pointer and called — the plaintext address never sits in a variable long enough to be easily dumped.

### Why This Is Hard to Bypass

- You cannot find "what functions EAC calls" by reading the import table — there is none
- You cannot hook EAC's internal calls via typical IAT hooking
- Each API call has a unique constant pair — you can't easily decode all of them without solving each one
- The constants are likely **regenerated per EAC build**, meaning they change with updates

---

## 4. Kernel Driver Enumeration & Blacklisting

EAC doesn't just check the currently running drivers — it maintains what appears to be a **compiled-in blacklist** stored in the binary's data section. The globals `aBin` (`0xFFFFF807C1FFEE10`) and `aBin_0` (`0xFFFFF807C1FFEDF0`) contain encoded binary data that functions as a signature database.

### Enumeration Process

```
1. Walk PsLoadedModuleList (doubly-linked list of LDR_DATA_TABLE_ENTRY)
   For each entry:
   ├── Read: BaseDllName (module name)
   ├── Read: FullDllName (full path)
   ├── Read: DllBase (load address)
   ├── Read: SizeOfImage (total mapped size)
   ├── Read: EntryPoint (DriverEntry address)
   └── Hash name → compare against internal blacklist

2. For each driver:
   ├── Verify Authenticode digital signature
   ├── Check SizeOfImage matches PE header value
   ├── Verify section headers are intact
   └── Check MajorFunction[] pointers are in-range
```

### DKOM Counter-Measure

Advanced cheat drivers unlink themselves from `PsLoadedModuleList` to become invisible. EAC counters this with a secondary scan:

```
Secondary scan (DKOM-resistant):
1. Iterate through MmSystemRange pages looking for MZ/PE headers
2. Any PE image found at a page-aligned address that is NOT in PsLoadedModuleList is a hidden driver
3. These hidden drivers are the most suspicious — immediately flagged
```

### Blacklisted Driver Categories

Based on known EAC bans and community analysis, the internal blacklist targets:

| Category | Examples | How Detected |
|---|---|---|
| **Kernel memory readers** | mhyprotect, PhyMem, memdriver | Module name hash |
| **HWID spoofers** | Various private spoofers | Signature pattern |
| **Debug/analysis tools** | WinDbg kernel stubs, kdnet | Module name |
| **Hypervisors** | VMware SVGA, VirtualBox additions in gaming VMs | Module path |
| **Cheat frameworks** | PUBG/Fortnite cheat drivers, various | Byte signature |
| **Vulnerable signed drivers** | Old Dell BIOSConnect, Ene.sys, etc. | Hash match |

---

## 5. Dispatch Table Hook Detection

Every Windows kernel driver exposes a `DRIVER_OBJECT` structure containing an array of **28 major function pointers** (IRP dispatch routines). EAC examines these for hooks:

```c
// For each loaded driver:
PDRIVER_OBJECT pDrv = ...;
for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
    PVOID handler = pDrv->MajorFunction[i];
    
    // Check: does this handler point within the driver's own image?
    if (handler < pDrv->DriverStart || 
        handler >= (PVOID)((ULONG_PTR)pDrv->DriverStart + pDrv->DriverSize)) {
        // HOOK DETECTED — handler points outside the driver!
        // Log: driver name, function index, rogue address
        flag_as_suspicious();
    }
}
```

### What This Catches

- **Storage driver hooks**: Cheats hook `disk.sys` or `storport.sys` MajorFunction to intercept IDENTIFY DEVICE commands and fake serial numbers
- **NDIS hooks**: MAC address spoofers hook NDIS miniport dispatch to return fake MACs
- **Legitimate call routing**: Sometimes filters legitimately extend stacks — EAC knows the expected stack layout and flags anomalies

---

## 6. Filter Driver & Stack Detection

The Windows I/O system uses **layered device stacks** — multiple drivers can attach above/below each other for a device. For example:

```
[Game Process] → [NTFS] → [Volume Manager] → [Disk Class Driver] → [HDD Firmware]
                                               ↑
                     [Spoofer filter attached here — intercepts IOCTL_STORAGE_QUERY]
```

EAC calls `IoGetAttachedDeviceReference` and `IoGetLowerDeviceObject` to walk device stacks and check:
- Number of drivers in the storage stack (unexpected extra layers = suspicious)
- Device type of each layer matches expected types
- Driver names of each layer are recognizable

---

## 7. Storage Driver IOCTL for HWID

To collect hardware IDs without going through easily-hookable user-mode APIs, EAC sends **direct IOCTL requests to storage drivers from kernel mode**:

```c
// EAC builds and sends these IOCTLs internally:

// 1. Get disk serial number:
IOCTL_STORAGE_QUERY_PROPERTY
  → StorageDeviceProperty → SerialNumberId

// 2. Get disk firmware info:  
IOCTL_ATA_PASS_THROUGH
  → ATA IDENTIFY DEVICE command
  → Returns 512 bytes including serial, model, firmware rev

// 3. Get volume GUID:
IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS
  → Cross-reference with registry volume GUID

// 4. Get network adapter MAC:
IOCTL_NDIS_QUERY_GLOBAL_STATS
  → OID_802_3_PERMANENT_ADDRESS (permanent, not spoofable via software)
```

By going **directly to the driver stack** rather than through WMI or registry, EAC bypasses most HWID-spoofing software that only intercepts the high-level query path.

---

*← [Back to README](README.md) | [Crypto & Obfuscation →](crypto_and_obfuscation.md)*

---

*Written by **Google Gemini (Antigravity AI)**.*