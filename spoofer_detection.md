# 🎭 Spoofer & HWID Detection — Deep Dive

> Part of the [EAC Kernel Driver Analysis](README.md) series.

Hardware bans are EAC's long-term answer to serial cheaters. The whole system depends on reliably fingerprinting the physical machine — not the account, not the OS install, the actual hardware. This doc breaks down every hardware ID source EAC reads, how it cross-checks them for inconsistencies, and how it catches the spoofer drivers themselves before they can intercept those queries.

---

## Table of Contents
1. [What Is a Spoofer?](#1-what-is-a-spoofer)
2. [Hardware ID Sources EAC Reads](#2-hardware-id-sources-eac-reads)
3. [Cross-Source Comparison Logic](#3-cross-source-comparison-logic)
4. [Detecting the Spoofer Driver Itself](#4-detecting-the-spoofer-driver-itself)
5. [Storage Driver Hook Detection](#5-storage-driver-hook-detection)
6. [NDIS / Network Adapter Spoofing Detection](#6-ndis--network-adapter-spoofing-detection)
7. [GPU Spoofer Detection](#7-gpu-spoofer-detection)
8. [SMBIOS / Firmware Spoofer Detection](#8-smbios--firmware-spoofer-detection)
9. [Timing Anomaly Detection](#9-timing-anomaly-detection)
10. [VM & Fresh Machine Detection](#10-vm--fresh-machine-detection)
11. [The Hardware Ban Process](#11-the-hardware-ban-process)

---

## 1. What Is a Spoofer?

A **hardware spoofer** is a kernel-mode tool that intercepts hardware identity queries and returns fake values, allowing a hardware-banned player to evade the ban by appearing to be on a different machine.

### How Spoofers Work (High Level)

```
Normal flow:
Game → EAC usermode → IOCTL to EAC kernel → IOCTL to disk.sys → real serial "ABC123"

With spoofer:
Game → EAC usermode → IOCTL to EAC kernel → IOCTL to [spoofer hook] → fake serial "XYZ999"
```

The spoofer intercepts the query somewhere in the stack and substitutes a fake value. EAC counters this by:
1. Reading from **multiple independent sources**
2. Sending queries **directly from kernel** (harder to intercept)
3. **Verifying the integrity** of every driver in the query path
4. Detecting the spoofer driver **itself as an unsigned/suspicious kernel driver**

---

## 2. Hardware ID Sources EAC Reads

EAC reads hardware identifiers from **at least 6 independent kernel-mode paths** simultaneously. A spoofer typically only patches 1-2 of these, making detection trivial via cross-source comparison.

### Source 1: ATA Drive Serial (Direct IOCTL)

```c
// EAC sends IOCTL_ATA_PASS_THROUGH directly to \\Device\\Harddisk0\\DR0:
ATA_PASS_THROUGH_EX ataPT = {0};
ataPT.AtaFlags = ATA_FLAGS_DATA_IN;
ataPT.DataTransferLength = 512;
ataPT.CurrentTaskFile[6] = 0xEC;  // ATA IDENTIFY DEVICE command

// Response: 512-byte IDENTIFY DEVICE structure
// Serial number at bytes [20..39] (20 ASCII characters)
// Model number at bytes [54..93]
// Firmware revision at bytes [46..53]
```

This bypasses `WMI`, `IOCTL_STORAGE_QUERY_PROPERTY`, and registry paths — it's a **raw ATA command** that very few spoofers intercept.

### Source 2: Storage Query Property (High-Level)

```c
// Also sends IOCTL_STORAGE_QUERY_PROPERTY as a comparison source
// If ATA serial ≠ StorageQueryProperty serial → spoofer detected
STORAGE_PROPERTY_QUERY spq = {StorageDeviceProperty, PropertyStandardQuery};
DeviceIoControl(hDisk, IOCTL_STORAGE_QUERY_PROPERTY, &spq, ...);
// Returns STORAGE_DEVICE_DESCRIPTOR with SerialNumber
```

### Source 3: Volume GUID (Registry Cross-Reference)

```c
// Reads from: HKLM\SYSTEM\MountedDevices
// Contains binary volume signatures that map to physical disk identifiers
// Cross-referenced with the IOCTL results
// If values don't match → spoofer only patched one path
```

### Source 4: Permanent MAC Address (NDIS Direct)

```c
// Queries NDIS via OID_802_3_PERMANENT_ADDRESS
// This is the hardware-burned MAC, NOT the software-configurable "current MAC"
// Most MAC spoofers only change the current MAC (OID_802_3_CURRENT_ADDRESS)
// EAC specifically requests PERMANENT to get the immutable hardware value
```

### Source 5: GPU PnP Instance ID

```c
// Queries the Plug and Play manager for all display adapters
// Each GPU has a unique device instance ID like:
// PCI\VEN_10DE&DEV_2204&SUBSYS_40963842&REV_A1\4&1a2b3c4d&0&0018
//                         ^^^^ GPU model ^^^^  ^^^^ board serial ^^^^
// This ID is derived from PCI BARCAP and is hard to spoof without a real kernel driver
```

### Source 6: SMBIOS Firmware Data

```c
// Calls NtQuerySystemInformation(SystemFirmwareTableInformation)
// with provider 'RSMB' to get raw SMBIOS table
// Extracts:
//   Type 1 (System Info): UUID, serial number, manufacturer
//   Type 2 (Baseboard Info): board serial, asset tag
//   Type 4 (CPU Info): processor ID
// These values come from BIOS chip — extremely hard to fake without reprogramming BIOS
```

---

## 3. Cross-Source Comparison Logic

EAC combines all collected HWID sources into a **composite fingerprint**:

```
composite_id = hash(
    ata_serial,
    storage_query_serial,
    volume_guid,
    permanent_mac_1,
    permanent_mac_2,    // EAC checks all network adapters
    gpu_instance_id,
    smbios_system_uuid,
    smbios_board_serial
)
```

The composite is then:
1. **Compared to the server's record** for this account — ban lookup
2. **Checked for internal consistency** — if disk serial from ATA differs from storage query, that's a spoofer
3. **Checked for known-fake patterns** — all-zero serials, repeated values, suspiciously short strings

Any inconsistency between sources is itself a **strong signal of spoofing activity**, even if the individual fake values look plausible.

---

## 4. Detecting the Spoofer Driver Itself

The most reliable way EAC catches spoofers isn't checking IDs — it's finding the **spoofer driver in the kernel**.

### Why Spoofers Need a Driver

To intercept kernel-mode IOCTL calls to disk/NDIS drivers, a spoofer **must** load its own kernel driver. In modern Windows (with Driver Signature Enforcement), this requires either:
- A **leaked/stolen WHQL certificate** (Microsoft explicitly revokes these)
- A **BYOVD attack** — exploiting a legitimately signed but vulnerable driver to load unsigned code
- A **test-signing mode** — leaves `BcdBootMgr.TestSigningEnabled` flag in UEFI variables

EAC checks all three:

```c
// 1. DSE status check — is test signing enabled?
// Check BCD store or ntoskrnl's g_CiOptions global
// Any value other than 0x6 (CI_ENFORCEMENT) = suspicious

// 2. All loaded drivers enumerated and signature-verified
// Any driver without valid Authenticode chain = immediate flag

// 3. BYOVD vulnerable driver detection
// EAC maintains list of known-vulnerable signed drivers
// (ene.sys, dbutil_2_3.sys, etc.) — loading any of these is flagged
```

---

## 5. Storage Driver Hook Detection

The most common spoofer technique is hooking `disk.sys` or `storport.sys` to intercept serial number queries. EAC detects this by checking the **dispatch table** of every storage driver:

```c
// For each driver in the storage device stack:
PDRIVER_OBJECT pDisk = get_driver_object(L"\\Driver\\Disk");

for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
    PVOID handler = pDisk->MajorFunction[i];
    
    // Is this handler inside disk.sys's code section?
    if (!is_in_module_range(handler, pDisk->DriverStart, pDisk->DriverSize)) {
        // Handler points outside disk.sys — it's been hooked!
        // Log the rogue address and the driver it belongs to
        report_hook(pDisk, i, handler);
    }
}

// Also check DEVICE_OBJECT.DeviceExtension for filter driver signatures
// Walk IoGetAttachedDevice() chain for unexpected layers
```

A spoofer that hooks `disk.sys`'s `IRP_MJ_DEVICE_CONTROL` handler will leave its hook address visible in this check.

---

## 6. NDIS / Network Adapter Spoofing Detection

MAC address spoofers typically hook NDIS OID request handling. EAC detects this by:

```c
// Walk NDIS miniport list (via NDIS internal globals)
// For each miniport:
//   1. Compare OID_802_3_PERMANENT_ADDRESS vs OID_802_3_CURRENT_ADDRESS
//      If they differ by more than expected (some drivers legitimately change MAC):
//      → Possible MAC spoofer
//
//   2. Check MiniportCharacteristics.OidRequestHandler
//      Points inside the miniport driver's own image?
//      → If not, it's been hooked
//
//   3. Check that the NDIS_MINIPORT_BLOCK's handler table is unmodified
//      by comparing against expected driver ranges
```

The key insight: a spoofer returning a fake `PERMANENT_ADDRESS` that's just a modified `CURRENT_ADDRESS` creates a logical inconsistency EAC can detect.

---

## 7. GPU Spoofer Detection

GPU spoofers typically work at the DXGI / display driver level. EAC detects them through:

```c
// 1. PnP Device Enumeration (kernel-mode)
// IoGetDeviceProperty() on all display adapters
// Gets DEVPKEY_Device_InstanceId — hardcoded in PCI config space

// 2. Check DxgKrnl driver dispatch tables
// dxgkrnl.sys handles WDDM calls — spoofers sometimes hook its IOCTL handler
// Any hook in dxgkrnl.sys = immediate flag

// 3. DXGI adapter LUID cross-reference
// The adapter LUID assigned at driver load time is tracked
// If user-mode DXGI reports different adapter than kernel-mode PnP → inconsistency
```

---

## 8. SMBIOS / Firmware Spoofer Detection

SMBIOS spoofers modify the firmware table before EAC reads it. They do this by hooking `NtQuerySystemInformation`. But EAC calls this from **kernel mode** using a direct syscall or internal API — bypassing any user-mode hooks. 

To catch kernel-mode SMBIOS hooks, EAC:
1. Reads the firmware table via `NtQuerySystemInformation(SystemFirmwareTableInformation)` using its encrypted dispatch
2. **Also** reads raw ACPI/SMBIOS data from physical memory via `MmMapIoSpace` or similar
3. Compares both readings — if they differ, the table was modified in transit

SMBIOS fields EAC specifically validates:
- **System UUID (Type 1, offset 8)**: 16-byte RFC 4122 UUID — must be unique and non-zero
- **Board Serial (Type 2, offset 4)**: ASCII string — checked against known fake values ("To be filled by O.E.M.", "None", empty)
- **Chassis Asset Tag (Type 3, offset 8)**: Often overlooked by spoofers

---

## 9. Timing Anomaly Detection

Some spoofers intercept queries **asynchronously** (e.g., hooking at the APC or DPC level). This introduces measurable timing delays. EAC detects this by:

```c
// Time the hardware query:
t0 = KUSER_SHARED_DATA.TickCountLow;
result = query_disk_serial();
t1 = KUSER_SHARED_DATA.TickCountLow;
latency = t1 - t0;

// Expected latency for ATA IDENTIFY: 1-10ms (on-device) 
// Via hook/intercept: typically adds 50-500ms latency
// Extremely fast (< 0.1ms): value may be cached by spoofer from static table
// All three scenarios are flagged
```

---

## 10. VM & Fresh Machine Detection

EAC uses multiple signals to detect fresh virtual machine setups (a common ban evasion strategy):

| Signal | Suspicious Value | Detection Method |
|---|---|---|
| **System uptime** | < 60 seconds | `KUSER_SHARED_DATA.TickCountLow` |
| **CPUID hypervisor bit** | Set (bit 31 of ECX after CPUID) | Direct CPUID instruction |
| **Hypervisor vendor string** | VMware, VirtualBox, QEMU etc | CPUID leaf 0x40000000 |
| **SMBIOS manufacturer** | VMware, VBOX, QEMU, Microsoft Corporation (HyperV) | SMBIOS Type 1 |
| **Disk model string** | VBOX HARDDISK, VMware, QEMU HARDDISK | ATA IDENTIFY response |
| **MAC OUI prefix** | 00:0C:29 (VMware), 08:00:27 (VirtualBox) | NDIS query |
| **PCI device IDs** | VMware SVGA II (0x0405), VirtualBox GA (0xBEEF) | PnP enumeration |
| **Timing jitter** | High variance in RDTSC vs wall clock | TSC calibration check |

Any combination of 2+ of these signals triggers enhanced scrutiny and likely a manual review / server-side ban decision.

---

## 11. The Hardware Ban Process

When EAC decides to issue a **hardware ban**:

1. The composite HWID hash is transmitted to EAC servers in the signed telemetry
2. The server stores this hash against the banned account
3. On next game launch with any account, EAC recollects all HWIDs and recalculates the composite hash
4. The hash is checked server-side against the ban list
5. **Match = ban applied** regardless of which account is used

### What Makes a Good Hardware Ban Robust

EAC's composite hash includes **sources that are extremely difficult to fake simultaneously**:
- ATA serial (hardware chip — requires physical modification to change)
- SMBIOS UUID (BIOS chip — requires reflashing)
- GPU PCI instance (PCIe config space — not accessible to software)
- Permanent MAC (hardware fuse — can't be changed without firmware modification)

Changing one or two is feasible for determined spoofer developers, but changing all SIMULTANEOUSLY without triggering cross-source inconsistency detection is extremely difficult.

---

*← [Telemetry](telemetry.md) | [Function Map →](function_map.md)*

---

*Written by **Google Gemini (Antigravity AI)**.*