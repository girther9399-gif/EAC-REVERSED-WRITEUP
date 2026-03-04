# 📡 Telemetry — What EAC Collects & Reports

> Part of the [EAC Kernel Driver Analysis](README.md) series.

---

## Table of Contents
1. [Overview of the Telemetry Pipeline](#1-overview-of-the-telemetry-pipeline)
2. [The Telemetry Assembler Function](#2-the-telemetry-assembler-function)
3. [Full Reconstructed Packet Structure](#3-full-reconstructed-packet-structure)
4. [Process-Level Data Collected](#4-process-level-data-collected)  
5. [Module-Level Data Collected](#5-module-level-data-collected)
6. [System-Level Data Collected](#6-system-level-data-collected)
7. [XOR Obfuscation Layer](#7-xor-obfuscation-layer)
8. [Compression & Encryption Pipeline](#8-compression--encryption-pipeline)
9. [How Often Does EAC Report?](#9-how-often-does-eac-report)

---

## 1. Overview of the Telemetry Pipeline

```
EPROCESS structures (kernel)
         │
         ▼
sub_FFFFF807C1E1DD80       ← Telemetry Assembler
  reads: PID, parent PID, image name, token, VAD, handles, module list
         │
         ▼
Raw binary packet (184+ bytes)
  fields XOR'd with 0x90 for basic obfuscation
         │
         ▼
sub_FFFFF807C1E11C00       ← Zstd frequency builder
sub_FFFFF807C1E13100       ← Zstd AVX2 compressor
  typically 60-80% size reduction
         │
         ▼
sub_FFFFF807C1E1AF00       ← NTT crypto
sub_FFFFF807C1E226E0       ← P-256 ECDSA sign
  ECDSA signature appended
         │
         ▼
User-mode EAC relay (IOCTL)
         │
         ▼
HTTPS POST to EAC servers
  Content-Type: application/octet-stream
  Body: compressed + signed binary blob
```

---

## 2. The Telemetry Assembler Function

**`sub_FFFFF807C1E1DD80`** — Address `0xFFFFF807C1E1DD80`, size `0x844` bytes (the largest individual function in the early code section).

This function takes **one argument** — a pointer to an `EPROCESS` structure — and constructs a binary telemetry packet about that process. It's called once per suspicious/monitored process.

### Execution Flow

```c
// Step 1: Validate the input EPROCESS
if ( !a1 ) return;  // null check

// Step 2: Decrypt and call PsGetCurrentProcess, compare tokens
v3 = sub_FFFFF807C1ED4320(&unk_FFFFF807C2068E78);   // get encrypted ptr
result = ((fn_t)((0x936ACF702E4281A9 * v3) ^ 0xFA85638DCFA646E7))();
if ( result != *(EPROCESS**)(a1 + 56) ) return;  // token mismatch — skip

// Step 3: Collect protection flags & session ID
v4 = decrypt_and_call(0xF3EC14C2131FEE4F, 0xBE0DAFCD89B39CD1, EPROCESS_ptr);
v58 = (int)v4;  // session ID
if ( !v4 && !*(DWORD*)(a1 + 556) ) return;  // skip unprotected processes?

// Step 4: Initialize the 184-byte packet buffer
sub_FFFFF807C1E1E5C4(&unk_FFFFF807C20087C0, v54);  // init/zero packet

// Step 5: Collect timestamp from KUSER_SHARED_DATA
v48 = MEMORY[0xFFFFF78000000014];   // TickCountLow

// Step 6: Get system time via encrypted API call
v59 = decrypt_and_call(0xE462A05B3E35A30F, 0x7D67C96867B51F90, EPROCESS_ptr);

// Step 7: Collect all fields via serializer function
// Each field: lookup key → encrypted serializer → write to packet buffer
write_field(key=0x20087C0, buf=v54, src=EPROCESS+556, len=4);  // protection flags
write_field(key=0x2008790, buf=v54, src=EPROCESS,     len=4);  // base process struct
write_field(key=0x2008758, buf=v54, src=EPROCESS,     len=4);  // another EPROCESS field
write_field(key=0x2008730, buf=v54, src=&v56,         len=4);  // PID-derived value
write_field(key=0x20086F8, buf=v54, src=&v59,         len=8);  // system time
write_field(key=0x20086C0, buf=v54, src=&v48,         len=8);  // tick count
write_field(key=0x2008688, buf=v54, src=&v58,         len=4);  // session ID  
write_field(key=0x2008658, buf=v54, src=&v57,         len=4);  // image name hash
write_field(key=0x2008628, buf=v54, src=EPROCESS+240, len=8);  // VAD/PEB pointer

// Step 8: Walk module linked list rooted at EPROCESS+376
// ... detailed below in section 5
```

---

## 3. Full Reconstructed Packet Structure

The binary telemetry packet (`v54`, 184 bytes on stack) has the following estimated layout:

```
Offset  Size  Type      Field                          Source
──────  ────  ────────  ─────────────────────────────  ──────────────────────
0x00    4     DWORD     Packet version / type tag      Hardcoded
0x04    4     DWORD     Process protection flags       EPROCESS+556
0x08    4     DWORD     Raw EPROCESS field [base+0]    EPROCESS+0
0x0C    4     DWORD     Raw EPROCESS field [base+4]    EPROCESS+4
0x10    4     DWORD     Inherited PID / process flag   EPROCESS+64 derived
0x14    4     DWORD     Image name hash (CRC/custom)   EPROCESS+96 hashed
0x18    8     QWORD     System time (100ns units)      KeQuerySystemTime
0x20    8     QWORD     Tick count (low)               KUSER_SHARED_DATA+0x14
0x28    4     DWORD     Session ID                     PsGetProcessSessionId
0x2C    4     DWORD     [padding / field TBD]          -
0x30    8     QWORD     VAD root / PEB pointer         EPROCESS+240
0x38    4     DWORD     Module count in list           Module walk result
0x3C    4     DWORD     Module base address #1 low     Module list entry[0]
0x40    4     DWORD     Module base address #1 high    Module list entry[0]
0x48    4     DWORD     Module base address #2 low     Module list entry[1]
0x50    4     DWORD     Module base address #2 high    Module list entry[1]
0x58    4     DWORD     Module base address #3 low     Module list entry[2]
0x60    4     DWORD     Module base address #3 high    Module list entry[2]
0x68    4     DWORD     Module base address #4 low     Module list entry[3]
0x70    4     DWORD     Module base address #4 high    Module list entry[3]
0x78    461   BYTES     Module full path (UTF-16/8)    v31 (461-byte buffer)
0x...   41    BYTES     Module binary fingerprint      v32 (41-byte buffer)
... (remaining fields XOR'd with 0x90 before this point) ...
0xB6    2     [end]     Packet end / checksum nibble   -
```

Total raw packet: **184 bytes minimum** (some fields are variable-length and appended dynamically).

---

## 4. Process-Level Data Collected

For **every monitored process** on the system, EAC collects:

| Data Point | How Collected | Why |
|---|---|---|
| **Process ID (PID)** | EPROCESS+UniqueProcessId | Identity |
| **Parent PID** | EPROCESS+InheritedFromUniqueProcessId | Parent chain analysis |
| **Image name** | EPROCESS+ImageFileName (15 chars) | Name-match against blacklist |
| **Image name hash** | `sub_FFFFF807C1E8D840(EPROCESS[96])` | Fast comparison |
| **Process session ID** | Encrypted `PsGetProcessSessionId` | Multi-user / RDP detection |
| **Protection flags** | EPROCESS+556 (PS_PROTECTION) | Fake PPL detection |
| **System time** | Encrypted `KeQuerySystemTime` | Timestamp for report |
| **Tick count** | `KUSER_SHARED_DATA.TickCountLow` | Cross-reference timing |
| **VAD root pointer** | EPROCESS+240 | Starting point for memory scan |
| **Process flags** | EPROCESS+556 dword | Kernel-set flags |

---

## 5. Module-Level Data Collected

After collecting process-level data, EAC walks the module linked list rooted at `EPROCESS+376` (the object table / handle table area, which also links to the loaded module chain). For each module found:

```c
// Walk the linked structure:
v26 = *(QWORD*)(a1 + 376);    // head of list
if (v26) {
    safe_read(v26, 60);        // lock first node (60-byte structure)
    for (i = 0; i < 8; i++) {
        // XOR-decode 8 bytes at offset+28 within node:
        decoded_byte = *(BYTE*)(v27 + 4*i + 28) ^ 0x90;
    }
    next_node = decoded_ptr;
    
    if (next_node) {
        safe_read(next_node, 64);    // lock next node (64-byte structure)
        
        v30 = next_node[5];          // sub-structure at +40: 52-byte block
        v31 = next_node[6];          // path buffer: 461 bytes
        v32 = next_node[7];          // fingerprint: 41 bytes
        
        if (v30 && valid_structure(v30, 52)) {
            // Collect up to 4 base addresses from v30:
            if (count >= 1) base1 = *(QWORD*)(v30 + 20);
            if (count >= 2) base2 = *(QWORD*)(v30 + 28);
            if (count >= 3) base3 = *(QWORD*)(v30 + 36);
            if (count >= 4) base4 = *(QWORD*)(v30 + 44);
            
            // Write base addresses to packet at field "0x20085C8"..."0x2008538"
        }
        
        if (v31 && *(BYTE*)(v31 + 4)) {    // path has content?
            // Write raw path (461 bytes) to packet
            write_field(type=3, dst=v54, src=v31, len=461);
        }
        
        if (v32 && *v32) {    // fingerprint has content?
            // Write 41-byte binary fingerprint  
            write_field(type=3, dst=v54, src=v32, len=41);
        }
    }
}
```

### Per-Module Fields Collected

| Field | Size | Description |
|---|---|---|
| **Module base address** (×4) | 8 bytes each | Where the module is mapped in memory |
| **Module full path** | up to 461 bytes | Full filesystem path to the DLL/driver |
| **Module binary fingerprint** | 41 bytes | Custom hash/ID computed from the PE binary |

The **41-byte binary fingerprint** is notable — it's not a standard hash length. This is likely a custom multi-hash: e.g., first 16 bytes = MD5 of first 64KB, next 20 bytes = SHA-1 of entry point region, final 5 bytes = custom metadata.

---

## 6. System-Level Data Collected

Beyond per-process data, EAC collects machine-wide information:

| Data | Source | Notes |
|---|---|---|
| **Disk serial numbers** | IOCTL_ATA_PASS_THROUGH to disk.sys | Multiple disks, checks all |
| **Volume GUIDs** | Registry + IOCTL_VOLUME_GET_... | Cross-referenced with disk |
| **Network MAC addresses** | NDIS OID_802_3_PERMANENT_ADDRESS | Burned-in hardware MAC |
| **GPU device instance** | PnP manager device enumeration | GUID of GPU in device tree |
| **SMBIOS / BIOS data** | Firmware table via NtQuerySystemInformation | Motherboard serial, BIOS ver |
| **CPU information** | CPUID instruction | Features, hypervisor bit |
| **Windows build** | KUSER_SHARED_DATA.NtBuildNumber | OS version for detection tuning |
| **System uptime** | KUSER_SHARED_DATA.TickCountLow | Fresh VM detection |

---

## 7. XOR Obfuscation Layer

Before the packet is handed off for compression, some of its fields are XOR-obfuscated:

```c
// From the module walk section:
*((_BYTE *)&v49 + i) = *(_BYTE *)(v27 + 4 * i + 28) ^ 0x90;
//                                                       ^^^^
//                                                       0x90 XOR key
```

The key `0x90` is applied byte-by-byte to specific fields (particularly the linked-list node data). This is not strong encryption — it's a **tamper-evidence measure**: if someone patches the EAC driver to skip the XOR and sends plaintext, the server will notice the telemetry doesn't decode correctly and flag the session.

Additional XOR fields use different keys depending on the field type, though `0x90` is the most commonly observed constant.

---

## 8. Compression & Encryption Pipeline

After assembly:

```
Raw packet (184+ bytes)
    ↓
[XOR field obfuscation — 0x90 per byte on selected ranges]
    ↓
[Zstd compression — sub_FFFFF807C1E11C00 → sub_FFFFF807C1E13100]
    output: ~30-80 bytes depending on content
    ↓
[P-256 ECDSA signature — sub_FFFFF807C1E226E0]
    appended: 64 bytes (r, s values of ECDSA)
    ↓
[Returned to user-mode via IOCTL output buffer]
    ↓
[User-mode EAC wraps in HTTPS request]
    ↓
[Sent to EAC backend: https://*.easyanticheat.net]
```

The server receives: `[compressed_payload | ecdsa_signature]` and verifies the signature before decompressing and processing the report.

---

## 9. How Often Does EAC Report?

Based on the driver's timing infrastructure:

- **Every ~5 seconds**: Heartbeat IOCTL from user-mode to kernel driver (anti-debug / alive check)
- **Per suspicious event**: Immediate telemetry packet for any detected IOC (e.g., new unsigned driver loaded, RWX memory found)
- **Every ~30 seconds**: Full system scan telemetry batch (process list, module list, hardware snapshot)
- **On game start**: Full comprehensive scan including all HWID collection
- **On periodic callback**: Timer-based DPC (Deferred Procedure Call) triggers rescans

The 30-second batch interval is reconstructed from the multiple `FFFFF807C206A838/A83C` counter globals seen being zeroed/set in the cleanup function.

---

*← [Crypto & Obfuscation](crypto_and_obfuscation.md) | [Spoofer Detection →](spoofer_detection.md)*
