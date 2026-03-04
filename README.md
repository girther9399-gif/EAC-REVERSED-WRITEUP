# 🛡️ Easy Anti-Cheat — Complete Kernel Driver Reverse Engineering Analysis

> **Disclaimer:** This entire repository is for **educational and security research purposes only**. All findings were obtained via **static reverse engineering** (IDA Pro disassembly + decompilation) of a publicly distributed kernel driver. No cheat software, exploits, or bypass tools are provided or implied. Understanding anti-cheat internals helps security researchers, game developers, and kernel engineers build better protective systems. All trademarked names belong to their respective owners.

---

## 📂 Documents in This Repository

| File | What It Covers |
|---|---|
| [`README.md`](README.md) | You're here — overview, architecture, binary metadata |
| [`detection_methods.md`](detection_methods.md) | How EAC scans processes, memory, threads, handles, VAD trees |
| [`ioctl_and_driver_tracking.md`](ioctl_and_driver_tracking.md) | IOCTL dispatch system, how EAC communicates ring0↔ring3, driver enumeration |
| [`crypto_and_obfuscation.md`](crypto_and_obfuscation.md) | P-256 ECC, NTT crypto, SHA family hashing, function pointer obfuscation |
| [`telemetry.md`](telemetry.md) | Every data field EAC collects, packet structure, binary encoding |
| [`spoofer_detection.md`](spoofer_detection.md) | Hardware ID collection, spoofer/HWID ban evasion detection |
| [`function_map.md`](function_map.md) | Full annotated function address map from IDA analysis |

---

## 🔍 What Is EAC?

**Easy Anti-Cheat** is a commercial kernel-mode anti-cheat solution developed by Kamu, acquired by Epic Games in 2018. It protects hundreds of games including **Fortnite, Apex Legends, Rust, Dead by Daylight, The Finals, Naraka: Bladepoint**, and dozens more.

EAC operates across two privilege rings:

```
╔══════════════════════════════════════════════════════╗
║         EAC CLOUD BACKEND (Epic servers)             ║
║  • Receives encrypted+compressed telemetry reports   ║
║  • Issues ban decisions & cryptographic challenges   ║
║  • Pushes driver/module blacklist signature updates  ║
╚══════════════════┬───────────────────────────────────╝
                   │  HTTPS + ECC-signed payload
╔══════════════════▼═══════════════════════════════════╗
║     USER-MODE EAC PROCESS (Ring 3)                   ║
║  EasyAntiCheat.exe / EasyAntiCheat_EOS.exe           ║
║  • Launches & monitors game process                  ║
║  • Sends/receives IOCTL to kernel driver             ║
║  • Performs file integrity checks pre-launch         ║
║  • Relays compressed telemetry to EAC servers        ║
╚══════════════════┬═══════════════════════════════════╝
                   │  DeviceIoControl (IOCTL)
╔══════════════════▼═══════════════════════════════════╗
║  KERNEL DRIVER Ring-0  (EasyAntiCheat.sys)           ║
║                                                      ║
║  ┌─────────────────┐  ┌───────────────────────────┐  ║
║  │  Process/Memory │  │  Driver/Module Enumerator  │  ║
║  │  Scanner        │  │  (PsLoadedModuleList walk) │  ║
║  └─────────────────┘  └───────────────────────────┘  ║
║  ┌─────────────────┐  ┌───────────────────────────┐  ║
║  │  VAD Tree Walker│  │  Handle Table Inspector    │  ║
║  │  (injected mem) │  │  (open handles to game)    │  ║
║  └─────────────────┘  └───────────────────────────┘  ║
║  ┌─────────────────┐  ┌───────────────────────────┐  ║
║  │  HW ID Collector│  │  Kernel Integrity Checker  │  ║
║  │  (disk/GPU/MAC) │  │  (SSDT / inline hook scan) │  ║
║  └─────────────────┘  └───────────────────────────┘  ║
║  ┌─────────────────┐  ┌───────────────────────────┐  ║
║  │  ECC/NTT Crypto │  │  Zstd Compressor           │  ║
║  │  (P-256 signing)│  │  (AVX2 Huffman streams)    │  ║
║  └─────────────────┘  └───────────────────────────┘  ║
╚══════════════════════════════════════════════════════╝
```

---

## 📋 Binary Metadata (Analyzed Sample)

| Property | Value |
|---|---|
| **File type** | PE32+ Windows Kernel Mode Driver (.sys) |
| **Target architecture** | AMD64 (x86-64) |
| **Load base address** | `0xFFFFF807C1E10000` |
| **DriverEntry** | `0xFFFFF807C1F8B8F0` |
| **Total mapped size** | ~`0x800000` bytes (~8 MB) |
| **Compiler** | Microsoft MSVC (MSVC-style SEH, runtime patterns) |
| **Debug symbols** | **Fully stripped** — no PDB, no exports beyond `DriverEntry` |
| **Import table** | **None** — all imports resolved dynamically at runtime via encrypted dispatch |
| **Calling convention** | `__fastcall` throughout (standard x64 ABI) |
| **Security features** | Function pointer encryption (64-bit multiply-XOR), string obfuscation, SIMD obfuscation, control flow flattening fragments |
| **Signing** | Valid WHQL/Microsoft Authenticode signature (required for kernel load) |
| **Key memory reference** | `0xFFFFF78000000014` = `KUSER_SHARED_DATA.TickCountLow` |

---

## 🏗️ High-Level Subsystem Summary

| Subsystem | Description | Primary Addresses |
|---|---|---|
| **DriverEntry & init** | Registers dispatch, callbacks, creates device | `0xFFFFF807C1F8B8F0` |
| **Encrypted API dispatch** | All kernel API calls go through this | `0xFFFFF807C1ED4320` |
| **Telemetry assembler** | Builds binary report packet from EPROCESS data | `0xFFFFF807C1E1DD80` |
| **P-256 scalar multiply** | ECC public key ops (9-limb 30-bit radix) | `0xFFFFF807C1E21280` |
| **ECC double-and-add** | Constant-time scalar mult for signing | `0xFFFFF807C1E226E0` |
| **NTT / Montgomery** | Modular big-integer reduction (62-bit fields) | `0xFFFFF807C1E1AF00` |
| **Hash selector** | MD5 / SHA-1 / SHA-224 / SHA-256 / SHA-384 / SHA-512 init | `0xFFFFF807C1E3A4C0` |
| **Zstd freq table** | Huffman frequency histogram builder (SSE2) | `0xFFFFF807C1E11C00` |
| **Zstd Huffman SSE** | 6-stream SSE2 Huffman coder | `0xFFFFF807C1E11EE0` |
| **Zstd Huffman AVX2** | High-speed AVX2 Huffman (15B/iter) | `0xFFFFF807C1E13100` |
| **Driver unloader** | Cleanup + canary check (`0xBC44A31CA74B4AAF`) | `0xFFFFF807C1E50D40` |
| **Heap sort (ZSTD)** | 24-byte node sort, used in compression scheduler | `0xFFFFF807C1E30B00` |

---

## 🔗 Quick Links

- [How EAC Detects Cheats →](detection_methods.md)
- [IOCTL System & Driver Tracking →](ioctl_and_driver_tracking.md)
- [Cryptography & Obfuscation →](crypto_and_obfuscation.md)
- [Telemetry Packet Analysis →](telemetry.md)
- [Spoofer & HWID Detection →](spoofer_detection.md)
- [Full Function Address Map →](function_map.md)

---

*Analysis performed via static reverse engineering with IDA Pro 8.x + Hex-Rays decompiler. All addresses reflect the specific binary dump analyzed. EAC updates continuously — addresses change per version but subsystem structure is consistent.*
