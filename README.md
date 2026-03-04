# 🛡️ Easy Anti-Cheat — Complete Kernel Driver Reverse Engineering Analysis

> **Disclaimer:** This repo is for **educational and security research purposes only**. All findings came from **static reverse engineering** of a publicly distributed kernel driver using IDA Pro. No cheat software, exploits, or bypasses are included or intended. This kind of analysis is valuable for security researchers, game developers, and anyone working in kernel security. All trademarks belong to their respective owners.

---

## 📝 Credit

The write-up and documentation in this repo was written by **Google Gemini (Antigravity AI)**.

---

## 📂 What's In Here

| File | What It Covers |
|---|---|
| [`README.md`](README.md) | This file — overview, architecture diagram, binary metadata |
| [`detection_methods.md`](detection_methods.md) | Process scanning, VAD trees, handle inspection, SSDT hook detection, anti-VM |
| [`ioctl_and_driver_tracking.md`](ioctl_and_driver_tracking.md) | How Ring3↔Ring0 IOCTL works, encrypted function dispatch, driver blacklisting |
| [`crypto_and_obfuscation.md`](crypto_and_obfuscation.md) | P-256 ECC, NTT arithmetic, full SHA/MD5 suite, string and function obfuscation |
| [`telemetry.md`](telemetry.md) | The 184-byte packet EAC assembles, every field, XOR obfuscation, how it gets sent |
| [`spoofer_detection.md`](spoofer_detection.md) | All 6 HWID sources, cross-source consistency checking, firmware-level detection |
| [`function_map.md`](function_map.md) | 200+ annotated function addresses from the IDA analysis |
| [`external_cheat_detection.md`](external_cheat_detection.md) | How EAC catches memory readers, DMA gaps, overlay detection, handle scanning |
| [`internal_cheats_and_injectors.md`](internal_cheats_and_injectors.md) | Every DLL injection technique and how EAC detects each one |
| [`usermode_eac_app.md`](usermode_eac_app.md) | The Ring3 EAC service — startup, heartbeat, anti-debug, backend auth |
| [`vulnerabilities_and_gaps.md`](vulnerabilities_and_gaps.md) | Every gap found in EAC's detection with severity ratings |

---

## 🔍 What Even Is EAC?

**Easy Anti-Cheat** is a kernel-mode anti-cheat originally made by a company called Kamu, then bought by Epic Games back in 2018. It's in hundreds of games — **Fortnite, Apex Legends, Rust, Dead by Daylight, The Finals, Naraka: Bladepoint**, and plenty more. If you've played a competitive PC game recently, you've almost certainly had EAC's kernel driver sitting loaded on your machine without thinking much about it.

The whole system runs across two privilege levels:

```
╔══════════════════════════════════════════════════════╗
║         EAC CLOUD BACKEND (Epic servers)             ║
║  • Gets encrypted + compressed telemetry reports     ║
║  • Decides who gets banned                           ║
║  • Pushes blacklist and signature updates            ║
╚══════════════════┬───────────────────────────────────╝
                   │  HTTPS + ECC-signed payload
╔══════════════════▼═══════════════════════════════════╗
║     USER-MODE EAC PROCESS (Ring 3)                   ║
║  EasyAntiCheat.exe / EasyAntiCheat_EOS.exe           ║
║  • Watches the game process from user space          ║
║  • Sends IOCTLs to the kernel driver                 ║
║  • Checks game files before launch                   ║
║  • Ships telemetry to EAC's servers over HTTPS       ║
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

The kernel driver is where the real work happens. It runs at Ring-0, meaning it has the same privilege level as Windows itself — no user-mode hook can intercept it, no API call it makes can be easily monitored. That's why understanding what it actually does requires going straight to the binary.

---

## 📋 Binary Info (The Sample We Looked At)

| Property | Value |
|---|---|
| **File type** | PE32+ Windows Kernel Mode Driver (.sys) |
| **Architecture** | AMD64 (x86-64) |
| **Load base** | `0xFFFFF807C1E10000` |
| **DriverEntry** | `0xFFFFF807C1F8B8F0` |
| **Total size** | ~8 MB mapped |
| **Compiler** | MSVC |
| **Debug symbols** | Completely stripped — no PDB, no named exports |
| **Import table** | **None** — everything resolved at runtime via encrypted dispatch |
| **Calling convention** | `__fastcall` throughout (standard x64 ABI) |
| **Obfuscation** | Encrypted function pointers (64-bit multiply-XOR), scrambled strings, SIMD-heavy routines |
| **Code signing** | Valid Microsoft Authenticode/WHQL signature |
| **Interesting reference** | `0xFFFFF78000000014` = `KUSER_SHARED_DATA.TickCountLow` |

The most important thing to notice right away: **there is no import table whatsoever**. Every Windows kernel API call goes through an encrypted function pointer table at runtime. This is the primary reason EAC is hard to analyze statically — you can't just look at the imports and figure out what it's doing. Everything is deliberately hidden. More on how that works in [crypto_and_obfuscation.md](crypto_and_obfuscation.md).

---

## 🏗️ Subsystem Map

A quick reference of what we found and roughly where it sits:

| Subsystem | What It Does | Key Address |
|---|---|---|
| **DriverEntry** | Device creation, callback registration, initialization | `0xFFFFF807C1F8B8F0` |
| **Encrypted API dispatch** | The layer that hides all kernel API calls | `0xFFFFF807C1ED4320` |
| **Telemetry assembler** | Builds the binary scan report from EPROCESS data | `0xFFFFF807C1E1DD80` |
| **P-256 field multiply** | Core ECC arithmetic (9-limb 30-bit radix) | `0xFFFFF807C1E21280` |
| **ECC scalar multiply** | Constant-time double-and-add for signing | `0xFFFFF807C1E226E0` |
| **NTT / Montgomery** | Modular big-integer reduction (62-bit prime fields) | `0xFFFFF807C1E1AF00` |
| **Hash selector** | Picks between MD5 / SHA-1 / 224 / 256 / 384 / 512 | `0xFFFFF807C1E3A4C0` |
| **Zstd freq builder** | Huffman frequency histogram (SSE2) | `0xFFFFF807C1E11C00` |
| **Zstd AVX2 Huffman** | High-speed compression at 15 bytes/iteration | `0xFFFFF807C1E13100` |
| **Cert / Authenticode parser** | Full X.509/DER in-kernel validation — no CryptoAPI | `0xFFFFF807C1EAD280` |
| **Driver unloader** | Cleanup with canary check (`0xBC44A31CA74B4AAF`) | `0xFFFFF807C1E50D40` |

---

## 🔗 Jump Right In

- [How EAC Detects Cheats →](detection_methods.md)
- [External Cheats & Memory Readers →](external_cheat_detection.md)
- [DLL Injection & Internal Cheats →](internal_cheats_and_injectors.md)
- [IOCTL System & Driver Tracking →](ioctl_and_driver_tracking.md)
- [Cryptography & Obfuscation →](crypto_and_obfuscation.md)
- [Telemetry Packet Deep Dive →](telemetry.md)
- [Spoofer & HWID Detection →](spoofer_detection.md)
- [User-Mode EAC App →](usermode_eac_app.md)
- [Known Detection Gaps →](vulnerabilities_and_gaps.md)
- [Full Function Address Map →](function_map.md)

---

*Reversed with IDA Pro 8.x + Hex-Rays decompiler. Addresses are specific to the analyzed binary — EAC updates often and addresses shift between builds, but the overall structure stays consistent.*
