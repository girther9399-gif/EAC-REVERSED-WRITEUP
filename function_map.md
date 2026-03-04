# 🗺️ Function Address Map — Full IDA Analysis

> Part of the [EAC Kernel Driver Analysis](README.md) series.
> 
> All addresses are for the specific analyzed binary loaded at base `0xFFFFF807C1E10000`.
> Different EAC versions will have different addresses but similar functional groupings.

---

## Legend

| Icon | Meaning |
|---|---|
| 🔐 | Cryptography |
| 📦 | Compression (Zstd) |
| 📡 | Telemetry & Data Collection |
| 🔎 | Detection / Scanning |
| 🔌 | IOCTL / Driver Communication |
| 🛡️ | Integrity Verification |
| ⚙️ | Infrastructure / Utility |
| 🚀 | Initialization / Startup |
| 🧹 | Cleanup / Unload |

---

## Primary Subsystem Functions

| Address | Size | Icon | Name (Reconstructed) | Description |
|---|---|---|---|---|
| `0xFFFFF807C1F8B8F0` | ~varies | 🚀 | `DriverEntry` | Driver initialization entry point — creates device object, registers callbacks, initializes all subsystems |
| `0xFFFFF807C1ED4320` | ~varies | 🔐 | `DecryptFnPtr` | Encrypted function pointer resolver — reads slot, applies 64-bit XOR to produce real kernel API address |
| `0xFFFFF807C1E1DD80` | `0x844` | 📡 | `AssembleTelemetryPacket` | Main telemetry builder — reads EPROCESS at 6 offsets, collects timestamps, walks module chain, encodes 184-byte packet |
| `0xFFFFF807C1E1E5C4` | `0xA4` | 📡 | `InitPacketBuffer` | Zero-initializes the 184-byte telemetry buffer and sets packet header |
| `0xFFFFF807C1E1E668` | `0x87` | 📡 | `SerializeField_20087C0` | Serializes process protection flags into packet |
| `0xFFFFF807C1E1E700` | `0x67` | 📡 | `SerializeField_2008758` | Serializes base EPROCESS field |
| `0xFFFFF807C1E1E780` | `0x53` | 📡 | `SerializeField_2008730` | Serializes PID-derived value |
| `0xFFFFF807C1E1E7D4` | `0x9A` | 📡 | `SerializeField_20086F8` | Serializes system time (8-byte QWORD) |
| `0xFFFFF807C1E1E870` | `0x8B` | 📡 | `SerializeField_20086C0` | Serializes TickCount from KUSER_SHARED_DATA |
| `0xFFFFF807C1E1E8FC` | `0x99` | 📡 | `SerializeField_2008688` | Serializes session ID (4-byte DWORD) |
| `0xFFFFF807C1E1E9A0` | `0x92` | 📡 | `SerializeField_2008658` | Serializes image name hash |
| `0xFFFFF807C1E1EA40` | `0x92` | 📡 | `SerializeField_2008628` | Serializes VAD/PEB pointer (8 bytes, EPROCESS+240) |
| `0xFFFFF807C1E1EAD4` | `0x8C` | 📡 | `SerializeField_20085F8` | Serializes module count at v30+12 (4 bytes) |
| `0xFFFFF807C1E1EB60` | `0x9A` | 📡 | `SerializeField_20085C8` | Serializes module base #1 (8 bytes, v30+20) |
| `0xFFFFF807C1E1EBFC` | `0x8C` | 📡 | `SerializeField_2008598` | Serializes module base #2 (8 bytes, v30+28) |
| `0xFFFFF807C1E1ECA0` | `0x92` | 📡 | `SerializeField_2008568` | Serializes module base #3 (8 bytes, v30+36) |
| `0xFFFFF807C1E1ED34` | `0x8C` | 📡 | `SerializeField_2008538` | Serializes module base #4 (8 bytes, v30+44) |
| `0xFFFFF807C1E1EDC0` | `0x8C` | 📡 | `SerializeField_2008508` | Serializes full module path (461-byte buffer, type=3) |
| `0xFFFFF807C1E1EE4C` | `0x99` | 📡 | `SerializeField_20084D8` | Serializes module binary fingerprint (41-byte buffer) |
| `0xFFFFF807C1E1F100` | `0x14` | ⚙️ | `GetField_Stub1` | Small stub — returns address for field key lookup |
| `0xFFFFF807C1E1F120` | `0x53` | ⚙️ | `GetField_Stub2` | Larger field key lookup dispatcher |

---

## Cryptographic Functions

| Address | Size | Icon | Name (Reconstructed) | Description |
|---|---|---|---|---|
| `0xFFFFF807C1E21280` | `0x409` | 🔐 | `P256_FieldMul` | P-256 polynomial field multiplication — 9-limb × 9-limb → 18-limb with carry prop, 30-bit radix |
| `0xFFFFF807C1E2168C` | `0x26C` | 🔐 | `P256_FieldReduce` | Modular reduction of multiplication result back to P-256 field element |
| `0xFFFFF807C1E21900` | `0x91` | 🔐 | `P256_PointAdd_Prep` | Elliptic curve point addition preparation (Jacobian coordinate conversion) |
| `0xFFFFF807C1E21994` | `0x137` | 🔐 | `P256_FieldAdd` | Field addition with conditional carry |
| `0xFFFFF807C1E21ACC` | `0x175` | 🔐 | `P256_FieldSub` | Field subtraction with borrow |
| `0xFFFFF807C1E21C44` | `0x175` | 🔐 | `P256_FieldNeg` | Field negation (p - x) |
| `0xFFFFF807C1E21DC0` | `0x81` | 🔐 | `P256_FieldSqr` | Field squaring (optimized double — not general multiply) |
| `0xFFFFF807C1E21E60` | `0x15B` | 🔐 | `P256_PointDouble` | Elliptic curve point doubling in Jacobian coordinates |
| `0xFFFFF807C1E21FC0` | `0x17E` | 🔐 | `P256_ConvertToAffine` | Convert Jacobian (X:Y:Z) to affine (x,y) coordinates |
| `0xFFFFF807C1E22140` | `0x1F2` | 🔐 | `P256_PointAdd` | Full Jacobian point addition (unified formula) |
| `0xFFFFF807C1E22340` | `0x1D0` | 🔐 | `P256_ConditionalSwap` | Constant-time conditional swap for Montgomery ladder |
| `0xFFFFF807C1E22520` | `0x17E` | 🔐 | `P256_FieldInvert` | Field inversion via Fermat's little theorem (exp to p-2) |
| `0xFFFFF807C1E226A0` | `0x35` | 🔐 | `P256_ScalarMul_Entry` | Entry point for P-256 scalar multiplication dispatch |
| `0xFFFFF807C1E226E0` | `0x31D` | 🔐 | `P256_ScalarMul` | Constant-time 2-bit NAF scalar multiplication — core ECC loop |
| `0xFFFFF807C1E1AF00` | `0x5EB` | 🔐 | `NTT_MontgomeryReduce` | NTT with Montgomery/Barrett modular reduction — polynomial multiplication in 62-bit prime field |
| `0xFFFFF807C1E1AB00` | `0x3E5` | 🔐 | `NTT_Butterfly` | Cooley-Tukey NTT butterfly operation — core transform primitive |
| `0xFFFFF807C1E1AA80` | `0x68` | 🔐 | `NTT_BitReverse` | Bit-reversal permutation for NTT input/output ordering |
| `0xFFFFF807C1E1A7C0` | `0x88` | 🔐 | `NTT_Finalize` | Post-NTT normalization — divide by transform length (Montgomery scaling) |
| `0xFFFFF807C1E1A850` | `0x149` | 🔐 | `NTT_Setup` | Initialize NTT workspace, compute twiddle factors |
| `0xFFFFF807C1E1A640` | `0x17D` | 🔐 | `ECDSA_Sign` | ECDSA signing operation using P-256 and NTT as backend |
| `0xFFFFF807C1E1A490` | `0x1A8` | 🔐 | `ECDSA_Verify` | ECDSA signature verification |
| `0xFFFFF807C1E977E0` | ~varies | 🔐 | `Montgomery_SqrStep` | Single-step Montgomery squaring (called in NTT exponentiation loop) |

---

## Hash / Integrity Functions

| Address | Size | Icon | Name (Reconstructed) | Description |
|---|---|---|---|---|
| `0xFFFFF807C1E3A4C0` | `0x11A` | 🛡️ | `HashContext_Init` | Hash algorithm selector — initializes MD5/SHA-1/SHA-224/SHA-256/SHA-384/SHA-512 context based on selector |
| `0xFFFFF807C1E3BB98` | ~varies | 🛡️ | `SHA512_Init` | SHA-512 specific initialization (64-byte init vector) |
| `0xFFFFF807C1E3BCCC` | ~varies | 🛡️ | `SHA384_Init` | SHA-384 specific initialization (48-byte output variant) |
| `0xFFFFF807C1E3A568` | ~varies | 🛡️ | `SHA256_BlockProcess` | SHA-256 block compression function (64-byte blocks) |
| `0xFFFFF807C1E3A5cd` | ~varies | 🛡️ | `SHA1_BlockProcess` | SHA-1 block compression function |
| `0xFFFFF807C1E8D840` | ~varies | 🛡️ | `HashImageName` | Hashes 15-char process image name from EPROCESS+96 |
| `0xFFFFF807C1E28DA0` | `0xC3` | 🛡️ | `VerifyModuleSignature` | Verifies Authenticode signature of a loaded module |
| `0xFFFFF807C1E29540` | `0x3B` | 🛡️ | `CheckSignatureResult` | Validates signature verification return code |
| `0xFFFFF807C1E2A4E0` | `0xCF` | 🛡️ | `ComputeModuleFingerprint` | Computes 41-byte binary fingerprint for a module |

---

## Zstd Compression Engine

| Address | Size | Icon | Name (Reconstructed) | Description |
|---|---|---|---|---|
| `0xFFFFF807C1E11C00` | `0x2D1` | 📦 | `Zstd_BuildFreqTable` | Builds byte frequency histogram from input data — core Huffman table builder (SSE2) |
| `0xFFFFF807C1E11EE0` | `0x579` | 📦 | `Zstd_Huffman_SSE2` | SSE2 6-stream Huffman decoder/encoder |
| `0xFFFFF807C1E12460` | `0x54D` | 📦 | `Zstd_Huffman_AVX2_v1` | AVX2 alternate Huffman coder |
| `0xFFFFF807C1E129C0` | `0x23A` | 📦 | `Zstd_BlockDecompress` | Zstd block decompression handler |
| `0xFFFFF807C1E12C00` | `0x2E9` | 📦 | `Zstd_SequenceDecode` | Zstd sequence decoding (literal + match copy) |
| `0xFFFFF807C1E12F00` | `0x1FA` | 📦 | `Zstd_FSE_Decode` | Finite State Entropy (FSE) table decoder |
| `0xFFFFF807C1E13100` | `0x577` | 📦 | `Zstd_Huffman_AVX2_4stream` | High-performance AVX2 4-to-6-stream Huffman — 15 bytes/iteration, vpinsrb/vmovdqu/vpaddq |
| `0xFFFFF807C1E13680` | `0x2DC` | 📦 | `Zstd_BuildHuffmanTree` | Constructs Huffman tree from frequency table |
| `0xFFFFF807C1E13960` | `0x28B` | 📦 | `Zstd_AssignCodeLengths` | Assigns canonical code lengths to Huffman tree nodes |
| `0xFFFFF807C1E13C00` | `0x274` | 📦 | `Zstd_FSE_BuildTable` | Constructs FSE decoding/encoding table |
| `0xFFFFF807C1E13E80` | `0x256` | 📦 | `Zstd_CompressBlock` | Compresses single data block (frame content) |
| `0xFFFFF807C1E140E0` | `0x255` | 📦 | `Zstd_CompressLiterals` | Compresses literal sequences using Huffman |
| `0xFFFFF807C1E30B00` | `0x10C` | 📦 | `Zstd_HeapSiftDown` | Min-heap sift-down for 24-byte key nodes (Huffman priority queue) |
| `0xFFFFF807C1E30C20` | `0x30F` | 📦 | `Zstd_Quicksort` | Introsort/quicksort for Zstd data blocks (median-of-3 pivot, threshold=40) |
| `0xFFFFF807C1E31BE0` | `0x158` | 📦 | `Zstd_FrameHeader_Write` | Writes Zstd frame header (magic 0xFD2FB528, frame descriptor) |
| `0xFFFFF807C1E31D40` | `0x1C6` | 📦 | `Zstd_FrameHeader_Read` | Parses Zstd frame header from compressed stream |
| `0xFFFFF807C1E31F20` | `0xA9` | 📦 | `Zstd_ChecksumVerify` | Verifies Zstd xxHash64 content checksum |

---

## Infrastructure & Utility Functions

| Address | Size | Icon | Name (Reconstructed) | Description |
|---|---|---|---|---|
| `0xFFFFF807C1E1A140` | `0x1` | ⚙️ | `nullsub_2` | Null subroutine — placeholder / alignment |
| `0xFFFFF807C1E1A150` | `0xD` | ⚙️ | `ReturnZero` | Always returns 0 — used as a default handler |
| `0xFFFFF807C1E1A160` | `0xF` | ⚙️ | `ReturnOne` | Always returns 1 |
| `0xFFFFF807C1E1A170` | `0x1D6` | ⚙️ | `Pool_Alloc` | Kernel pool allocator wrapper (ExAllocatePoolWithTag obfuscated) |
| `0xFFFFF807C1E1A350` | `0x1F` | ⚙️ | `Pool_GetTag` | Returns pool tag constant |
| `0xFFFFF807C1E1A370` | `0xA6` | ⚙️ | `Pool_Free` | Kernel pool free wrapper |
| `0xFFFFF807C1E1A420` | `0x5E` | ⚙️ | `Pool_AllocZeroed` | Allocate + zero-fill pool memory |
| `0xFFFFF807C1E1A480` | `0x3` | ⚙️ | `ReturnArg` | Returns first argument unchanged |
| `0xFFFFF807C1E196A0` | `0x14F` | ⚙️ | `SafeReadMemory` | `sub_FFFFF807C1EBF800` equivalent — safe memory read with size+lock validation |
| `0xFFFFF807C1E19630` | `0x70` | ⚙️ | `DereferenceObject` | Decrements reference count (ObDereferenceObject equivalent) |
| `0xFFFFF807C1E18AA0` | `0x133` | ⚙️ | `UnicodeString_Init` | Initializes UNICODE_STRING from char array |
| `0xFFFFF807C1E16630` | `0x3E` | ⚙️ | `SpinLock_Acquire` | Acquires kernel spin lock |
| `0xFFFFF807C1E16670` | `0x4E` | ⚙️ | `SpinLock_Release` | Releases kernel spin lock |
| `0xFFFFF807C1E166C0` | `0x45` | ⚙️ | `FastMutex_Acquire` | Acquires FAST_MUTEX (IRQL ≤ APC_LEVEL) |
| `0xFFFFF807C1E16710` | `0x5A` | ⚙️ | `FastMutex_Release` | Releases FAST_MUTEX |
| `0xFFFFF807C1E16770` | `0x42` | ⚙️ | `ListEntry_Validate` | `FatalListEntryError` — linked list integrity check |
| `0xFFFFF807C1E16820` | `0x251` | ⚙️ | `WorkItem_Queue` | Queues a work item to system worker thread pool |
| `0xFFFFF807C1E2D180` | `0x5` | ⚙️ | `Align_Stub` | Alignment/padding stub |
| `0xFFFFF807C1E2D840` | `0x42` | ⚙️ | `StringHash_FNV` | FNV-1a or similar fast string hash |
| `0xFFFFF807C1E30570` | `0x21` | ⚙️ | `Memcpy_Small` | Small optimized memcpy (≤ 32 bytes, non-SIMD) |
| `0xFFFFF807C1E33040` | `0x5` | ⚙️ | `Pad_Stub` | Padding |

---

## Driver Init, IOCTL & Lifecycle

| Address | Size | Icon | Name (Reconstructed) | Description |
|---|---|---|---|---|
| `0xFFFFF807C1E21180` | `0x7A` | 🔌 | `IoCompletionRoutine` | IRP completion callback — called when async I/O finishes |
| `0xFFFFF807C1E211FC` | `0x74` | 🔌 | `IrpDispatch_Create` | IRP_MJ_CREATE handler — called when user-mode opens `\\.\EasyAntiCheat` |
| `0xFFFFF807C1E30600` | ~varies | 🔌 | `IrpDispatch_DevCtrl` | IRP_MJ_DEVICE_CONTROL handler — main IOCTL router |
| `0xFFFFF807C1E308C0` | `0x23A` | 🔌 | `IrpDispatch_Close` | IRP_MJ_CLOSE — device handle closed by user-mode |
| `0xFFFFF807C1E2A4E0` | `0xCF` | 🔌 | `IrpDispatch_Cleanup` | IRP_MJ_CLEANUP — final handle cleanup |
| `0xFFFFF807C1E50D40` | ~varies | 🧹 | `DriverUnload` | Driver unload handler — derefs objects, checks `0xBC44A31CA74B4AAF` canary, frees pool |
| `0xFFFFF807C1F16DE0` | ~varies | 🧹 | `FreePoolWrapper` | Pool free wrapper called by DriverUnload for object deallocation |
| `0xFFFFF807C1F201E0` | ~varies | 🧹 | `ObjectCleanup` | Custom object destructor called on allocated EAC state block |

---

## Scanning & Detection Functions

| Address | Size | Icon | Name (Reconstructed) | Description |
|---|---|---|---|---|
| `0xFFFFF807C1E226E0` | `0x31D` | 🔎 | `ECC_ScalarMult` | Used in signing; also used in challenge verification from server |
| `0xFFFFF807C1E3A4C0` | `0x11A` | 🔎 | `HashAlgo_Select` | Chooses hash algorithm for code region verification |
| `0xFFFFF807C1EBF800` | ~varies | 🔎 | `SafeStructRead` | Kernel probe + safe-read wrapper for scanning kernel structures |
| `0xFFFFF807C1E17CF0` | `0xF2` | 🔎 | `ModuleEnum_IterNext` | Advances module list iterator (LDR_DATA_TABLE_ENTRY walk) |
| `0xFFFFF807C1E17F10` | `0xF2` | 🔎 | `ModuleEnum_GetBase` | Returns base address field from current module entry |
| `0xFFFFF807C1E173E0` | `0xFB` | 🔎 | `ProcessEnum_IterNext` | Advances process list iterator via ActiveProcessLinks |
| `0xFFFFF807C1E16EF0` | `0xF0` | 🔎 | `DispatchTable_Check` | Checks MajorFunction[] pointers are within driver range |
| `0xFFFFF807C1E16FE0` | `0xF7` | 🔎 | `SSDT_Validate` | Validates SSDT entries point into ntoskrnl |
| `0xFFFFF807C1E18190` | `0x4E` | 🔎 | `VAD_WalkNext` | Advances to next VAD node in tree traversal |

---

## Global Data / Key Addresses

| Address | Size | Name | Description |
|---|---|---|---|
| `0xFFFFF807C2068E78` | 8 | `enc_ptr_slot_0` | Encrypted function pointer — PsGetCurrentProcess equivalent |
| `0xFFFFF807C2068E88` | 8 | `enc_ptr_slot_1` | Encrypted function pointer — packet serializer |
| `0xFFFFF807C2068EC8` | 8 | `enc_ptr_slot_2` | Encrypted function pointer — PsGetProcessSessionId |
| `0xFFFFF807C2068EE8` | 8 | `enc_ptr_slot_3` | Encrypted function pointer — KeQuerySystemTime |
| `0xFFFFF807C206A820` | 1 | `g_bInitialized` | Driver initialized flag (byte) |
| `0xFFFFF807C206A828` | 8 | `g_pStateBlock` | Pointer to main EAC state allocation (canary = `0xBC44A31CA74B4AAF`) |
| `0xFFFFF807C206A830` | 8 | `g_pWorkQueue` | Pointer to work queue object |
| `0xFFFFF807C206A838` | 4 | `g_WorkItem1Active` | Work item #1 queued flag |
| `0xFFFFF807C206A83C` | 4 | `g_WorkItem2Active` | Work item #2 queued flag |
| `0xFFFFF807C206AD10` | 8 | `g_pCallback1` | Kernel callback registration handle #1 |
| `0xFFFFF807C206AD18` | 4 | `g_Callback1Active` | Callback #1 active flag |
| `0xFFFFF807C206AD20` | 8 | `g_pCallback2` | Kernel callback registration handle #2 |
| `0xFFFFF807C206AD28` | 4 | `g_Callback2Active` | Callback #2 active flag |
| `0xFFFFF807C206AD30` | 8 | `g_pCallback3` | Kernel callback registration handle #3 |
| `0xFFFFF807C206AD38` | 4 | `g_Callback3Active` | Callback #3 active flag |
| `0xFFFFF807C1FFEE10` | ~512 | `aBin` | Binary data — encoded module name signature table #1 |
| `0xFFFFF807C1FFEDF0` | ~512 | `aBin_0` | Binary data — encoded module name signature table #2 |
| `0xFFFFF78000000014` | 4 | `KUSER_SHARED_DATA.TickCountLow` | Referenced directly by telemetry assembler |
| `0xFFFFF807C1F8BF80` | 8 | `qword_F8BF80` | Function pointer — memset equivalent (zeroing library function) |
| `0xFFFFF807C1F8BCC0` | ~varies | `sub_F8BCC0` | Memcpy equivalent (used in NTT polynomial operations) |

---

## Stats

| Metric | Value |
|---|---|
| Total identified functions | 200+ |
| Cryptographic functions | ~22 |
| Compression functions | ~18 |
| Telemetry/data collection | ~20 |
| Detection/scanning | ~12 |
| IOCTL/dispatch | ~8 |
| Infrastructure/utility | ~30+ |
| Functions that failed decompilation | ~15 (SIMD-heavy or padding stubs) |
| Binary load size | ~8 MB |
| Code section size | ~7 MB |
| Data section size | ~1 MB (string tables, signature data, global state) |

---

*← [Spoofer Detection](spoofer_detection.md) | [Back to README](README.md)*
