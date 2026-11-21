# USA GP-opcode candidate audit

This report is a conservative opcode-pattern audit of the pinned retail JP
and USA ELF executables. It scans MIPS/R5900 `ADDIU` and load/store encodings
whose `rs` field equals `$gp`, then pairs byte-identical patterns inside long
unique-anchor runs. **These patterns are not automatically executable
instructions or confirmed GP-relative references.** The ELF `main` section
contains both code and data, so Splat classification is essential.

## Inputs and global-pointer metadata

| Field | JP | USA |
|---|---:|---:|
| ELF | `SLPS_251.05` | `SLUS_203.70` |
| SHA-1 | `9dabbf867a7ec2a030df99ba1ed969f2deef0488` | `8704cda65ca5e3f04202f0a50472401355335312` |
| `$gp` | `0x0048DB00` | `0x0048D3E0` |
| `.bss` start | `0x0048DB00` | `0x0048D400` |
| `.bss` size | `0x1E1500` | `0x1DFA80` |

The GP delta is `0x720` (1,824 bytes), while the BSS-start delta is
`0x700` (1,792 bytes). The USA GP is therefore 32 bytes before the USA BSS
start; the JP GP equals the JP BSS start.

## Exact-anchor coverage and Splat classification

| Measurement | Result |
|---|---:|
| Unique 16-byte anchor pairs (4-byte index alignment) | 207,994 |
| Long contiguous exact runs (at least 64 bytes) | 3,296 |
| Bytes covered by those runs | 458,564 |
| Raw GP-opcode candidates in the full main image, JP | 842 |
| Raw GP-opcode candidates in the full main image, USA | 771 |
| Paired GP-opcode patterns inside exact runs | 373 |

All **373 paired opcode patterns** preserve the same bytes and immediate, so
interpreting those words as instructions yields a computed-address delta of
`0x720`. This arithmetic observation alone does not establish that the words
are executed as instructions.

## Splat classification of all 842 JP opcode candidates

A second pass classified every JP raw candidate, not just the 373 paired
patterns. The 626-entry JP main Splat map places all 842 candidate words in
non-code subsegments:

| JP Splat type | Raw opcode candidates |
|---|---:|
| `data` | 840 |
| `rodata` | 2 |
| `c` | 0 |
| `asm` | 0 |
| `hasm` | 0 |
| **Total** | **842** |

Thus this scanner found **zero direct `$gp`-based ADDIU/load/store opcode
candidates inside JP subsegments classified as code**. A separate GPR-field
inspection of the 458 code subsegments found:
- one R-format write to register 28 at main offset `0x5C`, which is the
  startup `move $gp, $a0` initialization;
- eight R5900 `LQ`/`SQ` operations that save or restore register 28 in
  stack/context frames;
- zero other R-format uses of register 28.

The entry stub computes `0x0048DB00` in `$a0` and moves it to `$gp` at
VMA `0x0010005C`. This confirms the register is initialized, but the
code-segment scan does not find it used as a memory base. The LQ/SQ hits are
register preservation, not global-pointer-relative accesses.

 This does not prove
the executable never accesses globals: it does not detect a GP value copied
to another register, address formation through other instruction sequences,
or code outside the JP Splat boundaries. It does show that the apparent
373-reference match set was entirely data-pattern noise.

## Splat classification of the 373 paired patterns

| JP Splat subsegment | Type | Patterns |
|---|---|---:|
| `0x16F2E0–0x1B3A20` | `data` | 75 |
| `0x1DED10–0x201010` | `data` | 141 |
| `0x201078–0x25EC00` | `data` | 150 |
| `0x2DE5F0–0x31F8C8` | `data` | 7 |
| **Total** | | **373** |

The earlier arithmetic classification showed 44 data patterns whose
decoded JP address fell in the first 32 bytes of JP BSS while the corresponding
USA address fell immediately before USA BSS. Since the source words are
explicitly typed `data`, this is not evidence of actual variables or runtime
memory accesses.

## Interpretation

The result does **not** yet validate GP-relative code references. All 842 JP
raw opcode candidates fall in Splat `data` or `rodata` subsegments, and none
falls in a `c`, `asm`, or `hasm` subsegment. The 373 paired patterns are all
in `data`. This strongly indicates that the direct `$gp` opcode scan is
finding data words rather than actual code references. A separate scan is
needed for GP copied into another register or formed through other sequences.

The ELF `main` section contains both code and data. Raw opcode patterns can
occur in data, and exact byte anchors do not establish function boundaries.
The remaining work is to:

1. inspect whether the PS2 compiler uses a nonstandard global-base register or copies `$gp` before memory access;
2. search code subsegments for GP-derived register values and address-construction sequences;
3. use control-flow and function boundaries to reject data-pattern false positives;
4. recover global-data references and initializers from confirmed code;
5. validate startup initialization and callers before emitting USA linker symbols or a USA Splat configuration.

## Reproduction

```sh
python tools/elf/audit_gp_refs.py \
  SLPS_251.05 SLUS_203.70 --jp-yaml config/kh.jp.yaml \
  -o usa-gp-opcode-audit.json
```

The tool pins both input SHA-1 values and refuses other executables. With
`--jp-yaml`, it also classifies every paired JP location by its Splat
subsegment type. The JSON includes the candidate addresses, opcode-shaped
word fields, computed values, and exact-anchor run size.
