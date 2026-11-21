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
| Raw GP-based instruction candidates in the full main image, JP | 842 |
| Raw GP-based instruction candidates in the full main image, USA | 771 |
| Paired GP-opcode patterns inside exact runs | 373 |

All **373 paired opcode patterns** preserve the same bytes and immediate, so
interpreting those words as instructions yields a computed-address delta of
`0x720`. This arithmetic observation alone does not establish that the words
are executed as instructions.

## Splat classification of the 373 paired patterns

| JP Splat subsegment | Type | Patterns |
|---|---|---:|
| `0x16F2E0–0x1B3A20` | `data` | 75 |
| `0x1DED10–0x201010` | `data` | 141 |
| `0x201078–0x25EC00` | `data` | 150 |
| `0x2DE5F0–0x31F8C8` | `data` | 7 |
| **Total** | | **373** |

The earlier arithmetic classification showed 44 patterns whose computed JP
address fell in the first 32 bytes of JP BSS while the corresponding USA
address fell immediately before USA BSS. However, all 373 source locations
are inside JP Splat subsegments explicitly typed `data`; therefore these 44
are data words that happen to decode like GP-based operations, not evidence
of actual variables or runtime memory accesses.

## Interpretation

The result does **not** yet validate GP-relative code references. All 373
paired patterns are in JP Splat `data` subsegments, so the current code-level
confirmed-reference count is zero. The scan found 842 JP and 771 USA raw
opcode candidates in the complete main sections; most cannot be interpreted
without first separating code from data.

The ELF `main` section contains both code and data. Raw opcode patterns can
occur in data, and exact byte anchors do not establish function boundaries.
The remaining work is to:

1. scan only JP Splat `c`, `asm`, and `hasm` subsegments for GP-based operations;
2. pair code candidates with USA using surrounding instruction/control-flow anchors;
3. inspect unmatched GP operations, especially changed immediates;
4. recover GP-relative data objects from code references and initialization;
5. validate startup initialization, callers, and all GP-relative references
   before emitting USA linker symbols or a USA Splat configuration.

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
