> **Methodology correction (2026-11-22):** The original run below used the JP Splat code/data boundary to classify USA targets and limited the USA anchor index to the same JP-relative code span. That assumption is not validated. The scanner has since been corrected to search the entire USA `main` image and to label USA main-image targets as `main_image_unclassified` until a USA-specific code/data split is established. The aggregate USA code/data classifications and counts in the historical run below must therefore be treated as provisional and superseded by a fresh run. BSS membership remains ELF-defined. The corrected run has not yet been produced.

# USA static data-reference audit

This report documents a conservative instruction-pattern pass over the pinned
retail JP and USA ELF pair. It is the next step after the direct GP-opcode
audit: the JP Splat map shows that the code region contains no direct
`$gp`-relative load/store instructions, so this pass searches for absolute
addresses materialized with `LUI` plus `ADDIU` or `ORI`.

## Inputs and scope

| Field | JP | USA |
|---|---|---|
| ELF | `SLPS_251.05` | `SLUS_203.70` |
| SHA-1 | `9dabbf867a7ec2a030df99ba1ed969f2deef0488` | `8704cda65ca5e3f04202f0a50472401355335312` |
| Main VMA | `0x00100000` | `0x00100000` |
| GP | `0x0048DB00` | `0x0048D3E0` |
| BSS | `0x0048DB00–0x0066F000` | `0x0048D400–0x0066CE80` |

The JP Splat `main` segment declares one contiguous code span:
`main+0x000000–main+0x16F2E0`. The scanner uses only subsegments typed
`c`, `asm`, or `hasm`, and merges adjacent code subsegments. The remainder
of `main` is not scanned as instructions.

## Matching method

1. Decode `LUI rt, imm` followed within four instructions by
   `ADDIU rt, rt, imm` or `ORI rt, rt, imm`.
2. Reject the sequence if an intervening instruction overwrites `rt`.
3. Require a subsequent load/store-style instruction to use `rt` as its base
   register, without an intervening overwrite.
4. Map the JP instruction sequence into USA using at least two unique,
   non-overlapping 16-byte anchors that independently agree on the same
   code-address delta.
5. Confirm the opcode/register signatures of the LUI, low-immediate
   instruction, and memory operation at the mapped USA location.
6. Reconstruct both absolute target addresses. Classify JP targets using the
   JP Splat boundary; classify USA targets only as main-image, BSS, or outside
   until a USA-specific code/data split has been validated.

This is a conservative pattern matcher, not a full MIPS data-flow analysis.

## Aggregate results

| Measurement | Result |
|---|---:|
| JP address-materialization sequences with a following memory use | 1,202 |
| Sequences mapped into USA with two independent anchors | 925 |
| Targets in JP main data, also inside USA main image | 465 (historical; provisional) |
| Targets in JP BSS, also BSS in USA | 301 (historical; provisional) |
| Targets outside main/BSS in both builds | 157 (historical; provisional) |
| Targets classified as code in both builds | 2 (historical; provisional) |
| Cross-region target classifications | 0 (historical; provisional) |

The follow-up quality checks found 175 unique main-data address pairs and
169 unique BSS address pairs. Two adjacent-pair ordering anomalies remain in
each region and are retained for manual review rather than silently discarded.
A memory-access alignment check also flags one BSS candidate: JP code offset
`0x1FD94` forms base `0x004EFFFF` and then performs a word load at effective
address `0x004EC947`, which is not 4-byte aligned. Treat that candidate as
suspicious; it is not evidence for a valid global pointer. The other 300 BSS
candidates pass the alignment checks implemented for their recognized
load/store opcodes.

The alignment checker reports three failures in the complete mapped set,
not just the one BSS case:

| JP code offset | JP reconstructed base | Memory op + immediate | Effective address | Classification |
|---|---:|---|---:|---|
| `0x1FD94` | `0x004EFFFF` | `LW -0x36B8` | `0x004EC947` | BSS |
| `0x647DC` | `0xFDFFFFFF` | `LW 0` | `0xFDFFFFFF` | outside main/BSS |
| `0x7479C` | `0x40000075` | `LW +0x0164` | `0x400001D9` | outside main/BSS |

The latter two are not evidence for main-data or BSS objects; they are
unclassified address patterns and may represent MMIO, encoded constants, or
false positives from the deliberately lightweight instruction matcher. The
first BSS candidate is also suspicious because its reconstructed word address
is not 4-byte aligned. The remaining 300 BSS candidates pass the implemented
alignment checks. The checker does not claim to validate all PS2-specific
memory semantics.

The historical 766 main-data/BSS candidates are useful leads, but their
USA-side region breakdown has not yet been regenerated with the corrected
scanner. They do not
prove every pointer is a standalone global variable: some may be structure
bases, arrays, tables, or object-relative addresses.

### Byte-content corroboration

The 175 unique main-data target pairs were also checked directly against the
bytes at each JP and USA target. Every pair has a complete 64-byte window
available in both main images.

| Window from target | Exact byte-identical pairs | Mean byte equality |
|---|---:|---:|
| 16 bytes | 161 / 175 | 98.2% |
| 32 bytes | 152 / 175 | 97.1% |
| 64 bytes | 136 / 175 | 95.3% |

This independent content check supports many of the pointer correspondences.
The 14 pairs whose first 16 bytes differ are retained as candidates because
some referenced tables/structures may legitimately contain version-specific
pointers or data. They need object-level review rather than automatic rejection.

## Main-data address deltas

The JP-minus-USA pointer delta is not constant across the main data region.
The following 4 KiB pages had at least three mapped references:

| JP page | References | Dominant JP − USA delta |
|---|---:|---:|
| `0x002A0000` | 6 | `0x2110` |
| `0x002B8000` | 47 | `0x2110` (34), `0x2108` (13) |
| `0x002C1000` | 50 | `0x2110` |
| `0x002DE000` | 11 | `0x2120` |
| `0x0035E000` | 17 | `0x20E0` |
| `0x0036F000` | 14 | `0x2100` |
| `0x00375000` | 18 | `0x1FC8` (11), `0x1FD8` (4) |
| `0x00385000` | 59 | `0x1FD0` |
| `0x003ED000` | 44 | `0x05C0` (40) |
| `0x00420000` | 10 | `0x03E0` |
| `0x0044E000` | 12 | `0x03F0` |
| `0x00463000` | 13 | `0x0580` |
| `0x00464000` | 7 | `0x0760` |

The changing deltas are consistent with multiple independently shifted data
blocks. Do not apply one main-data delta to the entire executable.

## BSS address deltas

The BSS mapping is also piecewise and substantially less uniform than a
single `0x700` shift:

| JP BSS page | References | Dominant JP − USA delta |
|---|---:|---:|
| `0x0048DB00` | 8 | `0x0700` |
| `0x004D1B00` | 17 | `0x0580` |
| `0x0052BB00` | 10 | `0xE5F0` |
| `0x00531B00` | 8 | `0xE5F0` |
| `0x00553B00` | 5 | `0xB5F0` |
| `0x00556B00` | 11 | `0x1580` |
| `0x0060FB00` | 52 | `0x1580` |
| `0x0062CB00` | 11 | `0x1580` |
| `0x0063CB00` | 29 | mixed: `0x1548` (15), `0x1570` (8) |
| `0x0063FB00` | 5 | `0x13B0` |
| `0x00641B00` | 18 | `0x13B0` |
| `0x0064AB00` | 5 | `0x1750` |
| `0x00662B00` | 10 | `0x21A0` (9) |
| `0x00667B00` | 5 | `0x2180` |

This independently confirms that the BSS start delta alone cannot be used to
translate all BSS references. The USA layout contains multiple moved or
reshaped regions.

## Interpretation and next steps

The direct GP-opcode audit and this pass now fit together:

- The direct `$gp` scan finds no such base-register accesses in JP Splat code.
- The code does contain many address-materialization patterns using absolute
  addresses.
- 925 candidate instruction sequences can be mapped into USA with two
  independent local anchors.
- The resulting main-data and BSS target deltas vary by region.

Next, use these reference pairs to recover candidate data blocks and global
structures, then validate each block with reads/writes, neighboring pointers,
string references, and callers. Only after that should data symbols and
segment boundaries be emitted into a USA Splat/linker configuration.

## Reproduction

```sh
python tools/elf/audit_static_refs.py \
  SLPS_251.05 SLUS_203.70 config/kh.jp.yaml \
  -o usa-static-reference-audit.json
```

The JSON contains every mapped sequence, its JP/USA code offsets, reconstructed
target addresses, target classes, per-page delta summaries, alignment warnings,
and unique-address ordering checks. The ELF
SHA-1 values are pinned so unrelated binaries cannot silently reuse this
report.
