# Kingdom Hearts USA ELF audit

## Inputs and derived image checksums

| Build | File | Size | ELF SHA-1 |
|---|---|---:|---|
| Original Japanese | `SLPS_251.05` | 3,778,176 | `9dabbf867a7ec2a030df99ba1ed969f2deef0488` |
| USA | `SLUS_203.70` | 3,776,580 | `8704cda65ca5e3f04202f0a50472401355335312` |

Both are ELF32 little-endian MIPS executables with entry point `0x00100008`.
Both contain 34 DVP overlay-table records.

The JP raw image produced with `llvm-objcopy -O binary --gap-fill=0x00 -R .reginfo`
has SHA-1 `cb85dbab6c05667ed11d94e94abfa079baaf12c2`, exactly matching the
repository's existing JP checksum. The same extraction procedure produces
USA raw-image SHA-1 `1985db8cd8154990d6a605b7b7ac5e138d8d48bf`.
This confirms the raw-image extraction procedure against the known JP target.

## Main image metadata

| Field | JP | USA |
|---|---:|---:|
| Main VMA | `0x00100000` | `0x00100000` |
| Main file size | 3,726,080 (`0x38DB00`) | 3,724,256 (`0x38D3E0`) |
| GP from `.reginfo` | `0x0048DB00` | `0x0048D3E0` |
| BSS address | `0x0048DB00` | `0x0048D400` |
| BSS size | 1,971,456 (`0x1E1500`) | 1,957,504 (`0x1DFA80`) |

The USA GP and BSS values differ from JP. This is one reason the JP YAML
cannot safely be reused for USA by changing only the executable name.

## Symbol and relocation metadata

Both retail ELF files contain 42 section headers, but neither contains an
`SHT_REL` or `SHT_RELA` section, nor a conventional `.symtab` or
`.dynsym` section. The non-overlay sections are limited to the main image,
`.bss`, `.reginfo`, the empty `.mdebug.eabi64` marker, and the DVP
overlay metadata/string tables.

Consequently, there is no retained relocation table or full ELF function
symbol table to drive an automatic USA relink. JP symbol maps and Splat
boundaries are external project metadata; each proposed USA mapping must be
validated from instruction bytes, control-flow targets, and data references.
The GP and BSS values differ, but the subsequent code-only audit found no
direct `$gp`-based memory operations in the JP code subsegments; the apparent
opcode matches are data patterns. The GP delta alone is therefore not a
validated blocker or a usable global-data relocation rule. Static data
pointers and other address-construction sequences still require analysis.

## Overlay extraction method

The overlay table provides an EE load address and a VU address. The matching
`.DVP.overlay.*` section supplies the overlay size. In these files, the
marker section bytes are uniform fill values rather than the program bytes.
The candidate overlay bytes are therefore read from the `main` load image at:

```text
file_offset = main.file_offset + overlay.ee_address - main.address
payload_size = matching .DVP.overlay section size
```

Every extracted range was inside the main image, and every size was divisible
by 8 bytes (the size of a VU instruction pair).

## Results

- 22 of 34 extracted overlay payloads are byte-identical.
- 12 payloads differ.
- The 22 exact matches permit offset-for-offset correspondence inside those
  particular payloads only.
- The EE load-address delta is constant for overlays 0–15: JP is
  `0x7C0` bytes above USA.
- The remaining exact overlays have several different deltas; do not apply a
  single global address adjustment.

### Exact payload matches

| Overlay | JP EE address | USA EE address | JP − USA | VU address | Size |
|---:|---:|---:|---:|---:|---:|
| 0 | `0x4800A8` | `0x47F8E8` | `0x7C0` | `0x0000` | 2048 |
| 1 | `0x4808B0` | `0x4800F0` | `0x7C0` | `0x0800` | 1152 |
| 2 | `0x480D38` | `0x480578` | `0x7C0` | `0x0000` | 2048 |
| 3 | `0x481540` | `0x480D80` | `0x7C0` | `0x0800` | 896 |
| 4 | `0x4818C8` | `0x481108` | `0x7C0` | `0x0000` | 2048 |
| 5 | `0x4820D0` | `0x481910` | `0x7C0` | `0x0800` | 1256 |
| 6 | `0x4825C8` | `0x481E08` | `0x7C0` | `0x0000` | 2048 |
| 7 | `0x482DD0` | `0x482610` | `0x7C0` | `0x0800` | 1696 |
| 10 | `0x484038` | `0x483878` | `0x7C0` | `0x0000` | 576 |
| 11 | `0x484288` | `0x483AC8` | `0x7C0` | `0x0000` | 2048 |
| 12 | `0x484A90` | `0x4842D0` | `0x7C0` | `0x0800` | 1400 |
| 13 | `0x485018` | `0x484858` | `0x7C0` | `0x0000` | 2048 |
| 14 | `0x485820` | `0x485060` | `0x7C0` | `0x0800` | 1256 |
| 15 | `0x4864C0` | `0x485D00` | `0x7C0` | `0x0000` | 840 |
| 16 | `0x26F318` | `0x26D158` | `0x21C0` | `0x0000` | 80 |
| 17 | `0x26F420` | `0x26D2F0` | `0x2130` | `0x0000` | 1120 |
| 23 | `0x2715C8` | `0x26F498` | `0x2130` | `0x0800` | 1968 |
| 25 | `0x2725A8` | `0x270478` | `0x2130` | `0x0800` | 2048 |
| 26 | `0x272DB0` | `0x270C80` | `0x2130` | `0x1000` | 160 |
| 30 | `0x2740C0` | `0x271FB0` | `0x2110` | `0x0000` | 832 |
| 31 | `0x274420` | `0x272310` | `0x2110` | `0x0000` | 944 |
| 33 | `0x274D88` | `0x272C78` | `0x2110` | `0x0000` | 904 |

### Differing payloads

The similarity value below is the sum of non-overlapping matching byte blocks
of at least 16 bytes divided by the larger payload size. It is a lower bound,
not a semantic equivalence score.

| Overlay | JP size | USA size | Matching-byte lower bound |
|---:|---:|---:|---:|
| 8 | 2048 | 2048 | 91.89% |
| 9 | 944 | 936 | 99.15% |
| 18 | 1000 | 1000 | 99.60% |
| 19 | 1112 | 1112 | 99.73% |
| 20 | 1464 | 1464 | 99.80% |
| 21 | 1672 | 1672 | 99.82% |
| 22 | 2048 | 2048 | 99.85% |
| 24 | 2048 | 2048 | 99.85% |
| 27 | 2048 | 2048 | 98.63% |
| 28 | 2048 | 2048 | 98.83% |
| 29 | 544 | 568 | 95.60% |
| 32 | 1104 | 1104 | 99.73% |

### VU instruction-pair comparison

VU instructions are 8-byte pairs. For equal-sized overlays, pairs were compared
as two 32-bit words. The comparator also identifies branch-only changes where
the opcode and upper word are unchanged and only the signed 11-bit branch
displacement differs.

| Overlay | Exact pairs | Branch-displacement-only changes | Other changed pairs |
|---:|---:|---:|---:|
| 8 | 198 / 256 | 22 | 36 |
| 18 | 123 / 125 | 0 | 2 |
| 19 | 138 / 139 | 0 | 1 |
| 20 | 182 / 183 | 0 | 1 |
| 21 | 208 / 209 | 0 | 1 |
| 22 | 255 / 256 | 0 | 1 |
| 24 | 255 / 256 | 0 | 1 |
| 27 | 236 / 256 | 1 | 19 |
| 32 | 137 / 138 | 0 | 1 |

Three size/placement differences are alignment changes rather than broad code
rewrites:

- Overlay 9: the USA payload is one 8-byte pair shorter at the beginning; the
  remaining 117 pairs match exactly.
- Overlay 28: 253 pairs (2024 bytes) match after a 3-pair / 24-byte USA prefix.
- Overlay 29: 64 pairs (512 bytes) match after a 3-pair / 24-byte USA prefix;
  one later pair differs and the final three pairs match.

Overlay 8 contains many branch displacement changes. Those must be interpreted
as control-flow changes in the VU program, not blindly patched with a global
address delta. Overlay 27 also has a changed tail region and requires full
instruction-flow review.

## Main-image byte comparison

Comparing the two main sections at the same relative file offsets yields
1,681,944 equal bytes out of 3,724,256 (45.16%). A unique 16-byte block matcher
also finds 39,667 unique block correspondences, grouped into 2,139 contiguous
candidate ranges of at least 64 bytes (393,712 bytes total).

These are candidate byte correspondences only. The matcher does not distinguish
code from data, and a matching range may contain instructions, constants, or
other embedded data. Do not treat these ranges as function matches without
validating the relevant addresses against the JP split map and instruction
boundaries.

## Limits and next work

The current tools can inspect ELF metadata, extract overlay payloads, compare
VU pairs, and show coarse main-image block correspondences. They do not yet
provide a full VU semantic decoder, a complete MIPS R5900 function matcher,
relocation resolution, or a verified USA function map.

The repository's current decompilation configuration has JP and Final Mix
targets, but no USA target. A USA config must not be generated by copying the
JP YAML and changing only the basename: the main image layout, GP value, BSS
size, symbols, checksums, split boundaries, and undefined-symbol maps need
independent validation against the USA ELF.

Next implementation milestone: use the JP split map to classify main-image
matches as code/data, review the changed VU pairs and branch targets, then
generate and validate USA-specific split boundaries. Only after that should a
USA Splat configuration be enabled.

## JP split-map inventory and USA mapping tool

The JP `config/kh.jp.yaml` main segment contains 626 explicitly declared
subsegment starts across code, assembly, data, and rodata. A new read-only
helper, `tools/elf/map_main_subsegments.py`, parses those declarations and
searches the JP/USA main images for unique fixed-size byte anchors near each
JP subsegment start.

The helper reports candidate USA start addresses only when the matching
anchors agree on a common address delta. It also preserves the JP segment
type/name and lists each anchor used for the candidate. Results are classified
as unmatched, weak single-anchor, ambiguous, or candidate. No candidate is
automatically written into a USA YAML.

This advances the split-map workflow, but does not yet establish a validated
USA split map: the tool must be run against the actual JP and USA ELF files,
then candidate boundaries must be checked against MIPS instruction boundaries,
relocations, function control flow, and data/rodata references. The mapper's
unit tests have been added to the existing ELF helper test suite; no passing
CI result is claimed for this commit.
## Main-image split mapping

The first full JP-to-USA candidate mapping run is documented separately in
[`USA_MAIN_MAP.md`](USA_MAIN_MAP.md). It processes all 626 JP main-image
subsegment starts and reports candidate counts plus ordering anomalies. These
are still address candidates, not verified USA split boundaries.

The new `tools/elf/map_symbols.py` helper also maps the existing JP
`type:func` symbol entries to provisional USA address candidates. Its output
is bounded by the next greater JP function symbol and a configurable maximum
scan size. A manually checked six-function PPP cluster is documented in
`USA_MAIN_MAP.md`; later functions in that cluster diverge and are not mapped
by simple delta propagation.

The first full pass over the 532 JP game function symbols is documented in
[`USA_SYMBOL_MAP.md`](USA_SYMBOL_MAP.md). It yields 72 strong and 24 two-anchor
candidates; ordering conflicts and unmatched symbols remain, so the candidate
list is not yet a USA symbol map.

## Existing JP data-symbol inventory

The JP game symbol file contains 553 function symbols and 21 non-function
entries (16 `s32`, four `char`, and one `asciz`). Of those 21 data entries,
15 fall inside the JP `main` load image and six fall inside JP `.bss`.

The six JP BSS entries are `cdvd_Descriptor` at `0x004EC948`,
`ppvUserStopPartF` at `0x0061095C`, `ppvCurPrimpLen` at
`0x00610968`, `ppvPrimpLen` at `0x00610970`, `ppvEmptyLoop` at
`0x00610974`, and `ppvVertex` at `0x00610978`. Their USA addresses have
not been established.

The BSS start moves from `0x0048DB00` (JP) to `0x0048D400` (USA), a
`-0x700` difference. The GP moves from `0x0048DB00` to `0x0048D3E0`, a
different `-0x720` difference. The BSS size changes from `0x1E1500` to
`0x1DFA80` (a reduction of `0x1A80`). These distinct changes rule out
blindly applying one address delta to all data symbols.

Several JP initialized data symbols describe PS2-specific HDD/PFS paths and
disc identifiers (for example the disk manager's game-code and image-name
strings). Those values need USA-specific validation for a USA PS2 build and
will need a different storage design for an iOS runtime.


## Absolute data-reference mapping

A follow-up scan of the JP Splat code span found 1,202 address-materialization
sequences (`LUI` plus `ADDIU/ORI`) followed by a memory operation. The
historical scan mapped 925 into USA using two non-overlapping unique 16-byte
anchors and matching opcode/register signatures. Its USA code/data
classification reused the JP Splat code boundary, however, and is now marked
provisional: the USA boundary has not been validated. The corrected scanner
searches the complete USA main image and labels USA main-image targets as
unclassified until a USA-specific split map exists. The historical category
counts below the old report must not be used as confirmed USA code/data totals.

The target-address deltas vary across 4 KiB pages in both main data and BSS.
For example, the historical main-data page summary shows dominant deltas from
`0x2110` down to `0x03E0`, while BSS pages include `0x0700`, `0x0580`,
`0xE5F0`, `0xB5F0`, `0x1580`, `0x13B0`, and `0x1750`. These
patterns suggest piecewise address movement, but the main-data summary must
be regenerated with the corrected USA classification. The BSS observations
remain ELF-range based. The full report is
[USA_STATIC_REF_AUDIT.md](USA_STATIC_REF_AUDIT.md), and the reusable scanner is
[audit_static_refs.py](audit_static_refs.py).

These remain static pattern-based candidates, not a complete pointer map or
proof of global-object identity. They provide anchors for the next data-block
and global-structure reconstruction pass.

## Main-image function control-flow validation

A separate instruction-level validation pass now checks 13 mapped function
extents across the PPP, worldfile, and EE library regions. It compared 1,952
bytes and 488 MIPS instruction words: all 488 operation/register signatures
matched, all 61 control-flow instructions matched in position and kind, and
all 49 direct branch/jump/call targets resolved through three piecewise
address maps. The 12 remaining control-flow instructions are matching indirect
returns.

See [USA_CONTROL_FLOW.md](USA_CONTROL_FLOW.md) for function-level details and
the reproducible, SHA-1-pinned
[`validate_control_flow.py`](validate_control_flow.py) tool. This is
strong evidence for the listed clusters only; GP-relative data references,
jump tables, all callers, the remaining main-image functions, and the changed
VU overlays are still open validation work.

The initial main-subsegment and function-symbol candidate counts are marked
provisional in their respective reports because the anchor index was corrected
to include 4-byte-aligned positions. The revised full scans still need to be
run before any USA split configuration is generated.


## GP-opcode candidate audit

The [GP opcode audit report](USA_GP_AUDIT.md) records 373 paired opcode-shaped
patterns inside long byte-identical main-image runs. Cross-checking all 842
JP raw candidates against the 626-entry JP Splat main map shows that 840 are
in `data` and 2 are in `rodata`; none is in a `c`, `asm`, or `hasm` subsegment.
All 373 paired patterns are in `data`. They are therefore not confirmed
executable GP-relative references. The computed `0x720` delta and the 32-byte
GP/BSS boundary observation are arithmetic properties of data words, not
proof of runtime memory accesses.

The next required pass is to search code for GP values copied into other
registers or constructed through other instruction sequences, then validate
those references using instruction flow and callers. No direct `$gp`-based
memory operation has yet been confirmed in JP code by this scan.
