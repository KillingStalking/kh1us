# USA control-flow validation report

This report records an instruction-level validation pass against the two
supplied ELF files. Unlike the coarse byte-anchor mapper, this check compares
MIPS operation/register signatures and resolves every direct control-flow
target in the listed function extents.

## Inputs

| Field | JP | USA |
|---|---|---|
| ELF | `SLPS_251.05` | `SLUS_203.70` |
| SHA-1 | `9dabbf867a7ec2a030df99ba1ed969f2deef0488` | `8704cda65ca5e3f04202f0a50472401355335312` |
| Main VMA | `0x00100000` | `0x00100000` |

The validator rejects any input whose SHA-1 differs from these exact files.

## Aggregate result

<badge color="success">All listed checks matched</badge>

| Check | Result |
|---|---:|
| Function extents checked | 13 |
| Compared bytes | 1,952 |
| Equal bytes | 1,861 (95.34%) |
| MIPS instruction words | 488 |
| Matching operation/register signatures | 488 / 488 |
| Control-flow instructions | 61 / 61 |
| Direct branch/jump/call targets | 49 |
| Direct targets matching piecewise address maps | 49 / 49 |
| Unmapped or mismatched direct targets | 0 |

The 12 remaining control-flow instructions are indirect `jr` returns. Their
instruction positions and signatures also match.

## Function-level checks

Offsets are relative to the `main` section. Sizes are taken from the next
listed JP function symbol and correspond to the exact ranges checked.

| Function | JP offset | USA offset | Bytes equal | Instruction signatures | Control flow | Direct targets matched |
|---|---:|---:|---:|---:|---:|---:|
| `pppPoint` | `0x852E0` | `0x82B80` | 140/144 | 36/36 | 4/4 | 3/3 |
| `pppPointCon` | `0x85370` | `0x82C10` | 40/40 | 10/10 | 1/1 | — |
| `pppMove` | `0x85398` | `0x82C38` | 204/208 | 52/52 | 4/4 | 3/3 |
| `pppMoveCon` | `0x85468` | `0x82D08` | 40/40 | 10/10 | 1/1 | — |
| `pppAcceleCalc` | `0x85490` | `0x82D30` | 204/208 | 52/52 | 4/4 | 3/3 |
| `pppAcceleCon` | `0x85560` | `0x82E00` | 40/40 | 10/10 | 1/1 | — |
| `worldfile_getAbbr` | `0x11F40` | `0x11E80` | 35/40 | 10/10 | 1/1 | 1/1 |
| `worldfile_getNameNoSet` | `0x11F68` | `0x11EA8` | 127/136 | 34/34 | 6/6 | 5/5 |
| `worldfile_getNames` | `0x11FF0` | `0x11F30` | 184/224 | 56/56 | 11/11 | 10/10 |
| `worldfile_getBinImgName` | `0x120D0` | `0x12010` | 133/152 | 38/38 | 7/7 | 6/6 |
| `sprintf` | `0x14D8A0` | `0x14B388` | 140/144 | 36/36 | 2/2 | 1/1 |
| `strcat` | `0x14D930` | `0x14B418` | 298/300 | 75/75 | 10/10 | 9/9 |
| `strcpy` | `0x14DBA0` | `0x14B688` | 276/276 | 69/69 | 9/9 | 8/8 |

## Piecewise address translation

A single global delta is not valid. The 49 direct control-flow targets resolve
under three distinct address-map ranges:

| Target region | JP address range | JP-minus-USA delta | Direct targets |
|---|---|---:|---:|
| PPP code | `0x00185000–0x00185FFF` | `0x2760` | 9 |
| worldfile code | `0x00111000–0x00112FFF` | `0x00C0` | 6 |
| EE library | `0x0024D000–0x0024FFFF` | `0x2518` | 34 |

The worldfile functions are especially useful evidence: their internal game
code targets use the `0xC0` delta, while their calls into library functions
use the separate `0x2518` delta. For example, calls to JP `sprintf`,
`strcat`, and `strcpy` resolve to their USA counterparts under the library
delta. This independently confirms that address translation must be
piecewise and call-target-aware.

## Interpretation and limitations

This is a strong local validation of 13 function extents, not a full USA
decompilation. It does not validate data pointers, jump tables, GP-relative
loads/stores, every caller, exception paths, overlays, or unlisted functions.
The address ranges are deliberately narrow and derived from these observed
clusters. They must not be extrapolated to adjacent code without further
evidence.

The next step is to use these validated regions as anchors for a larger
function/call-graph matcher, then inspect GP-relative references and data
tables before generating any USA Splat configuration.
