# USA main-image split-map candidate report

This report records a first full run of the conservative JP-to-USA main-image
subsegment mapper against the two local ELF inputs used for this audit.

## Inputs

| Field | JP | USA |
|---|---:|---:|
| ELF | `SLPS_251.05` | `SLUS_203.70` |
| SHA-1 | `9dabbf867a7ec2a030df99ba1ed969f2deef0488` | `8704cda65ca5e3f04202f0a50472401355335312` |
| Main image size | `0x38DB00` | `0x38D3E0` |
| Main image VMA | `0x00100000` | `0x00100000` |

The SHA-1 values match the previously recorded audit values. The JP split map
contains 626 declared main-image subsegment starts.

## Mapper settings and result

- Anchor size: 16 bytes
- Anchor step: 16 bytes
- Search window: `0x1000` bytes from each JP subsegment start, clipped to
  that subsegment's end
- An anchor is eligible only when its 16-byte block occurs exactly once in
  each complete main image and contains at least four distinct byte values.
- A strong candidate requires at least three independent anchors voting for
  the same JP-to-USA offset delta.
- A two-anchor result is reported as a candidate, not as strong.

| Status | Count |
|---|---:|
| Strong candidate | 164 |
| Candidate (two anchors) | 33 |
| Candidate out of USA main-image range | 2 |
| Weak single-anchor result | 89 |
| Ambiguous top vote | 7 |
| Unmatched | 331 |
| **Total** | **626** |

The 197 in-range candidates (164 strong plus 33 two-anchor candidates) produce
19 adjacent ordering anomalies: a later JP split boundary maps to an equal or
lower USA offset than the preceding candidate boundary. Nine of these
anomalies occur among the 164 strong candidates alone.

Frequent candidate deltas include `0x31A0` (16 subsegments), `0x2200`
(11), `0x7C0` (9), `0x20D0` (7), and `0x7A0` (7). This confirms that
there is no single global JP-to-USA address offset for the main image.

## Interpretation and next validation

This is a useful candidate inventory, not a USA split map. Even a strong
candidate means only that multiple unique byte anchors near the JP boundary
agree on one offset delta. It does not prove that the candidate address is a
function entry, that code and data classifications agree, or that relocations
and branch targets remain valid.

The ordering anomalies demonstrate why candidate boundaries must not be
copied automatically into `config/kh.usa.yaml`. Next validation must classify
the candidate ranges against MIPS instruction boundaries and the existing JP
symbol/split information, then inspect GP-relative references, relocation
sites, and control-flow targets. Only validated regions should be promoted to
USA split boundaries.

## Candidate counts by JP segment type

The same run, grouped by the segment types already declared in the JP YAML:

| JP segment type | Total | Strong | Two-anchor candidate | Weak | Ambiguous | Out of range | Unmatched |
|---|---:|---:|---:|---:|---:|---:|---:|
| `c` | 279 | 68 | 18 | 44 | 5 | 1 | 143 |
| `asm` | 178 | 62 | 13 | 27 | 2 | 0 | 74 |
| `hasm` | 1 | 0 | 0 | 0 | 0 | 0 | 1 |
| `data` | 37 | 10 | 0 | 4 | 0 | 1 | 22 |
| `.data` | 11 | 0 | 1 | 2 | 0 | 0 | 8 |
| `.rodata` | 49 | 9 | 0 | 8 | 0 | 0 | 32 |
| `rodata` | 71 | 15 | 1 | 4 | 0 | 0 | 51 |

Of the 164 strong candidates, 130 originate from JP `c` or `asm`
segments and 34 from JP data/rodata segments. This type grouping is inherited
from the JP split map; it does not independently prove the USA classification.

## Manual spot-checks of candidate code regions

The first mapped assembly region at JP main offset `0x1870` has a strong
candidate at USA main offset `0x1960` (JP-minus-USA delta `-0xF0`).
Twenty-six unique 16-byte anchors in the first `0x1000` bytes vote for this
same delta. A byte comparison of the first `0x200` bytes gives 498/512 equal
bytes (97.27%). The differing words include address/immediate values, and
the MIPS disassembly at the two candidate starts shows the same initial
instruction sequence and control-flow shape, with call targets and constants
that differ between builds.

A second spot-check, JP `main+0x852E0` to USA `main+0x82B80`, has four
anchors and 180/184 equal bytes (97.83%) across the JP segment extent
(`0xB8` bytes). These spot-checks support the mapper's usefulness for
prioritizing code regions, but they do not validate all 626 boundaries or
establish symbol identity. Branch destinations, pointer tables, and the
following split boundaries still require independent review.

## JP named-function cluster spot-check

The JP function symbol table provides an additional check around the strong
candidate at JP `main+0x852E0` → USA `main+0x82B80` (delta
`0x2760`). Applying that same delta to the next consecutive JP symbols gives
the following byte comparisons over each function's extent as bounded by the
next listed JP function symbol:

| JP function | JP offset | Candidate USA offset | Compared bytes equal |
|---|---:|---:|---:|
| `pppPoint` | `0x852E0` | `0x82B80` | 140 / 144 (97.2%) |
| `pppPointCon` | `0x85370` | `0x82C10` | 40 / 40 (100%) |
| `pppMove` | `0x85398` | `0x82C38` | 204 / 208 (98.1%) |
| `pppMoveCon` | `0x85468` | `0x82D08` | 40 / 40 (100%) |
| `pppAcceleCalc` | `0x85490` | `0x82D30` | 204 / 208 (98.1%) |
| `pppAcceleCon` | `0x85560` | `0x82E00` | 40 / 40 (100%) |

The next listed functions do not maintain this high byte similarity under the
same delta: `pppAngleCalc` is 22/144 bytes equal, `pppAngleCon` is 5/32,
`pppAngMoveCalc` is 36/208, and `pppAngMoveCon` is 44/256. Do not propagate
the `0x2760` mapping beyond the six-function cluster without a fresh match.
This is a useful example of a locally reliable function cluster inside a
larger region where the mapping changes or code diverges.
