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
