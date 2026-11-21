# USA function-symbol candidate mapping report

This report records a full candidate-mapping pass over the existing JP game
function symbol table, using the supplied JP and USA ELF inputs.

## Inputs

- JP ELF: `SLPS_251.05`
- USA ELF: `SLUS_203.70`
- JP symbol source: `config/jp/symbol_addrs.txt`
- JP ELF SHA-1: `9dabbf867a7ec2a030df99ba1ed969f2deef0488`
- USA ELF SHA-1: `8704cda65ca5e3f04202f0a50472401355335312`

The symbol source contains 532 entries marked `type:func` within the JP main
image. All 532 have distinct start addresses.

## Mapper settings and results

- Anchor size: 16 bytes
- Anchor step: 16 bytes
- Maximum scan size per function: `0x400` bytes
- Function scan end: the next greater JP function symbol address, capped by
  the maximum scan size and the end of the main image
- An anchor is eligible only when its block occurs exactly once in each full
  main image and contains at least four distinct byte values.

| Status | Count |
|---|---:|
| Strong candidate (at least 3 anchors) | 72 |
| Candidate (2 anchors) | 24 |
| Weak single-anchor result | 59 |
| Ambiguous top vote | 1 |
| Unmatched | 376 |
| **Total** | **532** |

The 96 candidate symbols have nine adjacent ordering anomalies, where a later
JP symbol maps to an equal or lower USA address than the previous candidate.
Four of those anomalies occur within the 72 strong candidates. Frequent
candidate deltas include `0x31A0` (19 symbols), `0x2410` (10), and
`0x3260` (7), confirming that a single global address adjustment is invalid.

## Interpretation

These counts are generated from unique byte anchors within provisional
function extents. They are not proof of symbol identity: the JP symbol list may
omit functions, some functions may differ substantially between releases,
and a matching block can occur in unrelated code. The next step is to inspect
candidate function prologues, branch targets, call relationships, and
relocation-sensitive address constants. Do not copy these candidates directly
into a USA symbol map.

Two manually checked clusters are recorded in
[`USA_MAIN_MAP.md`](USA_MAIN_MAP.md): the PPP point/movement functions and
the worldfile functions. They demonstrate that useful local mappings exist,
but that deltas can change across nearby code.
