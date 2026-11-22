# USA function expansion priorities

This is a source-symbol work queue for expanding the validated JP-to-USA
function inventory. It deliberately records **JP names and addresses only**:
no USA addresses are inferred here. A priority entry becomes a USA mapping
only after the function body, instruction semantics, and control-flow targets
have been checked against the pinned USA ELF.

## Inputs and guardrails

- JP ELF SHA-1: `9dabbf867a7ec2a030df99ba1ed969f2deef0488`
- USA ELF SHA-1: `8704cda65ca5e3f04202f0a50472401355335312`
- JP function source: `config/jp/symbol_addrs.txt` (532 function symbols)
- Existing validated inventory: 13 functions in
  [USA_CONTROL_FLOW.md](USA_CONTROL_FLOW.md).

The 532-symbol count and addresses describe the JP symbol source, not the
number of functions present or recoverable in USA. Candidate mapper reports
are historical until regenerated with the corrected 4-byte-aligned anchor
index.

## Priority queue

| Priority | JP symbol group | JP address range / entries | Why it matters | Current status |
|---|---|---|---|---|
| P0 | CDVD / file loading | `0x11FB68–0x120958`; 14 named entries | File lookup, image reads, decompression, module loading and initialization are high-value dependencies for reaching game content on a new runtime. | JP symbols only; no USA mapping validated yet. |
| P1 | Startup-adjacent functions | `main=0x100438`, `func_0010BEE8`, `func_00110ED8` | Entry/startup and early subsystem setup can expose the call graph leading into file loading and game initialization. | Names are partly generic/uncertain; require caller and callee evidence. |
| P1 | PPP manager / resource setup | `0x180F78–0x1837C0` named functions | Rendering-system initialization, packet setup, object/shape/resource handling. Useful after file-loading paths. | JP symbols only; separate local mappings must be found. |
| P1 | PPP allocation and neighboring operators | `0x183D30–0x185CC0` | Contains allocator helpers and the known point/move/acceleration cluster, followed by operators whose layout diverges under the known PPP delta. | Six point/move/acceleration functions are validated; adjacent operators are not. |
| P2 | Remaining PPP operators and geometry | `0x185588+` | Angle, angular movement, scale, color, vertex/face and matrix functions can extend the rendering call graph. | Must not inherit the `0x2760` delta: the existing spot-check explicitly found poor byte similarity immediately after the six-function cluster. |
| P2 | Worldfile and CDVD callers | `0x111F40–0x120958` | Establishes links from game logic into world naming, file lookup, and resource loading. | Four worldfile functions validated; CDVD block remains unmapped. |
| P3 | EE library dependencies | Known `sprintf`, `strcat`, `strcpy` | Reusable call targets help close call edges and identify compiler/library regions. | Three functions validated at the separate `0x2518` delta. |

## Recommended expansion order

### 1. CDVD block

Start with `cdvd_GetFileDescriptor`, `cdvd_FindFreeTask`,
`cdvd_FreeTask`, `cdvd_Decompress`, `cdvd_Hash`, `cdvd_Compare`,
`cdvd_FindFile`, `cdvd_ReadImgFile`, `cdvd_TryLoadFile`,
`cdvd_Seek`, `cdvd_GetFileName`, `cdvd_TryLoadModule`,
`cdvd_StartModule`, and `cdvd_Initialize`.

Treat the next JP symbol as a provisional extent bound only. For each
candidate USA location:
- require at least two independent unique anchors, preferably three or more;
- compare operation/register signatures over the decoded body;
- resolve every direct branch, jump, and call;
- identify calls between CDVD functions and calls into known library ranges;
- inspect delay slots, return paths, and any jump tables;
- record data references separately from code edges.

Do not extrapolate a single delta across the whole CDVD block unless every
function and cross-function target supports it.

### 2. Startup callers

Use the entry point and generic early symbols to discover the route into
initialization. Generic labels such as `func_0010BEE8` and
`func_00110ED8` must retain generic names until semantics or matching
evidence justifies a descriptive name. A byte-anchor match alone is not enough.

### 3. PPP expansion

Do not extend the validated `0x2760` delta beyond the six checked point,
move, and acceleration functions. The next symbols (`pppAngleCalc`,
`pppAngleCon`, `pppAngMoveCalc`, and following operators) are an explicit
fresh-mapping target, not presumed members of the same USA range.

## Call-graph edge policy

Every discovered edge should carry:
- source function identity and exact source instruction offset;
- edge kind: conditional branch, unconditional jump, direct call, or indirect;
- JP target and USA target, where both are known;
- mapping evidence and confidence;
- whether the target is a validated function, a validated code region, or
  unresolved.

A target falling inside a previously observed address-delta range is not
automatically a known function. Indirect calls/jumps remain unresolved unless
a jump-table or function-pointer table is recovered. Keep call edges distinct
from intra-function branches.

## Promotion criteria

A function enters the validated inventory only if:
1. the exact pinned ELF hashes match;
2. multiple unique anchors support the start mapping;
3. the candidate body has coherent MIPS instruction boundaries and matching
   operation/register signatures;
4. direct control-flow layout and all direct targets are checked;
5. caller/callee relationships independently corroborate the mapping;
6. the candidate extent does not overlap another promoted function;
7. unresolved data references and indirect edges are explicitly recorded.

## Next deliverable

The next numerical deliverable should be a regenerated candidate inventory
from the corrected mapper, followed by a function-level validation report for
the first CDVD subcluster. Do not publish candidate counts as validated
mappings, and do not generate `config/kh.usa.yaml` from this queue alone.

## CDVD candidate-generation and validation commands

The function mapper's default 0x400-byte cap is too small for the
`cdvd_TryLoadFile` JP symbol interval (0x450 bytes to the next named function).
Use 0x800 as the cap; the mapper still stops at the next distinct function
symbol where that bound is available:

```sh
python tools/elf/map_symbols.py \
  SLPS_251.05 SLUS_203.70 config/jp/symbol_addrs.txt \
  --max-function-size 0x800 --min-anchors 2 \
  -o usa-symbol-candidates.json
python tools/elf/validate_symbol_candidates.py \
  SLPS_251.05 SLUS_203.70 usa-symbol-candidates.json \
  --name-prefix cdvd_ --min-anchors 2 --min-signature-ratio 0.98 \
  -o usa-cdvd-function-validation.json
```

The validator requires the pinned ELF hashes and matching mapper-report hashes.
It compares operation/register signatures and control-flow layout, and checks
translated direct targets when they fall inside another mapped candidate. It
records unresolved external targets instead of assuming a global address
 delta. Its `validated_candidate_body` label is deliberately weaker than a
promoted function mapping: independent caller/callee evidence, full target
resolution, delay-slot review, and boundary checks remain mandatory.

**Execution status:** these commands and the validator have been committed,
but the ELF analysis has not yet been rerun in this environment. No USA CDVD
address, function count, or call edge is claimed as measured by this revision.
