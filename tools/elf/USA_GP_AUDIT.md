# USA GP-relative reference audit

This report compares GP-based address formation in the pinned retail JP and
USA ELF executables. The tool scans only MIPS/R5900 `ADDIU` and load/store
instruction encodings with `rs = $gp`. It then pairs references only when
they fall inside long runs of unique, byte-identical 16-byte anchors shared
by both main images.

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

## Exact-anchor coverage

| Measurement | Result |
|---|---:|
| Unique 16-byte anchor pairs (4-byte index alignment) | 207,994 |
| Long contiguous exact runs (at least 64 bytes) | 3,296 |
| Bytes covered by those runs | 458,564 |
| Raw GP-based instruction candidates in the full main image, JP | 842 |
| Raw GP-based instruction candidates in the full main image, USA | 771 |
| Paired GP-based instructions inside exact runs | 373 |

All **373 paired references** preserve the same instruction bytes and
immediate, and their computed effective addresses differ by exactly
`0x720`. No other effective-address delta occurs in this paired set.

## Target-region comparison

| JP target region | USA target region | References |
|---|---|---:|
| Before BSS | Before BSS | 211 |
| BSS | BSS | 118 |
| BSS | Before BSS | 44 |
| **Total** | | **373** |

The 44 cross-boundary references are particularly important. Every one points
into the first 32 bytes of the JP BSS range:

- JP effective addresses: `0x0048DB00–0x0048DB1F`
- Corresponding USA effective addresses: `0x0048D3E0–0x0048D3FF`

Those USA addresses are immediately before the USA BSS start at
`0x0048D400`. This is consistent with a 32-byte difference in the GP/BSS
boundary layout, but does not by itself identify the variables or prove that
the two 32-byte regions have identical semantics. They must be checked against
Splat data boundaries and the instructions that initialize/use them.

## Interpretation

The result confirms that a single GP delta of `0x720` correctly translates
the effective addresses for the 373 paired, byte-identical references.
However, it does **not** justify applying that delta to every GP reference in
the executable: 842 JP and 771 USA raw candidates were found in the complete
main sections, and only the references inside long exact runs were paired.

The ELF `main` section contains both code and data. Raw opcode patterns can
occur in data, and exact byte anchors do not establish function boundaries.
The remaining work is to:

1. classify these ranges using JP Splat code/data boundaries;
2. identify which of the 373 candidates are genuine executed instructions;
3. inspect all unmatched GP references, especially changed immediates;
4. map the 32-byte GP/BSS boundary region to concrete data objects;
5. validate startup initialization, callers, and all GP-relative references
   before emitting USA linker symbols or a USA Splat configuration.

## Reproduction

```sh
python tools/elf/audit_gp_refs.py \
  SLPS_251.05 SLUS_203.70 \
  -o usa-gp-reference-audit.json
```

The tool pins both input SHA-1 values and refuses other executables. The JSON
contains each paired reference, its JP/USA instruction address, opcode,
immediate, computed effective addresses, target-region classification, and
the exact-anchor run size.
