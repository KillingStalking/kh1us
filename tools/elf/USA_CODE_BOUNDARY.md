# USA main-image code/data boundary recovery

## Current conclusion

**No USA main-image code/data split is established yet.** The retail USA ELF
stores the main image in one load image; the ELF metadata does not provide a
separate code section and data section boundary. The JP Splat boundary
(`main+0x16F2E0`) is metadata for the Japanese build and must not be copied to
USA by assumption.

The known JP-to-USA function checks establish several *local executable
islands*, not a continuous code interval:

| Cluster | USA main offset range | Evidence |
|---|---:|---|
| PPP point/movement functions | `0x82B80–0x85628` | Six consecutive function extents; 160/160 instruction operation/register signatures; all 14 direct targets checked in the cluster resolve under the PPP delta where applicable |
| worldfile functions | `0x11E80–0x120A8` | Four consecutive function extents; 138/138 instruction signatures; 25/25 control-flow instruction positions/types; 22/22 direct targets resolve |
| EE library functions | `0x14B388–0x14B79C` | Three consecutive function extents; 180/180 instruction signatures; 21/21 control-flow instruction positions/types; 18/18 direct targets resolve |

The aggregate pinned validation covers 13 functions, 488 instruction words,
61 control-flow instructions, and 49 direct branch/jump/call targets. These
results are documented in [USA_CONTROL_FLOW.md](USA_CONTROL_FLOW.md).

These extents prove that the listed USA ranges contain code matching the
corresponding JP functions. They do **not** prove that all bytes between or
outside those ranges are code, nor do they identify the first byte of the
USA data region. In particular, the gap between the worldfile and library
clusters cannot be classified from these samples.

## Why the current candidate mappers cannot decide the split

- `map_main_subsegments.py` searches a limited prefix of each JP subsegment
  and votes on an interior byte correspondence. A mapped interior anchor is
  not a verified USA subsegment start or an end boundary.
- `map_symbols.py` uses provisional JP function extents and unique byte
  anchors. A candidate symbol address is not promoted until instruction
  semantics and control-flow targets are checked.
- `audit_static_refs.py` now deliberately labels USA main-image targets as
  `main_image_unclassified`. It cannot use the JP Splat code/data boundary
  to classify USA addresses.
- The ELF has no retained relocation sections or conventional symbol table
  that would independently settle the split.

The historical aggregate counts in `USA_MAIN_MAP.md`,
`USA_SYMBOL_MAP.md`, and `USA_STATIC_REF_AUDIT.md` remain candidate
inventories, not validated USA split metadata. The mapper revision notices in
those reports must be respected until the tools are rerun on the pinned files.

## Evidence required before promoting a USA boundary

A proposed boundary or code interval should be promoted only when several
independent checks agree:

1. **Function identity:** a JP function maps to a USA address using multiple
   unique anchors, and the prologue/body decode as valid MIPS instructions.
2. **Control-flow closure:** direct branches, jumps, and calls resolve to
   independently mapped USA code; delay slots and return structure are
   consistent. An isolated plausible instruction sequence is insufficient.
3. **Caller/callee corroboration:** at least one independently mapped caller
   reaches the candidate function, or multiple callers resolve to it.
4. **Instruction/data discrimination:** candidate code decodes coherently over
   the function extent, while adjacent data is supported by pointer tables,
   strings, structured records, or non-code reference patterns. Opcode
   density alone is not sufficient because data can decode as MIPS.
5. **Boundary bracketing:** the last validated function before a proposed
   transition and the first validated function after it are both located;
   intervening bytes are inspected for alignment, padding, jump tables, and
   embedded constants.
6. **Address-reference consistency:** absolute address constructions and
   data references resolve to the independently recovered USA object ranges.
   Any unexplained cross-region reference blocks promotion.
7. **Reproducibility:** every promoted range is tied to the exact pinned ELF
   SHA-1 values and emitted by a deterministic audit report.

## Confidence levels for future reports

- **Verified function extent:** instruction/register signatures and all direct
  control-flow targets in the checked extent match independent USA mappings.
- **Strong code-region candidate:** multiple verified functions form a
  contiguous region, and caller/callee plus boundary-bracketing checks agree.
- **Provisional code/data transition:** one side is strongly classified but
  the adjacent side or intervening bytes remain unresolved.
- **Unclassified:** only byte anchors, instruction-like patterns, or static
  references are available.

Only verified extents and strong regions should enter a draft USA Splat map.
A single global code/data split must not be emitted unless the evidence shows
that the USA layout actually has one contiguous code prefix followed by data.
If the image is interleaved, the USA configuration must use multiple
subsegments instead.

## Next implementation sequence

1. Rerun the corrected main-subsegment and function-symbol mappers on the
   exact pinned ELF pair; replace historical candidate counts only after
   reviewing the new output.
2. Extend the validated function inventory beyond the three current clusters.
   Prioritize candidates with multiple anchors and consistent neighboring
   symbols, then decode each candidate and verify its direct targets.
3. Build a cross-reference graph from verified functions to verified
   functions and from verified code to candidate data objects.
4. Inspect candidate transitions and gaps; record padding, jump tables,
   embedded constants, and data blocks rather than forcing a binary split.
5. Generate a draft USA Splat configuration only from the resulting verified
   ranges. Keep unresolved intervals explicitly unclassified.

## Reproduction

The existing pinned function-level validator is:

```sh
python tools/elf/validate_control_flow.py \
  SLPS_251.05 SLUS_203.70 -o usa-control-flow-validation.json
```

This audit note is a methodology and evidence ledger. It does not claim that
the corrected candidate mappers have been rerun or that a USA Splat
configuration is ready.
