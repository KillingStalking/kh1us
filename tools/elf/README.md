# ELF audit tools

These scripts inspect PS2 ELF32/MIPS executables without modifying the inputs.

## Inspect one executable

```sh
python tools/elf/inspect.py SLUS_203.70 -o usa-elf.json
```

## Extract overlay payloads

```sh
python tools/elf/extract_overlays.py SLUS_203.70 -o extracted/usa
```

The extractor uses each overlay's EE address from `.DVP.ovlytab` and the
corresponding `.DVP.overlay.*` section size, then reads the payload from the
`main` load image. It writes one binary per overlay plus `manifest.json`.

## Disassemble VU instruction pairs

```sh
python tools/elf/vu_disasm.py extracted/usa/overlay_00_ee_XXXXXXXX_vu_XXXX.bin --base 0x0 --to-ebit
```

Replace the filename and `--base` with the EE/VU values in the extraction
manifest. VU instructions are 8-byte pairs (lower word followed by upper
word). The current decoder prints operation names, common register fields,
branch destinations, E/M/D/T/I flags, and raw words. It is a structural
inspection aid, not a cycle-accurate interpreter or complete semantic decoder.

## Compare Japanese and USA overlay payloads

```sh
python tools/elf/compare_overlays.py SLPS_251.05 SLUS_203.70 -o overlay-compare.json
```

The comparator reports payload hashes, exact matches, long matching byte
ranges, EE/VU addresses, and the fill-byte markers. In these ELF files, the
`.DVP.overlay.*` section bytes themselves are linker fill markers, not the
payload. The EE-addressed range in the main load image is the candidate payload
location.

## Compare main-image blocks

```sh
python tools/elf/compare_main.py SLPS_251.05 SLUS_203.70 -o main-map.json
```

This finds unique fixed-size blocks and groups contiguous matches into
candidate address ranges. It can help transfer known JP split boundaries to
candidate USA locations, but it does not distinguish code from data, resolve
relocations, or identify function boundaries.

Matching bytes are binary correspondences, not automatically verified
function boundaries or a complete JP-to-USA address map.
## Map JP main subsegments to USA candidates

```sh
python tools/elf/map_main_subsegments.py \\
  SLPS_251.05 SLUS_203.70 config/kh.jp.yaml \\
  -o usa-main-subsegment-map.json
```

The mapper reads the declared `main` subsegments from the JP Splat YAML and
looks for unique 16-byte anchors in the first `0x1000` bytes of each JP
subsegment (clipped to that subsegment's end) in both main images. The global
anchor index samples every 4-byte-aligned offset; the per-subsegment scan still
samples at the configured anchor step (16 bytes by default), so valid anchors
are not silently skipped when a segment starts at a non-16-byte alignment. It reports USA start candidates only when the anchors agree on an
address delta. The JSON includes the segment type/name, candidate deltas,
anchor locations, and a status for each subsegment.

This is deliberately conservative: a matching interior anchor does not prove
the JP and USA segment starts are equivalent. One-anchor matches are marked
weak by default; ties are ambiguous; no candidate is copied into a USA YAML.
The JSON also reports ordering anomalies where consecutive candidate JP
boundaries map to non-increasing USA addresses. Validate code/data
classification, MIPS function boundaries, relocations, GP references, and
branch targets before treating any result as a split boundary. The first
full-run candidate counts are recorded in `USA_MAIN_MAP.md`.

## Map JP function symbols to USA candidates

```sh
python tools/elf/map_symbols.py \
  SLPS_251.05 SLUS_203.70 config/jp/symbol_addrs.txt \
  -o usa-symbol-map.json

# Run separately for the JP SDK/library symbol table:
python tools/elf/map_symbols.py \
  SLPS_251.05 SLUS_203.70 config/jp/lib_symbol_addrs.txt \
  -o usa-library-symbol-map.json
```

The symbol mapper reads only entries marked `type:func`, bounds each scan by
the next greater JP function symbol (and a default maximum of `0x400` bytes),
then votes using unique 16-byte anchors indexed at 4-byte alignment. It is useful for checking known
function clusters and identifying candidate USA addresses. Short functions,
changed functions, missing symbols, aliases, and repeated code can prevent a
reliable mapping; all output remains provisional and must be checked against
MIPS disassembly and control flow. The JSON also reports non-increasing USA-address order anomalies between
consecutive candidate symbols. The first full result is recorded in
`USA_SYMBOL_MAP.md`.

## Audit GP-relative references

```sh
python tools/elf/audit_gp_refs.py \
  SLPS_251.05 SLUS_203.70 -o usa-gp-reference-audit.json
```

The GP audit pins the retail ELF hashes, scans `ADDIU` and load/store
encodings using `$gp`, and pairs patterns only inside long runs of unique,
byte-identical anchors. Pass `--jp-yaml` to classify each JP offset by Splat
subsegment. The current 373 paired patterns all fall in `data` subsegments;
none is confirmed as executable GP-relative code. The tool does not generate
linker symbols.

See [USA_GP_AUDIT.md](USA_GP_AUDIT.md) for the current results.

## Validate known JP-USA MIPS control-flow clusters

```sh
python tools/elf/validate_control_flow.py \
  SLPS_251.05 SLUS_203.70 \
  -o usa-control-flow-validation.json
```

This version-pinned check validates 13 manually mapped function extents from
the PPP, worldfile, and EE library regions. It compares instruction/register
signatures and verifies direct branch, jump, and call targets against three
piecewise JP-to-USA address ranges. It rejects ELF inputs whose SHA-1 values
do not match the audited JP and USA executables. The output is evidence for
these specific clusters only; it is not a complete USA symbol map.
