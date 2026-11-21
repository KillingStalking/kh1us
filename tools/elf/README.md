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
