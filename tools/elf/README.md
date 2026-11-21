# ELF audit tools

These scripts inspect PS2 ELF32/MIPS executables without modifying them.

## Inspect one executable

```sh
python tools/elf/inspect.py SLUS_203.70 -o usa-elf.json
```

## Compare Japanese and USA overlay payloads

```sh
python tools/elf/compare_overlays.py SLPS_251.05 SLUS_203.70 -o overlay-compare.json
```

The comparison tool reads each overlay's load address from `.DVP.ovlytab`,
gets its payload length from the corresponding `.DVP.overlay.*` section
header, and extracts the bytes from the `main` load image. The section's own
file range is metadata and is not treated as the loaded payload.

The JSON report includes exact matches, load addresses, payload hashes, and
long matching byte ranges for non-identical overlays. Exact matches support
offset-for-offset byte mapping within that overlay. Non-identical matching
ranges are only candidate correspondences: they are not function boundaries,
relocation proofs, or evidence that the code can be transplanted unchanged.

These tools do not extract game assets, modify the input ELF, or claim that
the USA version is fully supported by the decompilation build.
