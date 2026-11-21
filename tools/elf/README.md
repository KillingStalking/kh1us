# ELF audit tools

These scripts inspect PS2 ELF32/MIPS executables without modifying the inputs.

## Inspect one executable

```sh
python tools/elf/inspect.py SLUS_203.70 -o usa-elf.json
```

## Compare Japanese and USA DVP overlay payloads

```sh
python tools/elf/compare_overlays.py SLPS_251.05 SLUS_203.70 -o overlay-compare.json
```

For each DVP overlay table entry, the comparator:
- resolves the corresponding `.DVP.overlay.*` marker section;
- uses that section's size as the overlay payload length;
- reads the payload from the `main` load image at the entry's EE address;
- validates that the range is in bounds and aligned to 8-byte VU instruction pairs;
- reports exact hashes and long matching byte ranges.

The `.DVP.overlay.*` section bytes themselves are linker fill markers, not
the payload. The EE-addressed range in the main load image is the candidate
payload location. The report is a binary comparison aid: matching bytes do
not automatically establish function boundaries or a complete JP-to-USA
address map. The script validates bounds and alignment, but does not yet
disassemble VU instructions.
