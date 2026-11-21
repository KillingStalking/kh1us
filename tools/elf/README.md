# ELF audit tools

These scripts inspect PS2 ELF32/MIPS executables without modifying the inputs.

## Inspect one executable

```sh
python tools/elf/inspect.py SLUS_203.70 -o usa-elf.json
```

## Compare Japanese and USA DVP overlay metadata

```sh
python tools/elf/compare_overlays.py SLPS_251.05 SLUS_203.70 -o overlay-compare.json
```

The comparator pairs entries by overlay-table index and reports section names,
EE/VU address fields, section sizes, SHA-1 hashes, and constant fill-byte
patterns.

**Important:** In the inspected Kingdom Hearts ELF files, the
`.DVP.overlay.*` section contents are uniform fill bytes. They are not the
VU microprogram payloads. The comparator deliberately does not read bytes from
the main load image at the overlay EE addresses and does not claim to produce
a JP-to-USA function or code-address map.

Matching section fill patterns are not evidence of equivalent executable
code. Establishing the actual microprogram storage and loader behavior requires
separate analysis of the DVP linker/loader and the EE-side code that submits
VU programs.
