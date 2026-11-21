# Kingdom Hearts De:Compiled

A decompilation of the Playstation 2 releases of Kingdom Hearts.

## Supported Versions

| Game Version             | ELF           | Sha1                                     |
|--------------------------|---------------|------------------------------------------|
| Original Japanese        | `SLPS_251.05` | `9dabbf867a7ec2a030df99ba1ed969f2deef0488`|
| Final Mix (JP Exclusive) | `SLPS_251.98` | `e70bda789916142aafb53d85cef2e806b35ad8d8`|

---

### Dependencies

Some python dependencies are required, which you can obtain by running `pip install -U -r requirements.txt`.

A `mips-linux-gnu` binutils toolchain (`objcopy`, `as`, `ld`) and `ninja` are also required.

---

### Setup

1. Extract the ELF file from an ISO of the game version you're targeting and place it in the root of the repo.
2. Run `./configure.py` to generate the build files.
   - Optionally, specify the game version you're targeting with the `--version`/`-v` flag. Defaults to the original Japanese version if not specified.
   - You can clear existing configurations with the `--clean`/`-c` flag
   - eg: `./configure.py -c -v fm` will clear the existing configuration and generate a new one for the Final Mix version.

3. Run `ninja` to build the project. Final output will be stored by version in the `build` directory.

---

### Notes

No game assets are published in this repository. This includes any files required to run the game, such as the game's executable, ISO, or any files extracted from it.

This repository targets the game's main executable, an ELF file named uniquely by the game's serial number. A copy of the ELF file is required to build the project, and must be provided by the user by extracting it from a legal copy of the game.

 >[!WARNING]
 > Additional asset extraction is currently only supported by the JP version of the game.

Additional assets that are not used in this project may optionally be extracted by running `./tools/iso/extract.py` on the game's ISO. The extracted files are in the `kingdom` directory.

---

### USA ELF inspection (experimental)

The original USA release is not yet a supported decompilation target. The
repository currently contains linker configurations for the Japanese original
and Final Mix only. Do not reuse either configuration for the USA executable:
the main image layout, GP value, BSS size, symbols, and split boundaries must
be validated against the USA ELF first.

Read-only audit tools and current findings:

- `tools/elf/inspect.py` — inspect ELF headers, program headers, sections,
  GP value, hashes, and DVP overlay table metadata.
- `tools/elf/extract_overlays.py` — extract the EE-addressed overlay payloads.
- `tools/elf/vu_disasm.py` — inspect VU instruction pairs, flags, and branches.
- `tools/elf/compare_overlays.py` — compare overlay payloads and identify
  branch-displacement-only differences.
- `tools/elf/compare_main.py` — find coarse unique byte correspondences in
  the main image.
- `tools/elf/map_main_subsegments.py` — map JP Splat main subsegments to
  conservative USA address candidates using multiple unique byte anchors.
- `tools/elf/map_symbols.py` — map known JP function symbols to provisional
  USA addresses using function-bounded byte anchors.
- [USA GP-relative audit](tools/elf/USA_GP_AUDIT.md) — paired GP-opcode patterns; cross-checking shows all current matches are in Splat data segments.
- [USA static data-reference audit](tools/elf/USA_STATIC_REF_AUDIT.md) — 925 mapped absolute-address sequences, with piecewise main-data and BSS target deltas.
- [USA control-flow validation](tools/elf/USA_CONTROL_FLOW.md) — instruction-level checks across mapped PPP, worldfile, and EE library function clusters.
- [USA ELF audit report](tools/elf/USA_AUDIT.md) — validated metadata,
  overlay matches, and current limitations.
- [USA main-image mapping report](tools/elf/USA_MAIN_MAP.md) — first full
  626-boundary JP-to-USA candidate analysis and ordering diagnostics.
- [USA function-symbol mapping report](tools/elf/USA_SYMBOL_MAP.md) — first
  full pass over 532 JP function symbols.
- [iOS port architecture audit](docs/IOS_PORT_AUDIT.md) — confirmed PS2-specific
  build, graphics, VU, kernel, storage, and input dependencies.

The USA build is not enabled yet. These tools provide analysis and extraction,
not a complete USA decompilation configuration or a runnable iOS port.
