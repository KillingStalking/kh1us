# Kingdom Hearts USA ELF audit

## Inputs and derived image checksums

| Build | File | Size | ELF SHA-1 |
|---|---|---:|---|
| Original Japanese | `SLPS_251.05` | 3,778,176 | `9dabbf867a7ec2a030df99ba1ed969f2deef0488` |
| USA | `SLUS_203.70` | 3,776,580 | `8704cda65ca5e3f04202f0a50472401355335312` |

Both are ELF32 little-endian MIPS executables with entry point `0x00100008`.
Both contain 34 DVP overlay-table records.

The JP raw image produced with `llvm-objcopy -O binary --gap-fill=0x00 -R .reginfo`
has SHA-1 `cb85dbab6c05667ed11d94e94abfa079baaf12c2`, exactly matching the
repository's existing JP checksum. The same extraction procedure produces
USA raw-image SHA-1 `1985db8cd8154990d6a605b7b7ac5e138d8d48bf`.
This confirms the raw-image extraction procedure against the known JP target.

## Main image metadata

| Field | JP | USA |
|---|---:|---:|
| Main VMA | `0x00100000` | `0x00100000` |
| Main file size | 3,726,080 (`0x38DB00`) | 3,724,256 (`0x38D3E0`) |
| GP from `.reginfo` | `0x0048DB00` | `0x0048D3E0` |
| BSS address | `0x0048DB00` | `0x0048D400` |
| BSS size | 1,971,456 (`0x1E1500`) | 1,957,504 (`0x1DFA80`) |

The USA GP and BSS values differ from JP. This is one reason the JP YAML
cannot safely be reused for USA by changing only the executable name.

## Overlay extraction method

The overlay table provides an EE load address and a VU address. The matching
`.DVP.overlay.*` section supplies the overlay size. In these files, the
marker section bytes are uniform fill values rather than the program bytes.
The candidate overlay bytes are therefore read from the `main` load image at:

```text
file_offset = main.file_offset + overlay.ee_address - main.address
payload_size = matching .DVP.overlay section size
```

Every extracted range was inside the main image, and every size was divisible
by 8 bytes (the size of a VU instruction pair).

## Results

- 22 of 34 extracted overlay payloads are byte-identical.
- 12 payloads differ.
- The 22 exact matches permit offset-for-offset correspondence inside those
  particular payloads only.
- The EE load-address delta is constant for overlays 0–15: JP is
  `0x7C0` bytes above USA.
- The remaining exact overlays have several different deltas; do not apply a
  single global address adjustment.

### Exact payload matches

| Overlay | JP EE address | USA EE address | JP − USA | VU address | Size |
|---:|---:|---:|---:|---:|---:|
| 0 | `0x4800A8` | `0x47F8E8` | `0x7C0` | `0x0000` | 2048 |
| 1 | `0x4808B0` | `0x4800F0` | `0x7C0` | `0x0800` | 1152 |
| 2 | `0x480D38` | `0x480578` | `0x7C0` | `0x0000` | 2048 |
| 3 | `0x481540` | `0x480D80` | `0x7C0` | `0x0800` | 896 |
| 4 | `0x4818C8` | `0x481108` | `0x7C0` | `0x0000` | 2048 |
| 5 | `0x4820D0` | `0x481910` | `0x7C0` | `0x0800` | 1256 |
| 6 | `0x4825C8` | `0x481E08` | `0x7C0` | `0x0000` | 2048 |
| 7 | `0x482DD0` | `0x482610` | `0x7C0` | `0x0800` | 1696 |
| 10 | `0x484038` | `0x483878` | `0x7C0` | `0x0000` | 576 |
| 11 | `0x484288` | `0x483AC8` | `0x7C0` | `0x0000` | 2048 |
| 12 | `0x484A90` | `0x4842D0` | `0x7C0` | `0x0800` | 1400 |
| 13 | `0x485018` | `0x484858` | `0x7C0` | `0x0000` | 2048 |
| 14 | `0x485820` | `0x485060` | `0x7C0` | `0x0800` | 1256 |
| 15 | `0x4864C0` | `0x485D00` | `0x7C0` | `0x0000` | 840 |
| 16 | `0x26F318` | `0x26D158` | `0x21C0` | `0x0000` | 80 |
| 17 | `0x26F420` | `0x26D2F0` | `0x2130` | `0x0000` | 1120 |
| 23 | `0x2715C8` | `0x26F498` | `0x2130` | `0x0800` | 1968 |
| 25 | `0x2725A8` | `0x270478` | `0x2130` | `0x0800` | 2048 |
| 26 | `0x272DB0` | `0x270C80` | `0x2130` | `0x1000` | 160 |
| 30 | `0x2740C0` | `0x271FB0` | `0x2110` | `0x0000` | 832 |
| 31 | `0x274420` | `0x272310` | `0x2110` | `0x0000` | 944 |
| 33 | `0x274D88` | `0x272C78` | `0x2110` | `0x0000` | 904 |

### Differing payloads

The similarity value below is the sum of non-overlapping matching byte blocks
of at least 16 bytes divided by the larger payload size. It is a lower bound,
not a semantic equivalence score.

| Overlay | JP size | USA size | Matching-byte lower bound |
|---:|---:|---:|---:|
| 8 | 2048 | 2048 | 91.89% |
| 9 | 944 | 936 | 99.15% |
| 18 | 1000 | 1000 | 99.60% |
| 19 | 1112 | 1112 | 99.73% |
| 20 | 1464 | 1464 | 99.80% |
| 21 | 1672 | 1672 | 99.82% |
| 22 | 2048 | 2048 | 99.85% |
| 24 | 2048 | 2048 | 99.85% |
| 27 | 2048 | 2048 | 98.63% |
| 28 | 2048 | 2048 | 98.83% |
| 29 | 544 | 568 | 95.60% |
| 32 | 1104 | 1104 | 99.73% |

### VU instruction-pair comparison

VU instructions are 8-byte pairs. For equal-sized overlays, pairs were compared
as two 32-bit words. The comparator also identifies branch-only changes where
the opcode and upper word are unchanged and only the signed 11-bit branch
displacement differs.

| Overlay | Exact pairs | Branch-displacement-only changes | Other changed pairs |
|---:|---:|---:|---:|
| 8 | 198 / 256 | 22 | 36 |
| 18 | 123 / 125 | 0 | 2 |
| 19 | 138 / 139 | 0 | 1 |
| 20 | 182 / 183 | 0 | 1 |
| 21 | 208 / 209 | 0 | 1 |
| 22 | 255 / 256 | 0 | 1 |
| 24 | 255 / 256 | 0 | 1 |
| 27 | 236 / 256 | 1 | 19 |
| 32 | 137 / 138 | 0 | 1 |

Three size/placement differences are alignment changes rather than broad code
rewrites:

- Overlay 9: the USA payload is one 8-byte pair shorter at the beginning; the
  remaining 117 pairs match exactly.
- Overlay 28: 253 pairs (2024 bytes) match after a 3-pair / 24-byte USA prefix.
- Overlay 29: 64 pairs (512 bytes) match after a 3-pair / 24-byte USA prefix;
  one later pair differs and the final three pairs match.

Overlay 8 contains many branch displacement changes. Those must be interpreted
as control-flow changes in the VU program, not blindly patched with a global
address delta. Overlay 27 also has a changed tail region and requires full
instruction-flow review.

## Main-image byte comparison

Comparing the two main sections at the same relative file offsets yields
1,681,944 equal bytes out of 3,724,256 (45.16%). A unique 16-byte block matcher
also finds 39,667 unique block correspondences, grouped into 2,139 contiguous
candidate ranges of at least 64 bytes (393,712 bytes total).

These are candidate byte correspondences only. The matcher does not distinguish
code from data, and a matching range may contain instructions, constants, or
other embedded data. Do not treat these ranges as function matches without
validating the relevant addresses against the JP split map and instruction
boundaries.

## Limits and next work

The current tools can inspect ELF metadata, extract overlay payloads, compare
VU pairs, and show coarse main-image block correspondences. They do not yet
provide a full VU semantic decoder, a complete MIPS R5900 function matcher,
relocation resolution, or a verified USA function map.

The repository's current decompilation configuration has JP and Final Mix
targets, but no USA target. A USA config must not be generated by copying the
JP YAML and changing only the basename: the main image layout, GP value, BSS
size, symbols, checksums, split boundaries, and undefined-symbol maps need
independent validation against the USA ELF.

Next implementation milestone: use the JP split map to classify main-image
matches as code/data, review the changed VU pairs and branch targets, then
generate and validate USA-specific split boundaries. Only after that should a
USA Splat configuration be enabled.
