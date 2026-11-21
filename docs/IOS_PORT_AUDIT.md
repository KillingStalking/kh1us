# iOS port feasibility and platform-boundary audit

This repository is a PlayStation 2 decompilation project. Its current build
produces a PS2 MIPS ELF/ROM; it does not produce an iOS application. This audit
records concrete platform dependencies found in the current source tree and
defines the work required before an iOS target can be added safely.

## Confirmed blockers

### 1. Build system and CPU architecture

`configure.py` currently exposes only `jp` and `fm` versions. It invokes the
bundled Emotion Engine GCC toolchain, a PS2 assembler, and
`mips-linux-gnu-ld`. The compile flags and assembler configuration target the
R5900/EE ABI. This cannot be reused as an arm64 iOS build by changing compiler
flags: the generated code and inline assembly are for a different CPU and ABI.

Relevant files:
- `configure.py`
- `tools/cc/ee-gcc2.96/`
- `tools/cc/ee-gcc2.9-991111/`
- `include/sdk/ee/`

### 2. Graphics and command submission

The renderer is coupled to the PS2 Graphics Synthesizer and GIF/DMA command
submission. For example, `src/ppp/draw/draw.c` obtains the GIF DMA channel with
`sceDmaGetChan(SCE_DMA_GIF)`; the same module contains GS initialization and
ordering-table draw entry points. The SDK headers define PS2 GS register and
environment structures in `include/sdk/ee/libgraph.h` and DMA channel/tag
structures in `include/sdk/ee/libdma.h`.

An iOS renderer therefore needs a real translation layer from the game's
rendering state and packet generation to Metal resources and command buffers.
A thin wrapper that renames GS calls would not be sufficient.

### 3. Vector unit and R5900 instructions

`src/lib/libvu0.c` contains inline EE/VU instructions such as `lqc2`,
`vmulax`, `vmadday`, `qmfc2`, and `sqc2`. These are not arm64 instructions
and cannot be compiled by the iOS toolchain. The same file also has functions
still supplied through `INCLUDE_ASM`.

The portable path needs scalar/NEON implementations for the vector and matrix
API, with tests against known PS2 behavior. VU microprogram workloads need a
separate semantic audit; replacing the math helper library alone does not
translate VU programs.

### 4. Kernel, filesystem, disc, and save data

- `src/lib/libkernl/initsys.c` uses PS2 syscalls and initializes EE kernel
  facilities such as threads, alarms, and TLB functions.
- `src/lib/libkernl/filestub.c` implements the PS2 SIF filesystem RPC path.
- `src/disk.c` uses PS2 HDD/PFS operations, device-control calls, and CD/DVD
  power callbacks.
- `src/memcard.c` and `src/lib/libmc.c` use the PS2 memory-card service over
  SIF RPC.
- `include/sdk/ee/libpad.h` exposes the PS2 pad API.

These facilities need explicit iOS equivalents: lifecycle/threading,
sandboxed file access, asset streaming, save-game storage, and input routing.
The PS2 HDD and memory-card semantics should be adapted at the game-facing
service boundary, not emulated by pretending iOS has PS2 devices.

## Recommended port architecture

1. Keep the PS2 decompilation target intact as a reference implementation.
2. Finish the USA ELF/symbol/split work before introducing a second game
   revision into the runtime.
3. Identify stable game-facing service boundaries for rendering, audio,
   input, file/asset access, save data, timing, and threading.
4. Implement an arm64-native runtime layer and replace EE/VU assembly in the
   code that is required by that runtime.
5. Implement a Metal renderer that consumes game-level geometry/material/
   texture state rather than trying to execute PS2 GS DMA packets directly.
6. Add iOS app packaging, asset loading, controller/touch input, save storage,
   and device-level validation.

## Current status

| Area | Evidence-based status |
|---|---|
| PS2 JP decompilation project | Existing |
| USA ELF audit | Metadata and overlays audited; main split candidates in progress |
| USA Splat build target | Not implemented |
| arm64 game runtime | Not implemented |
| Metal renderer | Not implemented |
| iOS input/storage/save adapters | Not implemented |
| iOS app/IPA build | Not implemented |

This document is an architecture audit, not a claim that an iOS port exists.
The next implementation milestone remains a validated USA split map and a
reproducible USA decompilation build. Starting a Metal backend before that
would couple the renderer to an unstable game-revision layout.
