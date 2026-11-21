#!/usr/bin/env python3
"""Unit tests for the standalone KH1 ELF/VU audit helpers."""
from __future__ import annotations

import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent


def load_tool(filename: str, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, HERE / filename)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


compare_tool = load_tool("compare_overlays.py", "kh1_compare_overlays")
extract_tool = load_tool("extract_overlays.py", "kh1_extract_overlays")
vu_tool = load_tool("vu_disasm.py", "kh1_vu_disasm")


def make_elf(path: Path, main_payload: bytes) -> None:
    if len(main_payload) != 32:
        raise ValueError("test main payload must be exactly 32 bytes")

    data = bytearray(0x400)
    main_off, table_off, strtab_off, marker_off, shstr_off, shoff = (
        0x100, 0x220, 0x230, 0x250, 0x280, 0x300
    )
    overlay_strings = b".DVP.overlay.test\0"
    section_names = (
        b"\0main\0.DVP.ovlytab\0.DVP.ovlystrtab\0"
        b".DVP.overlay.test\0.shstrtab\0"
    )
    name_offsets = {}
    cursor = 0
    for name in section_names.split(b"\0"):
        if name:
            name_offsets[name.decode("ascii")] = cursor
        cursor += len(name) + 1

    data[main_off:main_off + 32] = main_payload
    struct.pack_into("<III", data, table_off, 0, 0x100000, 0)
    data[strtab_off:strtab_off + len(overlay_strings)] = overlay_strings
    data[marker_off:marker_off + 16] = b"\0" * 16
    data[shstr_off:shstr_off + len(section_names)] = section_names

    sections = [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (name_offsets["main"], 1, 7, 0x100000, main_off, 32, 0, 0, 128, 0),
        (name_offsets[".DVP.ovlytab"], 0x7FFFF800, 1, 0, table_off, 12, 0, 0, 4, 12),
        (name_offsets[".DVP.ovlystrtab"], 3, 1, 0, strtab_off, len(overlay_strings), 0, 0, 1, 1),
        (name_offsets[".DVP.overlay.test"], 0x7FFFF801, 5, 0, marker_off, 16, 0, 0, 8, 0),
        (name_offsets[".shstrtab"], 3, 0, 0, shstr_off, len(section_names), 0, 0, 1, 0),
    ]
    for index, section in enumerate(sections):
        struct.pack_into("<IIIIIIIIII", data, shoff + index * 40, *section)

    ident = b"\x7fELF\x01\x01\x01" + b"\0" * 9
    struct.pack_into(
        "<16sHHIIIIIHHHHHH",
        data,
        0,
        ident, 2, 8, 1, 0x100008, 0, shoff, 0x20924001,
        52, 32, 0, 40, len(sections), 5,
    )
    path.write_bytes(data)


class OverlayToolTests(unittest.TestCase):
    def test_identical_and_different_payloads(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jp = root / "jp.elf"
            usa = root / "usa.elf"
            payload = bytes(range(32))
            make_elf(jp, payload)
            make_elf(usa, payload)
            same = compare_tool.compare(jp, usa)
            self.assertEqual(same["exact_payload_match_count"], 1)

            changed = bytearray(payload)
            changed[4] ^= 0xFF
            make_elf(usa, bytes(changed))
            different = compare_tool.compare(jp, usa)
            self.assertEqual(different["different_payload_count"], 1)

    def test_extractor_writes_payload_and_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            elf = root / "sample.elf"
            out = root / "out"
            payload = bytes(range(32))
            make_elf(elf, payload)
            manifest = extract_tool.extract(elf, out)
            self.assertEqual(manifest["overlay_count"], 1)
            extracted = out / manifest["overlays"][0]["filename"]
            self.assertEqual(extracted.read_bytes(), payload[:16])
            self.assertTrue((out / "manifest.json").is_file())

    def test_vu_pair_decoder_and_alignment_validation(self):
        pair = struct.pack("<II", 0x100E0400, 0x000002FF)
        lines = vu_tool.disassemble(pair)
        self.assertEqual(len(lines), 1)
        self.assertIn("NOP", lines[0])
        self.assertIn("IADDIU", lines[0])
        with self.assertRaises(ValueError):
            vu_tool.disassemble(pair + b"\0")


if __name__ == "__main__":
    unittest.main()
