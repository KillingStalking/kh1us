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
compare_main_tool = load_tool("compare_main.py", "kh1_compare_main")
extract_tool = load_tool("extract_overlays.py", "kh1_extract_overlays")
vu_tool = load_tool("vu_disasm.py", "kh1_vu_disasm")
map_tool = load_tool("map_main_subsegments.py", "kh1_map_main_subsegments")
map_symbol_tool = load_tool("map_symbols.py", "kh1_map_symbols")
symbol_tool = load_tool("map_symbols.py", "kh1_map_symbols")


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

    def test_branch_displacement_only_change(self):
        jp_pair = struct.pack("<II", 0x40000001, 0x000002FF)
        usa_pair = struct.pack("<II", 0x40000002, 0x000002FF)
        stats = compare_tool.pair_statistics(jp_pair, usa_pair)
        self.assertEqual(stats["branch_displacement_only_changes"], 1)
        self.assertEqual(stats["other_changed_pairs"], 0)
        self.assertEqual(stats["pairs_equal_after_branch_mask"], 1)

    def test_main_image_matcher(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jp = root / "jp.elf"
            usa = root / "usa.elf"
            payload = bytes(range(32))
            make_elf(jp, payload)
            make_elf(usa, payload)
            result = compare_main_tool.compare(jp, usa, chunk_size=16, min_run=16)
            self.assertEqual(result["reported_matching_bytes"], 32)
            self.assertEqual(result["ranges"][0]["delta"], 0)

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

    def test_jp_yaml_subsegment_parser(self):
        yaml_text = """segments:
- name: main
  type: code
  subsegments:
  - [ 0x0, hasm, crt0 ]
  - [ 0x20, c, gameplay ]
  - [ 0x80, data ]
- name: overlay_0
"""
        entries = map_tool.parse_main_subsegments(yaml_text)
        self.assertEqual(len(entries), 3)
        self.assertEqual(entries[0]["type"], "hasm")
        self.assertEqual(entries[0]["name"], "crt0")
        self.assertEqual(entries[0]["jp_size"], 0x20)
        self.assertEqual(entries[1]["jp_size"], 0x60)

    def test_main_subsegment_mapper_uses_multiple_unique_anchors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jp = root / "jp.elf"
            usa = root / "usa.elf"
            payload = bytes(range(32))
            make_elf(jp, payload)
            make_elf(usa, payload)
            yaml_path = root / "jp.yaml"
            yaml_path.write_text(
                "segments:\n- name: main\n  subsegments:\n"
                "  - [ 0x0, asm, first ]\n"
                "  - [ 0x10, data, second ]\n",
                encoding="utf-8",
            )
            result = map_tool.map_subsegments(
                jp, usa, yaml_path, block_size=16, step=16,
                search_window=16, min_anchors=1,
            )
            self.assertEqual(result["subsegment_count"], 2)
            self.assertEqual(result["subsegments"][0]["status"], "candidate")
            self.assertEqual(result["subsegments"][1]["status"], "candidate")
            self.assertEqual(result["mapping_order_anomaly_count"], 0)
            self.assertEqual(
                result["subsegments"][1]["candidates"][0]["usa_start_candidate"],
                16,
            )

    def test_mapper_reports_non_monotonic_candidates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jp = root / "jp.elf"
            usa = root / "usa.elf"
            payload = bytes(range(32))
            make_elf(jp, payload)
            make_elf(usa, payload[16:] + payload[:16])
            yaml_path = root / "jp.yaml"
            yaml_path.write_text(
                "segments:\n- name: main\n  subsegments:\n"
                "  - [ 0x0, asm, first ]\n"
                "  - [ 0x10, data, second ]\n",
                encoding="utf-8",
            )
            result = map_tool.map_subsegments(
                jp, usa, yaml_path, block_size=16, step=16,
                search_window=16, min_anchors=1,
            )
            self.assertEqual(result["mapped_candidate_count"], 2)
            self.assertEqual(result["mapping_order_anomaly_count"], 1)

    def test_function_symbol_parser(self):
        symbol_text = """// ignored
foo = 0x00100000; // type:func
bar = 0x00100010; // type:func
data_value = 0x00100020; // type:s32
"""
        symbols = symbol_tool.parse_function_symbols(symbol_text)
        self.assertEqual(
            symbols,
            [
                {"name": "foo", "address": 0x00100000},
                {"name": "bar", "address": 0x00100010},
            ],
        )

    def test_function_symbol_mapper(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jp = root / "jp.elf"
            usa = root / "usa.elf"
            payload = bytes(range(32))
            make_elf(jp, payload)
            make_elf(usa, payload)
            symbols_path = root / "symbols.txt"
            symbols_path.write_text(
                "first = 0x00100000; // type:func\n"
                "second = 0x00100010; // type:func\n",
                encoding="utf-8",
            )
            result = symbol_tool.map_symbols(
                jp, usa, symbols_path, block_size=16, step=16,
                max_function_size=16, min_anchors=1,
            )
            self.assertEqual(result["function_symbol_count"], 2)
            self.assertEqual(result["status_counts"]["candidate"], 2)
            self.assertEqual(result["mapping_order_anomaly_count"], 0)
            self.assertEqual(
                result["symbols"][1]["candidates"][0]["usa_address_candidate"],
                "0x00100010",
            )

    def test_function_symbol_mapper_reports_order_anomaly(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jp = root / "jp.elf"
            usa = root / "usa.elf"
            payload = bytes(range(32))
            make_elf(jp, payload)
            make_elf(usa, payload[16:] + payload[:16])
            symbols_path = root / "symbols.txt"
            symbols_path.write_text(
                "first = 0x00100000; // type:func\n"
                "second = 0x00100010; // type:func\n",
                encoding="utf-8",
            )
            result = symbol_tool.map_symbols(
                jp, usa, symbols_path, block_size=16, step=16,
                max_function_size=16, min_anchors=1,
            )
            self.assertEqual(result["mapped_candidate_count"], 2)
            self.assertEqual(result["mapping_order_anomaly_count"], 1)

    def test_main_mapper_indexes_non_16_byte_aligned_subsegment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jp = root / "jp.elf"
            usa = root / "usa.elf"
            payload = bytes(range(32))
            make_elf(jp, payload)
            make_elf(usa, payload)
            yaml_path = root / "jp.yaml"
            yaml_path.write_text(
                "segments:\n- name: main\n  subsegments:\n"
                "  - [ 0x4, asm, unaligned_to_16 ]\n",
                encoding="utf-8",
            )
            result = map_tool.map_subsegments(
                jp, usa, yaml_path, block_size=16, step=16,
                search_window=16, min_anchors=1,
            )
            item = result["subsegments"][0]
            self.assertEqual(item["status"], "candidate")
            self.assertEqual(item["candidates"][0]["usa_start_candidate"], 4)

    def test_symbol_mapper_indexes_non_16_byte_aligned_function(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jp = root / "jp.elf"
            usa = root / "usa.elf"
            payload = bytes(range(32))
            make_elf(jp, payload)
            make_elf(usa, payload)
            symbols = root / "symbols.txt"
            symbols.write_text(
                "unaligned_func = 0x100004; // type:func\n",
                encoding="utf-8",
            )
            result = map_symbol_tool.map_symbols(
                jp, usa, symbols, block_size=16, step=16,
                max_function_size=16, min_anchors=1,
            )
            item = result["symbols"][0]
            self.assertEqual(item["status"], "candidate")
            self.assertEqual(item["candidates"][0]["usa_offset_candidate"], 4)

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
