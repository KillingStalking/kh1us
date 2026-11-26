#!/usr/bin/env python3
"""Validate known JP->USA KH1 function clusters at MIPS control-flow level.

This is a version-pinned audit helper for the supplied JP and USA ELF files.
It checks instruction/register signatures and translates every direct branch,
jump, and call target using the locally established address-map ranges.
It does not prove whole-program equivalence or generate a USA symbol map.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import struct
from pathlib import Path
from typing import Any


EXPECTED_JP_SHA1 = "9dabbf867a7ec2a030df99ba1ed969f2deef0488"
EXPECTED_USA_SHA1 = "8704cda65ca5e3f04202f0a50472401355335312"

# Offsets are relative to the main section; sizes end at the next JP symbol.
FUNCTIONS = [
    ("pppPoint", 0x852E0, 0x82B80, 0x90),
    ("pppPointCon", 0x85370, 0x82C10, 0x28),
    ("pppMove", 0x85398, 0x82C38, 0xD0),
    ("pppMoveCon", 0x85468, 0x82D08, 0x28),
    ("pppAcceleCalc", 0x85490, 0x82D30, 0xD0),
    ("pppAcceleCon", 0x85560, 0x82E00, 0x28),
    ("worldfile_getAbbr", 0x11F40, 0x11E80, 0x28),
    ("worldfile_getNameNoSet", 0x11F68, 0x11EA8, 0x88),
    ("worldfile_getNames", 0x11FF0, 0x11F30, 0xE0),
    ("worldfile_getBinImgName", 0x120D0, 0x12010, 0x98),
    ("sprintf", 0x14D8A0, 0x14B388, 0x90),
    ("strcat", 0x14D930, 0x14B418, 0x12C),
    ("strcpy", 0x14DBA0, 0x14B688, 0x114),
]

# EE virtual-address ranges, ordered by the address space they describe.
TARGET_MAPS = [
    {"name": "PPP code", "start": 0x185000, "end": 0x186000, "delta": 0x2760},
    {"name": "worldfile code", "start": 0x111000, "end": 0x113000, "delta": 0xC0},
    {"name": "EE library", "start": 0x24D000, "end": 0x250000, "delta": 0x2518},
]


def load_inspector():
    path = Path(__file__).with_name("inspect.py")
    spec = importlib.util.spec_from_file_location("kh1_cf_elf_inspect", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load ELF inspector: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.inspect


inspect_elf = load_inspector()


def get_main_image(path: Path):
    data = path.read_bytes()
    report = inspect_elf(path)
    section = next((item for item in report["sections"] if item["name"] == "main"), None)
    if section is None:
        raise ValueError(f"{path}: ELF has no main section")
    start = section["file_offset"]
    end = start + section["size"]
    if start < 0 or end > len(data):
        raise ValueError(f"{path}: main section extends beyond file")
    return data[start:end], section, report


def instruction_signature(word: int) -> int:
    """Keep operation and register fields; ignore immediate/address operands."""
    opcode = word >> 26
    if opcode == 0:  # SPECIAL: retain all R-format fields and funct.
        return word
    if opcode in (2, 3):  # J/JAL: retain operation, ignore target field.
        return word & 0xFC000000
    return word & 0xFFFF0000  # I-format operation + rs/rt.


def decode_control_flow(data: bytes, base_address: int = 0, start: int = 0, size: int | None = None):
    """Return direct branches/jumps/calls and indirect JR/JALR instructions."""
    if size is None:
        size = len(data) - start
    if start < 0 or size < 0 or start + size > len(data) or size % 4:
        raise ValueError("Control-flow range must be in-bounds and word-aligned")
    result = []
    for offset in range(start, start + size, 4):
        word = struct.unpack_from("<I", data, offset)[0]
        opcode, funct = word >> 26, word & 0x3F
        pc = base_address + offset
        kind, target = None, None
        if opcode in (1, 4, 5, 6, 7, 20, 21, 22, 23):
            immediate = word & 0xFFFF
            if immediate & 0x8000:
                immediate -= 0x10000
            kind = "branch"
            target = (pc + 4 + (immediate << 2)) & 0xFFFFFFFF
        elif opcode in (2, 3):
            kind = "jump" if opcode == 2 else "call"
            target = (((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)) & 0xFFFFFFFF
        elif opcode == 0 and funct in (8, 9):
            kind = "jr" if funct == 8 else "jalr"
        if kind:
            result.append({
                "offset": offset - start,
                    "kind": kind,
                "signature": instruction_signature(word),
                "target": target,
            })
    return result


def translate_target(address: int):
    for item in TARGET_MAPS:
        if item["start"] <= address < item["end"]:
            return address - item["delta"], item["name"]
    return None, None




def build_control_flow_graph(functions: list[dict[str, Any]], base_address: int):
    """Build conservative direct-edge and indirect-transfer inventories."""
    extents = []
    for function in functions:
        start = int(function["usa_offset"], 16) + base_address
        extents.append((start, start + function["size"], function["name"]))

    direct_edges = []
    call_edges = []
    indirect_transfers = []
    for function in functions:
        for edge in function["target_checks"]:
            target = int(edge["usa_target"], 16) if edge["usa_target"] else None
            target_function = None
            if target is not None and edge["matches"]:
                # Prefer an exact function entry point over an enclosing
                # function extent (e.g. a nested/overlapping candidate).
                exact = [entry for entry in extents if entry[0] == target]
                containing = [
                    entry for entry in extents if entry[0] <= target < entry[1]
                ]
                selected = exact or sorted(
                    containing, key=lambda entry: (entry[1] - entry[0], entry[0])
                )
                target_function = selected[0][2] if selected else None
            record = {
                "source_function": function["name"],
                "source_usa": edge["usa_source"],
                "kind": edge["kind"],
                "target_jp": edge["jp_target"],
                "target_usa": edge["usa_target"],
                "mapped_region": edge["map"],
                "target_function": target_function,
                "validated_translation": edge["matches"],
            }
            direct_edges.append(record)
            if edge["kind"] == "call":
                call_edges.append(record)
        indirect_transfers.extend(function["indirect_transfers"])

    return {
        "direct_edge_count": len(direct_edges),
        "direct_edges": direct_edges,
        "direct_call_count": len(call_edges),
        "direct_call_edges": call_edges,
        "indirect_transfer_count": len(indirect_transfers),
        "indirect_transfers": indirect_transfers,
        "warning": (
            "A JAL edge is a direct call instruction, not proof that its target "
            "is a recovered function. J/JR/JALR may be tail transfers, returns, "
            "or dispatch; indirect targets are intentionally unresolved."
        ),
    }


def validate(jp_path: Path, usa_path: Path):
    jp_main, jp_section, jp_report = get_main_image(jp_path)
    usa_main, usa_section, usa_report = get_main_image(usa_path)
    if jp_report["sha1"] != EXPECTED_JP_SHA1:
        raise ValueError("JP ELF SHA-1 does not match the audited executable")
    if usa_report["sha1"] != EXPECTED_USA_SHA1:
        raise ValueError("USA ELF SHA-1 does not match the audited executable")
    if jp_section["address"] != usa_section["address"]:
        raise ValueError("JP and USA main sections have different VMAs")

    functions = []
    for name, jp_offset, usa_offset, size in FUNCTIONS:
        if jp_offset + size > len(jp_main) or usa_offset + size > len(usa_main):
            raise ValueError(f"{name}: function range is outside main image")
        jp_bytes = jp_main[jp_offset:jp_offset + size]
        usa_bytes = usa_main[usa_offset:usa_offset + size]
        jp_words = [struct.unpack_from("<I", jp_bytes, i)[0] for i in range(0, size, 4)]
        usa_words = [struct.unpack_from("<I", usa_bytes, i)[0] for i in range(0, size, 4)]
        signature_matches = sum(
            instruction_signature(a) == instruction_signature(b)
            for a, b in zip(jp_words, usa_words)
        )
        jp_cf = decode_control_flow(jp_main, jp_section["address"], jp_offset, size)
        usa_cf = decode_control_flow(usa_main, usa_section["address"], usa_offset, size)
        layout_matches = (
            len(jp_cf) == len(usa_cf)
            and all(
                (a["offset"], a["kind"], a["signature"])
                == (b["offset"], b["kind"], b["signature"])
                for a, b in zip(jp_cf, usa_cf)
            )
        )
        target_checks = []
        indirect_transfers = []
        if layout_matches:
            for jp_item, usa_item in zip(jp_cf, usa_cf):
                if jp_item["target"] is None:
                    if jp_item["kind"] in ("jr", "jalr"):
                        indirect_transfers.append({
                            "source_function": name,
                            "source_jp": f"0x{jp_section['address'] + jp_offset + jp_item['offset']:08X}",
                            "source_usa": f"0x{usa_section['address'] + usa_offset + usa_item['offset']:08X}",
                            "kind": jp_item["kind"],
                            "target": None,
                            "resolution": "unresolved_indirect",
                        })
                    continue
                expected, map_name = translate_target(jp_item["target"])
                target_checks.append({
                    "offset": f"0x{jp_item['offset']:X}",
                    "source_jp": f"0x{jp_section['address'] + jp_offset + jp_item['offset']:08X}",
                    "source_usa": f"0x{usa_section['address'] + usa_offset + usa_item['offset']:08X}",
                    "kind": jp_item["kind"],
                    "jp_target": f"0x{jp_item['target']:08X}",
                    "usa_target": (
                        f"0x{usa_item['target']:08X}"
                        if usa_item["target"] is not None else None
                    ),
                    "map": map_name,
                    "expected_usa_target": f"0x{expected:08X}" if expected is not None else None,
                    "matches": expected is not None and expected == usa_item["target"],
                })
        functions.append({
            "name": name,
            "jp_offset": f"0x{jp_offset:X}",
            "usa_offset": f"0x{usa_offset:X}",
            "size": size,
            "byte_equal": sum(a == b for a, b in zip(jp_bytes, usa_bytes)),
            "instruction_words": len(jp_words),
            "instruction_signature_matches": signature_matches,
            "jp_control_flow_count": len(jp_cf),
            "usa_control_flow_count": len(usa_cf),
            "control_flow_layout_matches": layout_matches,
            "direct_target_count": len(target_checks),
            "translated_target_matches": sum(item["matches"] for item in target_checks),
            "unmapped_or_mismatched_targets": [
                item for item in target_checks if not item["matches"]
            ],
            "target_checks": target_checks,
            "indirect_transfers": indirect_transfers,
            "target_validation_blocked": not layout_matches,
        })

    total_words = sum(item["instruction_words"] for item in functions)
    total_matches = sum(item["instruction_signature_matches"] for item in functions)
    total_cf = sum(item["jp_control_flow_count"] for item in functions)
    total_direct = sum(item["direct_target_count"] for item in functions)
    total_target_matches = sum(item["translated_target_matches"] for item in functions)
    graph = build_control_flow_graph(functions, usa_section["address"])
    return {
        "jp_sha1": jp_report["sha1"],
        "usa_sha1": usa_report["sha1"],
        "function_count": len(functions),
        "instruction_words": total_words,
        "instruction_signature_matches": total_matches,
        "jp_control_flow_instructions": total_cf,
        "direct_targets": total_direct,
        "translated_direct_targets_matched": total_target_matches,
        "functions": functions,
        "control_flow_graph": graph,
        "address_maps": TARGET_MAPS,
        "warning": (
            "This validates only the listed function clusters and direct control-flow "
            "targets. It is not a complete USA symbol map or proof of whole-program equivalence."
        ),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jp_elf", type=Path)
    parser.add_argument("usa_elf", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    result = validate(args.jp_elf, args.usa_elf)
    rendered = json.dumps(result, indent=2)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
