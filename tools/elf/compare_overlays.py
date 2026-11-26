#!/usr/bin/env python3
"""Compare Sony DVP overlay payloads in two PS2 ELF32/MIPS executables.

In these KH1 ELF files, .DVP.overlay.* sections are linker fill markers.
Their sizes describe the corresponding overlay payloads, whose bytes are
stored in the main load image at the EE address from .DVP.ovlytab.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any


BRANCH_OPS = {0x20, 0x21, 0x28, 0x29, 0x2C, 0x2D, 0x2E, 0x2F}


def load_inspector():
    path = Path(__file__).with_name("elf_inspect.py")
    spec = importlib.util.spec_from_file_location("kh1_elf_inspect", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load ELF inspector: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.inspect


inspect_elf = load_inspector()


def get_payload(data: bytes, report: dict[str, Any], overlay: dict[str, Any]):
    sections = {section["name"]: section for section in report["sections"]}
    main = sections.get("main")
    marker = sections.get(overlay["section_name"])
    if main is None or marker is None:
        raise ValueError(f"Overlay {overlay['index']} has no main/marker section")

    address = overlay["ee_address"]
    start = main["file_offset"] + address - main["address"]
    end = start + marker["size"]
    main_end = main["file_offset"] + main["size"]
    marker_end = marker["file_offset"] + marker["size"]
    if address < main["address"] or end > main_end or end > len(data):
        raise ValueError(f"Overlay {overlay['index']} range is outside main image")
    if marker["file_offset"] < 0 or marker_end > len(data):
        raise ValueError(f"Overlay {overlay['index']} marker section is outside file")

    payload = data[start:end]
    if len(payload) % 8:
        raise ValueError(f"Overlay {overlay['index']} is not 8-byte aligned")
    marker_data = data[marker["file_offset"]:marker_end]
    return payload, start, sorted(set(marker_data))


def signed_imm11(word: int) -> int:
    value = word & 0x7FF
    return value - 0x800 if value & 0x400 else value


def pair_statistics(jp_payload: bytes, usa_payload: bytes) -> dict[str, Any]:
    if len(jp_payload) != len(usa_payload):
        return {
            "same_size": False,
            "aligned_matching_pairs": None,
            "exact_pairs": None,
            "branch_displacement_only_changes": None,
            "other_changed_pairs": None,
            "pairs_equal_after_branch_mask": None,
            "branch_changes": [],
        }

    exact = branch_only = other = normalized_equal = 0
    branch_changes = []
    for pair_index in range(len(jp_payload) // 8):
        offset = pair_index * 8
        jp_lower = int.from_bytes(jp_payload[offset:offset + 4], "little")
        jp_upper = int.from_bytes(jp_payload[offset + 4:offset + 8], "little")
        usa_lower = int.from_bytes(usa_payload[offset:offset + 4], "little")
        usa_upper = int.from_bytes(usa_payload[offset + 4:offset + 8], "little")

        if jp_lower == usa_lower and jp_upper == usa_upper:
            exact += 1
            normalized_equal += 1
            continue

        jp_op = (jp_lower >> 25) & 0x7F
        usa_op = (usa_lower >> 25) & 0x7F
        is_branch_only = (
            not (jp_upper & (1 << 31))
            and not (usa_upper & (1 << 31))
            and jp_op in BRANCH_OPS
            and jp_op == usa_op
            and jp_upper == usa_upper
            and (jp_lower & ~0x7FF) == (usa_lower & ~0x7FF)
        )
        if is_branch_only:
            branch_only += 1
            normalized_equal += 1
            branch_changes.append({
                "pair_index": pair_index,
                "jp_imm11": signed_imm11(jp_lower),
                "usa_imm11": signed_imm11(usa_lower),
                "jp_target_pair": pair_index + 1 + signed_imm11(jp_lower),
                "usa_target_pair": pair_index + 1 + signed_imm11(usa_lower),
            })
        else:
            other += 1

    return {
        "same_size": True,
        "pair_count": len(jp_payload) // 8,
        "exact_pairs": exact,
        "branch_displacement_only_changes": branch_only,
        "other_changed_pairs": other,
        "pairs_equal_after_branch_mask": normalized_equal,
        "branch_changes": branch_changes,
    }


def compare(jp_path: Path, usa_path: Path, min_block: int = 16) -> dict[str, Any]:
    if min_block < 1:
        raise ValueError("min_block must be positive")
    jp_data, usa_data = jp_path.read_bytes(), usa_path.read_bytes()
    jp, usa = inspect_elf(jp_path), inspect_elf(usa_path)
    if jp["dvp_overlay_count"] != usa["dvp_overlay_count"]:
        raise ValueError("DVP overlay table counts differ")

    rows = []
    for jo, uo in zip(jp["dvp_overlays"], usa["dvp_overlays"]):
        if jo["index"] != uo["index"]:
            raise ValueError("DVP overlay table order differs")
        jp_payload, jp_off, jp_fill = get_payload(jp_data, jp, jo)
        usa_payload, usa_off, usa_fill = get_payload(usa_data, usa, uo)

        matcher = difflib.SequenceMatcher(None, jp_payload, usa_payload, autojunk=False)
        blocks = [
            {"jp_offset": b.a, "usa_offset": b.b, "size": b.size}
            for b in matcher.get_matching_blocks()
            if b.size >= min_block
        ]
        matched = sum(b["size"] for b in blocks)
        denom = max(len(jp_payload), len(usa_payload), 1)
        rows.append({
            "index": jo["index"],
            "jp_section": jo["section_name"],
            "usa_section": uo["section_name"],
            "jp_ee_address": f"0x{jo['ee_address']:08X}",
            "usa_ee_address": f"0x{uo['ee_address']:08X}",
            "jp_vu_address": f"0x{jo['vu_address']:08X}",
            "usa_vu_address": f"0x{uo['vu_address']:08X}",
            "jp_file_offset": f"0x{jp_off:X}",
            "usa_file_offset": f"0x{usa_off:X}",
            "jp_size": len(jp_payload),
            "usa_size": len(usa_payload),
            "exact_payload_match": jp_payload == usa_payload,
            "matching_bytes": matched,
            "similarity_lower_bound": round(matched / denom, 6),
            "jp_payload_sha1": hashlib.sha1(jp_payload).hexdigest(),
            "usa_payload_sha1": hashlib.sha1(usa_payload).hexdigest(),
            "jp_marker_fill": [f"0x{x:02X}" for x in jp_fill],
            "usa_marker_fill": [f"0x{x:02X}" for x in usa_fill],
            "vu_pair_statistics": pair_statistics(jp_payload, usa_payload),
            "matching_blocks": blocks,
        })

    return {
        "jp_file": jp_path.name,
        "usa_file": usa_path.name,
        "jp_sha1": jp["sha1"],
        "usa_sha1": usa["sha1"],
        "jp_entry_point": f"0x{jp['elf']['entry_point']:08X}",
        "usa_entry_point": f"0x{usa['elf']['entry_point']:08X}",
        "overlay_count": len(rows),
        "exact_payload_match_count": sum(r["exact_payload_match"] for r in rows),
        "different_payload_count": sum(not r["exact_payload_match"] for r in rows),
        "overlay_rows": rows,
        "method": [
            "The .DVP.overlay.* section size is used as the overlay payload length.",
            "Payload bytes are read from the main load image at the EE address in .DVP.ovlytab.",
            "The .DVP.overlay.* section bytes themselves are linker fill markers, not payload.",
            "VU payloads are checked as 8-byte instruction pairs.",
            "Branch-only changes are detected by masking the lower instruction's signed 11-bit branch displacement.",
            "Matching byte ranges are candidates for correspondence, not verified function boundaries.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jp_elf", type=Path)
    parser.add_argument("usa_elf", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--min-block", type=int, default=16)
    args = parser.parse_args()
    result = compare(args.jp_elf, args.usa_elf, args.min_block)
    rendered = json.dumps(result, indent=2)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
