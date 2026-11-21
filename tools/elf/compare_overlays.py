#!/usr/bin/env python3
"""Compare Sony DVP overlays between two PS2 ELF32/MIPS executables.

The overlay table stores load addresses, while overlay section headers provide
payload lengths. Payload bytes are read from the main load image at the overlay
EE address. The overlay section's own file range is metadata, not the payload.

This is a binary comparison aid: matching byte ranges do not prove semantic
or function-level equivalence.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any


def load_inspector():
    path = Path(__file__).with_name("inspect.py")
    spec = importlib.util.spec_from_file_location("kh1_elf_inspect", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load ELF inspector: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.inspect


inspect_elf = load_inspector()


def overlay_payload(data: bytes, report: dict[str, Any], overlay: dict[str, Any]):
    sections = {section["name"]: section for section in report["sections"]}
    main = sections.get("main")
    section = sections.get(overlay["section_name"])
    if main is None or section is None:
        raise ValueError(f"Overlay {overlay['index']} has no main/metadata section")

    address = overlay["ee_address"]
    start = main["file_offset"] + address - main["address"]
    end = start + section["size"]
    main_end = main["file_offset"] + main["size"]
    if address < main["address"] or end > main_end or end > len(data):
        raise ValueError(
            f"Overlay {overlay['index']} payload range {start:#x}:{end:#x} "
            "is outside the main load image"
        )
    return data[start:end], start, section["size"]


def compare(jp_path: Path, usa_path: Path, min_block: int = 16):
    jp_data = jp_path.read_bytes()
    usa_data = usa_path.read_bytes()
    jp = inspect_elf(jp_path)
    usa = inspect_elf(usa_path)

    if jp["dvp_overlay_count"] != usa["dvp_overlay_count"]:
        raise ValueError(
            f"Overlay counts differ: {jp['dvp_overlay_count']} vs "
            f"{usa['dvp_overlay_count']}"
        )

    results = []
    for jp_overlay, usa_overlay in zip(jp["dvp_overlays"], usa["dvp_overlays"]):
        if jp_overlay["index"] != usa_overlay["index"]:
            raise ValueError("Overlay table order differs")

        jp_bytes, jp_file_offset, jp_size = overlay_payload(jp_data, jp, jp_overlay)
        usa_bytes, usa_file_offset, usa_size = overlay_payload(
            usa_data, usa, usa_overlay
        )
        matcher = difflib.SequenceMatcher(None, jp_bytes, usa_bytes, autojunk=False)
        blocks = [
            {"jp_offset": block.a, "usa_offset": block.b, "size": block.size}
            for block in matcher.get_matching_blocks()
            if block.size >= min_block
        ]
        matched_bytes = sum(block["size"] for block in blocks)
        denominator = max(jp_size, usa_size, 1)

        results.append({
            "index": jp_overlay["index"],
            "jp_address": f"0x{jp_overlay['ee_address']:08X}",
            "usa_address": f"0x{usa_overlay['ee_address']:08X}",
            "jp_file_offset": f"0x{jp_file_offset:X}",
            "usa_file_offset": f"0x{usa_file_offset:X}",
            "jp_size": jp_size,
            "usa_size": usa_size,
            "exact_match": jp_bytes == usa_bytes,
            "matched_bytes_in_blocks": matched_bytes,
            "similarity_lower_bound": round(matched_bytes / denominator, 6),
            "jp_sha1": hashlib.sha1(jp_bytes).hexdigest(),
            "usa_sha1": hashlib.sha1(usa_bytes).hexdigest(),
            "matching_blocks": blocks,
        })

    exact_count = sum(item["exact_match"] for item in results)
    return {
        "jp_file": jp_path.name,
        "usa_file": usa_path.name,
        "jp_sha1": jp["sha1"],
        "usa_sha1": usa["sha1"],
        "jp_entry_point": f"0x{jp['elf']['entry_point']:08X}",
        "usa_entry_point": f"0x{usa['elf']['entry_point']:08X}",
        "overlay_count": len(results),
        "exact_overlay_count": exact_count,
        "different_overlay_count": len(results) - exact_count,
        "overlays": results,
        "notes": [
            "Payloads are read from the main load image using the overlay EE address.",
            "Similarity sums non-overlapping SequenceMatcher matching blocks.",
            "Matching blocks are byte correspondences, not verified function boundaries.",
            "Only exact overlays justify direct offset-for-offset byte mapping.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jp_elf", type=Path, help="Japanese ELF executable")
    parser.add_argument("usa_elf", type=Path, help="USA ELF executable")
    parser.add_argument("-o", "--output", type=Path, help="Write JSON report")
    parser.add_argument(
        "--min-block", type=int, default=16,
        help="Minimum matching block length to include (default: 16)",
    )
    args = parser.parse_args()
    if args.min_block < 1:
        parser.error("--min-block must be positive")

    result = compare(args.jp_elf, args.usa_elf, args.min_block)
    rendered = json.dumps(result, indent=2)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
