#!/usr/bin/env python3
"""Compare Sony DVP overlay payloads in two PS2 ELF32/MIPS executables.

In these KH1 ELF files, .DVP.overlay.* sections are linker fill markers.
Their sizes describe the corresponding overlay payloads, whose bytes are
stored in the main load image at the EE address from .DVP.ovlytab.

The tool validates that each range is inside the main image, then compares
the extracted payloads. Matching bytes are binary correspondences, not
automatically verified function boundaries.
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
    if address < main["address"] or end > main_end or end > len(data):
        raise ValueError(
            f"Overlay {overlay['index']} range {start:#x}:{end:#x} "
            "is outside the main load image"
        )
    payload = data[start:end]
    if len(payload) % 8:
        raise ValueError(
            f"Overlay {overlay['index']} payload size {len(payload)} "
            "is not a multiple of an 8-byte VU instruction pair"
        )
    marker_data = data[marker["file_offset"]:marker["file_offset"] + marker["size"]]
    fill_values = sorted(set(marker_data))
    return payload, start, marker, fill_values


def compare(jp_path: Path, usa_path: Path, min_block: int = 16) -> dict[str, Any]:
    jp_data, usa_data = jp_path.read_bytes(), usa_path.read_bytes()
    jp, usa = inspect_elf(jp_path), inspect_elf(usa_path)
    if jp["dvp_overlay_count"] != usa["dvp_overlay_count"]:
        raise ValueError("DVP overlay table counts differ")

    rows = []
    for jo, uo in zip(jp["dvp_overlays"], usa["dvp_overlays"]):
        if jo["index"] != uo["index"]:
            raise ValueError("DVP overlay table order differs")
        jp_payload, jp_off, jp_marker, jp_fill = get_payload(jp_data, jp, jo)
        usa_payload, usa_off, usa_marker, usa_fill = get_payload(usa_data, usa, uo)

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
            "Matching byte ranges are candidates for code correspondence, not verified function boundaries.",
            "VU instruction pairs are 8 bytes; this tool validates payload alignment but does not disassemble them.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jp_elf", type=Path)
    parser.add_argument("usa_elf", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--min-block", type=int, default=16)
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
