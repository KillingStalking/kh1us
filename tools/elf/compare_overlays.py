#!/usr/bin/env python3
"""Compare Sony DVP overlay metadata in two PS2 ELF32/MIPS executables.

Important: DVP overlay sections in the inspected KH1 executables contain
constant fill bytes, not executable VU microcode. This tool therefore compares
overlay table metadata and section fill patterns only. It does not infer
microprogram contents or function/address mappings.
"""
from __future__ import annotations

import argparse
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


def section_fill(data: bytes, section: dict[str, Any]) -> dict[str, Any]:
    start = section["file_offset"]
    end = start + section["size"]
    if start < 0 or end > len(data):
        raise ValueError(f"Section {section['name']} extends beyond file")
    payload = data[start:end]
    unique = sorted(set(payload))
    return {
        "size": len(payload),
        "sha1": hashlib.sha1(payload).hexdigest(),
        "uniform_fill": len(unique) <= 1,
        "fill_byte": f"0x{unique[0]:02X}" if len(unique) == 1 else None,
        "unique_byte_count": len(unique),
    }


def compare(jp_path: Path, usa_path: Path) -> dict[str, Any]:
    jp_data, usa_data = jp_path.read_bytes(), usa_path.read_bytes()
    jp, usa = inspect_elf(jp_path), inspect_elf(usa_path)
    if jp["dvp_overlay_count"] != usa["dvp_overlay_count"]:
        raise ValueError("DVP overlay table counts differ")

    jp_sections = {s["name"]: s for s in jp["sections"]}
    usa_sections = {s["name"]: s for s in usa["sections"]}
    rows = []
    for jo, uo in zip(jp["dvp_overlays"], usa["dvp_overlays"]):
        js, us = jp_sections.get(jo["section_name"]), usa_sections.get(uo["section_name"])
        if js is None or us is None:
            raise ValueError(f"Missing section for overlay index {jo['index']}")
        jf, uf = section_fill(jp_data, js), section_fill(usa_data, us)
        rows.append({
            "index": jo["index"],
            "jp_section": jo["section_name"],
            "usa_section": uo["section_name"],
            "jp_ee_address": f"0x{jo['ee_address']:08X}",
            "usa_ee_address": f"0x{uo['ee_address']:08X}",
            "jp_vu_address": f"0x{jo['vu_address']:08X}",
            "usa_vu_address": f"0x{uo['vu_address']:08X}",
            "ee_address_equal": jo["ee_address"] == uo["ee_address"],
            "vu_address_equal": jo["vu_address"] == uo["vu_address"],
            "section_size_equal": jf["size"] == uf["size"],
            "section_bytes_equal": jf["sha1"] == uf["sha1"] and jf["size"] == uf["size"],
            "jp_section_fill": jf,
            "usa_section_fill": uf,
        })

    return {
        "jp_file": jp_path.name,
        "usa_file": usa_path.name,
        "jp_sha1": jp["sha1"],
        "usa_sha1": usa["sha1"],
        "jp_entry_point": f"0x{jp['elf']['entry_point']:08X}",
        "usa_entry_point": f"0x{usa['elf']['entry_point']:08X}",
        "jp_main_section": next(
            {"address": f"0x{s['address']:08X}", "size": s["size"]}
            for s in jp["sections"] if s["name"] == "main"
        ),
        "usa_main_section": next(
            {"address": f"0x{s['address']:08X}", "size": s["size"]}
            for s in usa["sections"] if s["name"] == "main"
        ),
        "overlay_count": len(rows),
        "same_section_bytes_count": sum(r["section_bytes_equal"] for r in rows),
        "overlay_rows": rows,
        "interpretation": [
            "DVP overlay section bytes are metadata/fill patterns in these inputs, not VU microcode.",
            "EE/VU addresses and section sizes are metadata and require loader/linker analysis.",
            "Matching fill patterns do not establish matching executable code.",
            "This report must not be used as a JP-to-USA function address map.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jp_elf", type=Path)
    parser.add_argument("usa_elf", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    result = compare(args.jp_elf, args.usa_elf)
    rendered = json.dumps(result, indent=2)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
