#!/usr/bin/env python3
"""Find unique fixed-size matching blocks between two PS2 ELF main images.

The output is a coarse byte-correspondence map. It does not identify function
boundaries, distinguish code from data, or resolve MIPS relocations.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from collections import defaultdict
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


def main_image(data: bytes, report: dict[str, Any]):
    section = next((s for s in report["sections"] if s["name"] == "main"), None)
    if section is None:
        raise ValueError("ELF has no main section")
    start = section["file_offset"]
    end = start + section["size"]
    if start < 0 or end > len(data):
        raise ValueError("Main section extends beyond the ELF file")
    return data[start:end], section


def compare(jp_path: Path, usa_path: Path, chunk_size: int = 16, min_run: int = 64):
    if chunk_size < 4 or chunk_size % 4:
        raise ValueError("chunk_size must be a multiple of 4 and at least 4")
    if min_run < chunk_size:
        raise ValueError("min_run must be at least chunk_size")

    jp_data, usa_data = jp_path.read_bytes(), usa_path.read_bytes()
    jp_report, usa_report = inspect_elf(jp_path), inspect_elf(usa_path)
    jp_main, jp_section = main_image(jp_data, jp_report)
    usa_main, usa_section = main_image(usa_data, usa_report)

    usa_index = defaultdict(list)
    for offset in range(0, len(usa_main) - chunk_size + 1, chunk_size):
        block = usa_main[offset:offset + chunk_size]
        if len(set(block)) >= 4:
            usa_index[block].append(offset)

    jp_index = defaultdict(list)
    for offset in range(0, len(jp_main) - chunk_size + 1, chunk_size):
        block = jp_main[offset:offset + chunk_size]
        if len(set(block)) >= 4:
            jp_index[block].append(offset)

    pairs = []
    for block, jp_offsets in jp_index.items():
        usa_offsets = usa_index.get(block, [])
        if len(jp_offsets) == 1 and len(usa_offsets) == 1:
            pairs.append((jp_offsets[0], usa_offsets[0]))

    pairs.sort(key=lambda pair: (pair[0] - pair[1], pair[0]))
    ranges = []
    for jp_offset, usa_offset in pairs:
        delta = jp_offset - usa_offset
        if (
            ranges
            and ranges[-1]["delta"] == delta
            and ranges[-1]["jp_offset"] + ranges[-1]["size"] == jp_offset
            and ranges[-1]["usa_offset"] + ranges[-1]["size"] == usa_offset
        ):
            ranges[-1]["size"] += chunk_size
            ranges[-1]["blocks"] += 1
        else:
            ranges.append({
                "jp_offset": jp_offset,
                "usa_offset": usa_offset,
                "delta": delta,
                "size": chunk_size,
                "blocks": 1,
            })

    ranges = [r for r in ranges if r["size"] >= min_run]
    ranges.sort(key=lambda r: (-r["size"], r["jp_offset"]))
    for item in ranges:
        item["jp_ee_start"] = f"0x{jp_section['address'] + item['jp_offset']:08X}"
        item["usa_ee_start"] = f"0x{usa_section['address'] + item['usa_offset']:08X}"
        item["delta_hex"] = f"0x{item['delta']:X}"

    return {
        "jp_file": jp_path.name,
        "usa_file": usa_path.name,
        "jp_sha1": jp_report["sha1"],
        "usa_sha1": usa_report["sha1"],
        "chunk_size": chunk_size,
        "min_run": min_run,
        "unique_matching_blocks": len(pairs),
        "reported_ranges": len(ranges),
        "reported_matching_bytes": sum(r["size"] for r in ranges),
        "ranges": ranges,
        "warning": (
            "Candidate byte correspondences only. They may be code or data; "
            "they are not verified function boundaries or relocation-safe maps."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jp_elf", type=Path)
    parser.add_argument("usa_elf", type=Path)
    parser.add_argument("--chunk-size", type=int, default=16)
    parser.add_argument("--min-run", type=int, default=64)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    result = compare(args.jp_elf, args.usa_elf, args.chunk_size, args.min_run)
    rendered = json.dumps(result, indent=2)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
