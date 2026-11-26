#!/usr/bin/env python3
"""Map JP Splat main-image subsegments to USA using unique byte anchors.

This is a conservative candidate mapper, not a function matcher. It never
rewrites the USA YAML. A boundary is proposed only when multiple unique
16-byte anchors inside the JP subsegment agree on one JP-to-USA offset delta.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


SUBSEGMENT_RE = re.compile(
    r"^\s{2}-\s*\[\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*"
    r"([^,\]]+?)(?:\s*,\s*([^\]]+?))?\s*\]"
)


def load_inspector():
    path = Path(__file__).with_name("elf_inspect.py")
    spec = importlib.util.spec_from_file_location("kh1_elf_inspect", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load ELF inspector: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.inspect


inspect_elf = load_inspector()


def parse_main_subsegments(yaml_text: str) -> list[dict[str, Any]]:
    """Read the explicitly declared subsegments under the top-level main entry."""
    lines = yaml_text.splitlines()
    main_index = next(
        (i for i, line in enumerate(lines) if re.match(r"^-\s+name:\s*main\s*$", line)),
        None,
    )
    if main_index is None:
        raise ValueError("JP YAML has no top-level 'main' segment")

    in_subsegments = False
    entries: list[dict[str, Any]] = []
    for line in lines[main_index + 1:]:
        if line and not line[0].isspace() and line.startswith("- "):
            break
        if re.match(r"^\s{2}subsegments:\s*$", line):
            in_subsegments = True
            continue
        if not in_subsegments:
            continue
        match = SUBSEGMENT_RE.match(line)
        if not match:
            continue
        raw_offset, raw_type, raw_name = match.groups()
        segment_type = raw_type.strip()
        name = raw_name.strip() if raw_name else ""
        entries.append({
            "jp_offset": int(raw_offset, 0),
            "type": segment_type,
            "name": name,
        })

    if not entries:
        raise ValueError("No main subsegments parsed from JP YAML")
    entries.sort(key=lambda item: item["jp_offset"])
    for index, entry in enumerate(entries):
        next_offset = (
            entries[index + 1]["jp_offset"]
            if index + 1 < len(entries)
            else None
        )
        entry["jp_end"] = next_offset
        entry["jp_size"] = (
            next_offset - entry["jp_offset"] if next_offset is not None else None
        )
    return entries


def get_main_image(data: bytes, report: dict[str, Any]):
    section = next((s for s in report["sections"] if s["name"] == "main"), None)
    if section is None:
        raise ValueError("ELF has no main section")
    start = section["file_offset"]
    end = start + section["size"]
    if start < 0 or end > len(data):
        raise ValueError("Main section extends beyond ELF file")
    return data[start:end], section


def unique_block_index(data: bytes, block_size: int, index_step: int = 4):
    """Index anchors on every aligned 32-bit word boundary.

    The candidate scan may begin at any 4-byte-aligned offset. Indexing only
    at the anchor sampling step (normally 16 bytes) silently misses functions
    and subsegments whose starts have a different alignment modulo 16.
    """
    occurrences: dict[bytes, list[int]] = defaultdict(list)
    for offset in range(0, len(data) - block_size + 1, index_step):
        block = data[offset:offset + block_size]
        if len(set(block)) >= 4:
            occurrences[block].append(offset)
    return occurrences


def map_subsegments(
    jp_elf: Path,
    usa_elf: Path,
    jp_yaml: Path,
    block_size: int = 16,
    step: int = 16,
    search_window: int = 0x1000,
    min_anchors: int = 2,
):
    if block_size < 8 or block_size % 4:
        raise ValueError("block_size must be a multiple of 4 and at least 8")
    if step < block_size or step % 4:
        raise ValueError("step must be a multiple of 4 and >= block_size")
    if search_window < block_size:
        raise ValueError("search_window must be >= block_size")
    if min_anchors < 1:
        raise ValueError("min_anchors must be positive")

    jp_bytes, usa_bytes = jp_elf.read_bytes(), usa_elf.read_bytes()
    jp_report, usa_report = inspect_elf(jp_elf), inspect_elf(usa_elf)
    jp_main, jp_section = get_main_image(jp_bytes, jp_report)
    usa_main, usa_section = get_main_image(usa_bytes, usa_report)
    entries = parse_main_subsegments(jp_yaml.read_text(encoding="utf-8"))

    jp_index = unique_block_index(jp_main, block_size)
    usa_index = unique_block_index(usa_main, block_size)
    output = []

    for entry in entries:
        start = entry["jp_offset"]
        end = entry["jp_end"] if entry["jp_end"] is not None else len(jp_main)
        if start >= len(jp_main) or end > len(jp_main) or end <= start:
            entry_result = {**entry, "status": "out_of_range", "candidates": []}
            output.append(entry_result)
            continue

        scan_end = min(end, start + search_window)
        votes = Counter()
        anchors_by_delta: dict[int, list[dict[str, int]]] = defaultdict(list)
        for jp_offset in range(start, scan_end - block_size + 1, step):
            block = jp_main[jp_offset:jp_offset + block_size]
            jp_hits = jp_index.get(block, [])
            usa_hits = usa_index.get(block, [])
            if len(jp_hits) != 1 or len(usa_hits) != 1:
                continue
            usa_offset = usa_hits[0]
            delta = jp_offset - usa_offset
            votes[delta] += 1
            anchors_by_delta[delta].append({
                "jp_offset": jp_offset,
                "usa_offset": usa_offset,
            })

        ranked = votes.most_common(3)
        candidates = []
        for delta, count in ranked:
            mapped_start = start - delta
            candidates.append({
                "delta": delta,
                "delta_hex": f"0x{delta:X}",
                "usa_start_candidate": mapped_start,
                "usa_start_hex": f"0x{mapped_start:X}" if mapped_start >= 0 else None,
                "anchor_count": count,
                "anchors": anchors_by_delta[delta],
            })

        if not ranked:
            status = "unmatched"
        elif ranked[0][1] < min_anchors:
            status = "weak_single_anchor"
        elif len(ranked) > 1 and ranked[0][1] == ranked[1][1]:
            status = "ambiguous"
        elif ranked[0][1] >= 3:
            status = "candidate_strong"
        else:
            status = "candidate"
        if ranked and not (0 <= start - ranked[0][0] < len(usa_main)):
            status = "candidate_out_of_range"

        output.append({
            **entry,
            "jp_ee_start": f"0x{jp_section['address'] + start:08X}",
            "jp_ee_end": f"0x{jp_section['address'] + end:08X}",
            "status": status,
            "candidates": candidates,
        })

    mapped_candidates = []
    for item in output:
        if item["status"] not in ("candidate", "candidate_strong"):
            continue
        if not item["candidates"]:
            continue
        candidate = item["candidates"][0]
        usa_start = candidate["usa_start_candidate"]
        if 0 <= usa_start < len(usa_main):
            mapped_candidates.append({
                "jp_offset": item["jp_offset"],
                "usa_offset": usa_start,
                "delta": candidate["delta"],
                "anchor_count": candidate["anchor_count"],
            })

    ordering_anomalies = []
    for previous, current in zip(mapped_candidates, mapped_candidates[1:]):
        if current["usa_offset"] <= previous["usa_offset"]:
            ordering_anomalies.append({
                "previous": previous,
                "current": current,
            })

    return {
        "jp_elf": jp_elf.name,
        "usa_elf": usa_elf.name,
        "jp_yaml": jp_yaml.name,
        "jp_sha1": jp_report["sha1"],
        "usa_sha1": usa_report["sha1"],
        "block_size": block_size,
        "step": step,
        "search_window": search_window,
        "min_anchors": min_anchors,
        "jp_main_size": len(jp_main),
        "usa_main_size": len(usa_main),
        "subsegment_count": len(output),
        "status_counts": dict(Counter(item["status"] for item in output)),
        "mapped_candidate_count": len(mapped_candidates),
        "mapping_order_anomaly_count": len(ordering_anomalies),
        "mapping_order_anomalies": ordering_anomalies,
        "subsegments": output,
        "warning": (
            "Candidates only. Matching interior anchors do not prove that the "
            "JP and USA subsegment starts are equivalent. Validate code/data "
            "type, function boundaries, relocations, and branch targets before "
            "using any candidate in a USA Splat configuration."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jp_elf", type=Path)
    parser.add_argument("usa_elf", type=Path)
    parser.add_argument("jp_yaml", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--block-size", type=int, default=16)
    parser.add_argument("--step", type=int, default=16)
    parser.add_argument("--search-window", type=lambda x: int(x, 0), default=0x1000)
    parser.add_argument("--min-anchors", type=int, default=2)
    args = parser.parse_args()

    result = map_subsegments(
        args.jp_elf,
        args.usa_elf,
        args.jp_yaml,
        block_size=args.block_size,
        step=args.step,
        search_window=args.search_window,
        min_anchors=args.min_anchors,
    )
    rendered = json.dumps(result, indent=2)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
