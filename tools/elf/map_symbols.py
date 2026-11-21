#!/usr/bin/env python3
"""Map JP function symbols to conservative USA address candidates.

Function extents are bounded by the next greater function symbol and by a
maximum scan size. Results are candidates only; no symbol map is rewritten.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


SYMBOL_RE = re.compile(
    r"^\s*([A-Za-z_.$][\w.$@]*)\s*=\s*(0x[0-9a-fA-F]+)\s*;"
    r"\s*//\s*type:func\s*$"
)


def load_inspector():
    path = Path(__file__).with_name("inspect.py")
    spec = importlib.util.spec_from_file_location("kh1_symbol_elf_inspect", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load ELF inspector: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.inspect


inspect_elf = load_inspector()


def parse_function_symbols(text: str) -> list[dict[str, Any]]:
    symbols = []
    for line in text.splitlines():
        match = SYMBOL_RE.match(line)
        if match:
            symbols.append({
                "name": match.group(1),
                "address": int(match.group(2), 16),
            })
    return symbols


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


def map_symbols(
    jp_elf: Path,
    usa_elf: Path,
    jp_symbols: Path,
    block_size: int = 16,
    step: int = 16,
    max_function_size: int = 0x400,
    min_anchors: int = 2,
):
    if block_size < 8 or block_size % 4:
        raise ValueError("block_size must be a multiple of 4 and at least 8")
    if step < block_size or step % 4:
        raise ValueError("step must be a multiple of 4 and >= block_size")
    if max_function_size < block_size:
        raise ValueError("max_function_size must be >= block_size")
    if min_anchors < 1:
        raise ValueError("min_anchors must be positive")

    jp_bytes, usa_bytes = jp_elf.read_bytes(), usa_elf.read_bytes()
    jp_report, usa_report = inspect_elf(jp_elf), inspect_elf(usa_elf)
    jp_main, jp_section = get_main_image(jp_bytes, jp_report)
    usa_main, usa_section = get_main_image(usa_bytes, usa_report)
    symbols = parse_function_symbols(jp_symbols.read_text(encoding="utf-8"))
    main_start = jp_section["address"]
    main_end = main_start + len(jp_main)
    symbols = [
        symbol for symbol in symbols
        if main_start <= symbol["address"] < main_end
    ]
    symbols.sort(key=lambda item: (item["address"], item["name"]))

    unique_addresses = sorted({item["address"] for item in symbols})
    next_address = {
        address: (
            unique_addresses[index + 1]
            if index + 1 < len(unique_addresses)
            else main_end
        )
        for index, address in enumerate(unique_addresses)
    }

    jp_index = unique_block_index(jp_main, block_size)
    usa_index = unique_block_index(usa_main, block_size)
    output = []

    for symbol in symbols:
        start = symbol["address"] - main_start
        symbol_end = min(
            next_address[symbol["address"]] - main_start,
            start + max_function_size,
            len(jp_main),
        )
        votes = Counter()
        anchors_by_delta: dict[int, list[dict[str, int]]] = defaultdict(list)

        for jp_offset in range(start, symbol_end - block_size + 1, step):
            block = jp_main[jp_offset:jp_offset + block_size]
            jp_hits = jp_index.get(block, [])
            usa_hits = usa_index.get(block, [])
            if len(jp_hits) != 1 or len(usa_hits) != 1:
                continue
            delta = jp_hits[0] - usa_hits[0]
            votes[delta] += 1
            anchors_by_delta[delta].append({
                "jp_offset": jp_offset,
                "usa_offset": usa_hits[0],
            })

        ranked = votes.most_common(3)
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

        candidates = []
        for delta, count in ranked:
            usa_offset = start - delta
            candidates.append({
                "delta": delta,
                "delta_hex": f"0x{delta:X}",
                "usa_offset_candidate": usa_offset,
                "usa_address_candidate": (
                    f"0x{usa_section['address'] + usa_offset:08X}"
                    if 0 <= usa_offset < len(usa_main) else None
                ),
                "anchor_count": count,
                "anchors": anchors_by_delta[delta],
            })

        if ranked and not (0 <= start - ranked[0][0] < len(usa_main)):
            status = "candidate_out_of_range"

        output.append({
            "name": symbol["name"],
            "jp_address": f"0x{symbol['address']:08X}",
            "jp_offset": start,
            "scan_size": max(0, symbol_end - start),
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
        usa_offset = candidate["usa_offset_candidate"]
        if 0 <= usa_offset < len(usa_main):
            mapped_candidates.append({
                "name": item["name"],
                "jp_offset": item["jp_offset"],
                "usa_offset": usa_offset,
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
        "jp_symbols": jp_symbols.name,
        "jp_sha1": jp_report["sha1"],
        "usa_sha1": usa_report["sha1"],
        "block_size": block_size,
        "step": step,
        "max_function_size": max_function_size,
        "min_anchors": min_anchors,
        "function_symbol_count": len(symbols),
        "status_counts": dict(Counter(item["status"] for item in output)),
        "mapped_candidate_count": len(mapped_candidates),
        "mapping_order_anomaly_count": len(ordering_anomalies),
        "mapping_order_anomalies": ordering_anomalies,
        "symbols": output,
        "warning": (
            "Candidates only. The next symbol address is used as a provisional "
            "function bound, and symbol tables may omit functions or contain "
            "aliases. Verify function prologues, control flow, branch targets, "
            "relocations, and callers before promoting any mapping."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jp_elf", type=Path)
    parser.add_argument("usa_elf", type=Path)
    parser.add_argument("jp_symbols", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--block-size", type=int, default=16)
    parser.add_argument("--step", type=int, default=16)
    parser.add_argument("--max-function-size", type=lambda x: int(x, 0), default=0x400)
    parser.add_argument("--min-anchors", type=int, default=2)
    args = parser.parse_args()

    result = map_symbols(
        args.jp_elf,
        args.usa_elf,
        args.jp_symbols,
        block_size=args.block_size,
        step=args.step,
        max_function_size=args.max_function_size,
        min_anchors=args.min_anchors,
    )
    rendered = json.dumps(result, indent=2)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
