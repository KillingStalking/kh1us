#!/usr/bin/env python3
"""Validate mapped JP function candidates against a pinned USA MIPS ELF.

Consumes map_symbols.py JSON. Candidate starts remain hypotheses until this
pass checks instruction signatures, control-flow layout, and any direct
targets that land inside another independently mapped candidate extent.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import struct
from pathlib import Path
from typing import Any


def load_control_flow_tool():
    path = Path(__file__).with_name("validate_control_flow.py")
    spec = importlib.util.spec_from_file_location("kh1_candidate_cf", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load control-flow validator: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cf = load_control_flow_tool()


def mapped_candidates(map_report: dict[str, Any], min_anchors: int = 2):
    result = []
    for item in map_report.get("symbols", []):
        if item.get("status") not in ("candidate", "candidate_strong"):
            continue
        if not item.get("candidates"):
            continue
        best = item["candidates"][0]
        if best.get("anchor_count", 0) < min_anchors:
            continue
        if best.get("usa_address_candidate") is None:
            continue
        result.append({
            "name": item["name"],
            "jp_address": int(item["jp_address"], 16),
            "jp_offset": item["jp_offset"],
            "usa_offset": best["usa_offset_candidate"],
            "anchor_count": best["anchor_count"],
            "delta": best["delta"],
            "scan_size": item["scan_size"],
        })
    result.sort(key=lambda x: (x["jp_address"], x["name"]))
    return result


def target_mapping(target: int, candidates: list[dict[str, Any]], main_vma: int):
    for item in candidates:
        start = item["jp_address"]
        end = start + item["scan_size"]
        if start <= target < end:
            return main_vma + item["usa_offset"] + (target - start), item["name"]
    return None, None


def validate_candidates(jp_path: Path, usa_path: Path, map_json: Path,
                        min_anchors: int = 2, min_signature_ratio: float = 0.98):
    report = json.loads(map_json.read_text(encoding="utf-8"))
    jp_main, jp_section, jp_report = cf.get_main_image(jp_path)
    usa_main, usa_section, usa_report = cf.get_main_image(usa_path)
    if jp_report["sha1"] != cf.EXPECTED_JP_SHA1:
        raise ValueError("JP ELF SHA-1 does not match the pinned executable")
    if usa_report["sha1"] != cf.EXPECTED_USA_SHA1:
        raise ValueError("USA ELF SHA-1 does not match the pinned executable")
    if report.get("jp_sha1") != jp_report["sha1"] or report.get("usa_sha1") != usa_report["sha1"]:
        raise ValueError("Mapper JSON hashes do not match the supplied ELF pair")

    candidates = mapped_candidates(report, min_anchors)
    # Build a unique-address index; aliases at one JP address share one extent.
    by_start = {}
    for item in candidates:
        by_start.setdefault(item["jp_address"], item)
    starts = sorted(by_start)
    for index, start in enumerate(starts):
        next_start = starts[index + 1] if index + 1 < len(starts) else None
        by_start[start]["jp_candidate_end"] = next_start

    results = []
    for item in candidates:
        jp_offset = item["jp_offset"]
        usa_offset = item["usa_offset"]
        size = item["scan_size"]
        record = {
            "name": item["name"],
            "jp_address": f"0x{item['jp_address']:08X}",
            "usa_address_candidate": f"0x{usa_section['address'] + usa_offset:08X}",
            "size": size,
            "anchor_count": item["anchor_count"],
            "instruction_signature_matches": 0,
            "instruction_words": 0,
            "signature_ratio": 0.0,
            "control_flow_layout_matches": False,
            "known_candidate_targets": [],
            "unresolved_direct_targets": [],
            "status": "rejected",
        }
        if size <= 0 or size % 4 or jp_offset < 0 or usa_offset < 0:
            record["reason"] = "invalid_or_unaligned_extent"
            results.append(record)
            continue
        if jp_offset + size > len(jp_main) or usa_offset + size > len(usa_main):
            record["reason"] = "extent_out_of_bounds"
            results.append(record)
            continue

        jp_words = [struct.unpack_from("<I", jp_main, off)[0] for off in range(jp_offset, jp_offset + size, 4)]
        usa_words = [struct.unpack_from("<I", usa_main, off)[0] for off in range(usa_offset, usa_offset + size, 4)]
        matches = sum(cf.instruction_signature(a) == cf.instruction_signature(b) for a, b in zip(jp_words, usa_words))
        ratio = matches / len(jp_words) if jp_words else 0.0
        jp_cf = cf.decode_control_flow(jp_main, jp_section["address"], jp_offset, size)
        usa_cf = cf.decode_control_flow(usa_main, usa_section["address"], usa_offset, size)
        layout = (
            len(jp_cf) == len(usa_cf)
            and all((a["offset"], a["kind"], a["signature"]) ==
                    (b["offset"], b["kind"], b["signature"])
                    for a, b in zip(jp_cf, usa_cf))
        )
        record.update({
            "instruction_signature_matches": matches,
            "instruction_words": len(jp_words),
            "signature_ratio": round(ratio, 6),
            "control_flow_layout_matches": layout,
        })

        if layout:
            for jp_edge, usa_edge in zip(jp_cf, usa_cf):
                if jp_edge["target"] is None:
                    continue
                expected, target_name = target_mapping(jp_edge["target"], candidates, usa_section["address"])
                edge = {
                    "kind": jp_edge["kind"],
                    "source_jp": f"0x{jp_section['address'] + jp_offset + jp_edge['offset']:08X}",
                    "source_usa": f"0x{usa_section['address'] + usa_offset + usa_edge['offset']:08X}",
                    "jp_target": f"0x{jp_edge['target']:08X}",
                    "usa_target": f"0x{usa_edge['target']:08X}",
                    "mapped_candidate": target_name,
                    "expected_usa_target": f"0x{expected:08X}" if expected is not None else None,
                }
                if expected is None:
                    record["unresolved_direct_targets"].append(edge)
                else:
                    edge["matches"] = expected == usa_edge["target"]
                    record["known_candidate_targets"].append(edge)

        target_results = record["known_candidate_targets"]
        targets_match = all(edge["matches"] for edge in target_results)
        if ratio >= min_signature_ratio and layout and targets_match:
            record["status"] = "validated_candidate_body"
        elif ratio >= min_signature_ratio and layout:
            record["status"] = "partial_candidate_body"
        else:
            record["status"] = "rejected"
        record["reason"] = (
            "Local signatures/layout and all mapped candidate targets agree; "
            "unresolved external targets remain unverified."
            if record["status"] == "validated_candidate_body"
            else "Insufficient instruction/control-flow agreement or a mapped target mismatch."
        )
        results.append(record)

    return {
        "jp_sha1": jp_report["sha1"],
        "usa_sha1": usa_report["sha1"],
        "mapper_parameters": {
            "block_size": report.get("block_size"),
            "step": report.get("step"),
            "max_function_size": report.get("max_function_size"),
            "min_anchors": min_anchors,
            "min_signature_ratio": min_signature_ratio,
        },
        "candidate_count": len(candidates),
        "validated_candidate_body_count": sum(x["status"] == "validated_candidate_body" for x in results),
        "partial_candidate_body_count": sum(x["status"] == "partial_candidate_body" for x in results),
        "rejected_count": sum(x["status"] == "rejected" for x in results),
        "functions": results,
        "warning": (
            "Validated candidate body is not yet a promoted symbol: extents are "
            "bounded by JP symbol spacing, external direct targets may remain "
            "unresolved, and caller/callee corroboration plus adjacent-boundary "
            "inspection are still required."
        ),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jp_elf", type=Path)
    parser.add_argument("usa_elf", type=Path)
    parser.add_argument("mapper_json", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--min-anchors", type=int, default=2)
    parser.add_argument("--min-signature-ratio", type=float, default=0.98)
    args = parser.parse_args()
    result = validate_candidates(args.jp_elf, args.usa_elf, args.mapper_json,
                                 args.min_anchors, args.min_signature_ratio)
    rendered = json.dumps(result, indent=2)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
