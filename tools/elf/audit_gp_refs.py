#!/usr/bin/env python3
"""Conservative GP-relative reference audit for the pinned KH1 JP/USA ELF pair."""
from __future__ import annotations
import argparse
import collections
import hashlib
import json
import re
import struct
from pathlib import Path

EXPECTED = {
    "jp": "9dabbf867a7ec2a030df99ba1ed969f2deef0488",
    "usa": "8704cda65ca5e3f04202f0a50472401355335312",
}
# GP-relative address formation: ADDIU and MIPS/R5900 load/store operations.
BASE_OPS = {0x09, *range(0x20, 0x40)}


def parse_elf(path: Path):
    data = path.read_bytes()
    if len(data) < 52 or data[:4] != b"\x7fELF" or data[4:6] != b"\x01\x01":
        raise ValueError(f"{path}: expected ELF32 little-endian")
    hdr = struct.unpack_from("<16sHHIIIIIHHHHHH", data)
    if hdr[2] != 8:
        raise ValueError(f"{path}: expected MIPS ELF")
    shoff, shentsize, shnum, shstrndx = hdr[6], hdr[11], hdr[12], hdr[13]
    if shentsize < 40 or shstrndx >= shnum:
        raise ValueError(f"{path}: invalid section table")
    raw = [struct.unpack_from("<IIIIIIIIII", data, shoff + i * shentsize)
           for i in range(shnum)]
    names_hdr = raw[shstrndx]
    names = data[names_hdr[4]:names_hdr[4] + names_hdr[5]]

    def cstr(buf, off):
        end = buf.find(b"\0", off)
        return buf[off:end if end >= 0 else len(buf)].decode("latin1")

    sections = {}
    for s in raw:
        sections[cstr(names, s[0])] = {
            "type": s[1], "flags": s[2], "address": s[3],
            "offset": s[4], "size": s[5],
        }
    for name in ("main", ".bss", ".reginfo"):
        if name not in sections:
            raise ValueError(f"{path}: missing {name}")
    reg = sections[".reginfo"]
    if reg["size"] < 24:
        raise ValueError(f"{path}: truncated .reginfo")
    gp = struct.unpack_from("<I", data, reg["offset"] + 20)[0]
    main = sections["main"]
    payload = data[main["offset"]:main["offset"] + main["size"]]
    if len(payload) != main["size"]:
        raise ValueError(f"{path}: truncated main")
    return {
        "sha1": hashlib.sha1(data).hexdigest(), "gp": gp,
        "main": main, "bss": sections[".bss"], "payload": payload,
    }


def decode_gp_refs(data: bytes, gp: int):
    refs = []
    for off in range(0, len(data) - 3, 4):
        word = struct.unpack_from("<I", data, off)[0]
        op, rs, rt, imm = word >> 26, (word >> 21) & 31, (word >> 16) & 31, word & 0xffff
        if rs != 28 or op not in BASE_OPS:
            continue
        signed = imm if imm < 0x8000 else imm - 0x10000
        refs.append({
            "offset": off, "opcode": op, "rt": rt, "immediate": signed,
            "ea": (gp + signed) & 0xffffffff,
        })
    return refs


def exact_anchor_runs(jp: bytes, usa: bytes, block=16, step=4, minimum=64):
    def index(data):
        result = collections.defaultdict(list)
        for off in range(0, len(data) - block + 1, step):
            chunk = data[off:off + block]
            if len(set(chunk)) >= 4:
                result[chunk].append(off)
        return result
    ji, ui = index(jp), index(usa)
    pairs = []
    for chunk, joffs in ji.items():
        uoffs = ui.get(chunk)
        if len(joffs) == 1 and uoffs and len(uoffs) == 1:
            pairs.append((joffs[0], uoffs[0]))
    pairs.sort()
    runs = []
    for jo, uo in pairs:
        if runs and jo == runs[-1][1] + 4 and uo == runs[-1][3] + 4:
            a, _, b, _, size = runs[-1]
            runs[-1] = (a, jo, b, uo, size + 4)
        else:
            runs.append((jo, jo, uo, uo, 16))
    return pairs, [r for r in runs if r[4] >= minimum]


def region(address, bss):
    start, end = bss["address"], bss["address"] + bss["size"]
    return "bss" if start <= address < end else ("before_bss" if address < start else "after_bss")


def parse_main_subsegments(path: Path, main_size: int):
    """Read the simple [offset, type, name] entries from the JP Splat main segment."""
    lines = path.read_text(encoding="utf-8").splitlines()
    entries = []
    in_main = False
    in_subsegments = False
    item_re = re.compile(
        r"^\s+-\s*\[\s*(0x[0-9a-fA-F]+|[0-9]+)\s*,\s*([^,\]]+)(?:,\s*([^\]]+))?\]"
    )
    for line in lines:
        if re.match(r"^-\s+name:\s*main\s*$", line.strip()):
            in_main, in_subsegments = True, False
            continue
        if in_main and re.match(r"^\s+-\s+name:", line):
            break
        if in_main and re.match(r"^\s+subsegments:\s*$", line):
            in_subsegments = True
            continue
        if in_subsegments:
            match = item_re.match(line)
            if match:
                entries.append({
                    "offset": int(match.group(1), 0),
                    "type": match.group(2).strip(),
                    "name": (match.group(3) or "").strip(),
                })
    entries.sort(key=lambda item: item["offset"])
    for index, item in enumerate(entries):
        item["end"] = entries[index + 1]["offset"] if index + 1 < len(entries) else main_size
    return entries


def find_subsegment(offset: int, entries):
    for item in entries:
        if item["offset"] <= offset < item["end"]:
            return item
    return None


def audit(jp_path: Path, usa_path: Path, jp_yaml: Path | None = None):
    jp, usa = parse_elf(jp_path), parse_elf(usa_path)
    if jp["sha1"] != EXPECTED["jp"] or usa["sha1"] != EXPECTED["usa"]:
        raise ValueError("ELF SHA-1 does not match the pinned retail executables")
    pairs, runs = exact_anchor_runs(jp["payload"], usa["payload"])
    paired = {}
    for js, _, us, _, size in runs:
        jr = decode_gp_refs(jp["payload"][js:js + size], jp["gp"])
        ur = decode_gp_refs(usa["payload"][us:us + size], usa["gp"])
        for a, b in zip(jr, ur):
            paired[(js + a["offset"], us + b["offset"])] = (a, b, size)
    details = []
    for (jo, uo), (a, b, run_size) in sorted(paired.items()):
        details.append({
            "jp_offset": jo, "usa_offset": uo,
            "jp_vma": jp["main"]["address"] + jo,
            "usa_vma": usa["main"]["address"] + uo,
            "opcode": f"0x{a['opcode']:02X}", "rt": a["rt"],
            "immediate": a["immediate"],
            "jp_ea": a["ea"], "usa_ea": b["ea"],
            "ea_delta": a["ea"] - b["ea"],
            "jp_region": region(a["ea"], jp["bss"]),
            "usa_region": region(b["ea"], usa["bss"]),
            "anchor_run_size": run_size,
        })
    deltas = collections.Counter(x["ea_delta"] for x in details)
    splat_classification = None
    if jp_yaml is not None:
        entries = parse_main_subsegments(jp_yaml, jp["main"]["size"])
        paired_type_counts = collections.Counter()
        segment_counts = collections.Counter()
        for item in details:
            segment = find_subsegment(item["jp_offset"], entries)
            if segment is None:
                paired_type_counts["unmapped"] += 1
                continue
            paired_type_counts[segment["type"]] += 1
            segment_counts[
                f"0x{segment['offset']:X}-0x{segment['end']:X} {segment['type']} {segment['name']}".strip()
            ] += 1
        raw_type_counts = collections.Counter()
        raw_code_offsets = []
        for item in decode_gp_refs(jp["payload"], jp["gp"]):
            segment = find_subsegment(item["offset"], entries)
            kind = segment["type"] if segment else "unmapped"
            raw_type_counts[kind] += 1
            if kind in {"c", "asm", "hasm"}:
                raw_code_offsets.append(item["offset"])
        splat_classification = {
            "subsegment_count": len(entries),
            "paired_pattern_type_counts": dict(paired_type_counts),
            "raw_jp_opcode_candidate_type_counts": dict(raw_type_counts),
            "raw_jp_code_subsegment_candidate_count": len(raw_code_offsets),
            "paired_pattern_segment_counts": dict(segment_counts),
        }
    region_pairs = collections.Counter((x["jp_region"], x["usa_region"]) for x in details)
    return {
        "jp_sha1": jp["sha1"], "usa_sha1": usa["sha1"],
        "jp_gp": f"0x{jp['gp']:08X}", "usa_gp": f"0x{usa['gp']:08X}",
        "gp_delta": jp["gp"] - usa["gp"],
        "jp_bss": {"address": f"0x{jp['bss']['address']:08X}", "size": jp["bss"]["size"]},
        "usa_bss": {"address": f"0x{usa['bss']['address']:08X}", "size": usa["bss"]["size"]},
        "raw_gp_memory_candidates": {
            "jp": len(decode_gp_refs(jp["payload"], jp["gp"])),
            "usa": len(decode_gp_refs(usa["payload"], usa["gp"])),
        },
        "unique_exact_anchor_pairs": len(pairs),
        "long_exact_runs": len(runs),
        "long_exact_run_bytes": sum(x[4] for x in runs),
        "paired_gp_references": len(details),
        "effective_address_deltas": dict(deltas),
        "jp_splat_classification": splat_classification,
        "region_pair_counts": {f"{a}->{b}": n for (a, b), n in region_pairs.items()},
        "references": details,
        "limitations": [
            "The ELF main section mixes code and data; raw opcode matches are candidates, not confirmed source-level references.",
            "Exact anchor runs establish byte identity only within each run, not function boundaries.",
            "References outside exact runs, including instructions whose immediate changed, are not paired.",
            "This does not recover variable names, struct layouts, jump tables, or unaligned address constructions.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jp_elf", type=Path)
    parser.add_argument("usa_elf", type=Path)
    parser.add_argument("--jp-yaml", type=Path, help="JP Splat YAML; classifies paired offsets as code/data")
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    result = audit(args.jp_elf, args.usa_elf, args.jp_yaml)
    rendered = json.dumps(result, indent=2)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
