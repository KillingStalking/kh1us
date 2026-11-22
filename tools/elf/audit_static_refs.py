#!/usr/bin/env python3
"""Recover conservative JP->USA absolute data-reference correspondences.

The tool scans only JP Splat main subsegments classified c/asm/hasm. It looks
for LUI + ADDIU/ORI address materialization followed by a memory operation,
then maps the instruction sequence into USA using two non-overlapping unique
16-byte anchors. Results are candidates, not a complete relocation table.
"""
from __future__ import annotations
import argparse, collections, hashlib, json, re, struct
from pathlib import Path

EXPECTED = {
    "jp": "9dabbf867a7ec2a030df99ba1ed969f2deef0488",
    "usa": "8704cda65ca5e3f04202f0a50472401355335312",
}
CODE_TYPES = {"c", "asm", "hasm"}
MEMORY_OPS = set(range(0x20, 0x30)) | set(range(0x30, 0x40))


def read_elf(path: Path):
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
    st = raw[shstrndx]
    names = data[st[4]:st[4] + st[5]]
    def cstr(off):
        end = names.find(b"\0", off)
        return names[off:end if end >= 0 else len(names)].decode("latin1")
    sections = {cstr(s[0]): {"type": s[1], "address": s[3],
                              "offset": s[4], "size": s[5]} for s in raw}
    for name in ("main", ".bss", ".reginfo"):
        if name not in sections:
            raise ValueError(f"{path}: missing {name}")
    reg = sections[".reginfo"]
    gp = struct.unpack_from("<I", data, reg["offset"] + 20)[0]
    main = sections["main"]
    payload = data[main["offset"]:main["offset"] + main["size"]]
    if len(payload) != main["size"]:
        raise ValueError(f"{path}: truncated main section")
    return {"sha1": hashlib.sha1(data).hexdigest(), "main": main,
            "bss": sections[".bss"], "gp": gp, "payload": payload}


def parse_code_ranges(yaml_path: Path, main_size: int):
    lines = yaml_path.read_text(encoding="utf-8").splitlines()
    main_i = next((i for i, line in enumerate(lines)
                   if re.match(r"^-\s+name:\s*main\s*$", line)), None)
    if main_i is None:
        raise ValueError("JP YAML has no top-level main segment")
    item_re = re.compile(
        r"^\s{2}-\s*\[\s*(0x[0-9a-fA-F]+|[0-9]+)\s*,\s*([^,\]]+)"
    )
    entries = []
    in_subsegments = False
    for line in lines[main_i + 1:]:
        if line and not line[0].isspace() and line.startswith("- "):
            break
        if re.match(r"^\s{2}subsegments:\s*$", line):
            in_subsegments = True
            continue
        if not in_subsegments:
            continue
        match = item_re.match(line)
        if match:
            entries.append((int(match.group(1), 0), match.group(2).strip()))
    if not entries:
        raise ValueError("No main subsegments found in JP YAML")
    entries.sort()
    ranges = []
    for i, (start, kind) in enumerate(entries):
        end = entries[i + 1][0] if i + 1 < len(entries) else main_size
        if kind not in CODE_TYPES:
            continue
        if start < 0 or end > main_size or end < start:
            raise ValueError("Invalid JP Splat subsegment bounds")
        if ranges and ranges[-1][1] == start:
            ranges[-1] = (ranges[-1][0], end)
        else:
            ranges.append((start, end))
    return ranges


def sign16(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


def writes_register(word: int, reg: int) -> bool:
    op, rt, rd, funct = word >> 26, (word >> 16) & 31, (word >> 11) & 31, word & 63
    if op == 0:
        if funct == 8:
            return False
        if funct == 9:
            return rd == reg
        return rd != 0 and rd == reg
    if op == 0x1E:  # R5900 LQ writes a 128-bit GPR.
        return rt != 0 and rt == reg
    if op in (1, 2, 4, 5, 6, 7):
        return False
    if op == 3:
        return reg == 31
    # Immediate ALU operations and integer loads write rt. Coprocessor
    # loads (LWC1/LWC2/LDC1/LDC2), PREF, and ordinary stores do not.
    if op in set(range(8, 16)) | set(range(0x20, 0x28)) | {0x30, 0x34, 0x37, 0x38, 0x3C}:
        # SC/SCD write the success result back to rt, despite being stores.
        return rt != 0 and rt == reg
    return False


def decode_candidate(words: list[int], index: int):
    """Decode one LUI -> ADDIU/ORI -> memory-use sequence, conservatively."""
    first = words[index]
    if first >> 26 != 0x0F:
        return None
    reg, hi = (first >> 16) & 31, first & 0xFFFF
    if reg == 0:
        return None
    for j in range(index + 1, min(index + 5, len(words))):
        ins = words[j]
        op, rs, rt = ins >> 26, (ins >> 21) & 31, (ins >> 16) & 31
        if writes_register(ins, reg):
            if op in (0x09, 0x0D) and rs == reg and rt == reg:
                low = ins & 0xFFFF
                target = ((hi << 16) + (sign16(low) if op == 0x09 else low)) & 0xFFFFFFFF
                for k in range(j + 1, min(j + 7, len(words))):
                    use = words[k]
                    uop, urs = use >> 26, (use >> 21) & 31
                    if urs == reg and uop in MEMORY_OPS:
                        return {"i": index * 4, "j": j * 4, "k": k * 4,
                                "reg": reg, "target": target, "low_op": op,
                                "mem_op": uop, "mem_imm": sign16(use & 0xFFFF),
                                "signature": [first & 0xFFFF0000,
                                              ins & 0xFFFF0000,
                                              use & 0xFFFF0000]}
                    if writes_register(use, reg):
                        break
                return None
            break
    return None


def build_anchor_index(data: bytes, code_limit: int, block_size=16, step=4):
    index = collections.defaultdict(list)
    for off in range(0, code_limit - block_size + 1, step):
        block = data[off:off + block_size]
        if len(set(block)) >= 4:
            index[block].append(off)
    return index


def map_code_offset(candidate, jp_data, usa_data, jp_index, usa_index,
                    code_limit, radius=0x80):
    deltas = collections.defaultdict(list)
    lo = max(0, candidate["i"] - radius)
    hi = min(code_limit - 16, candidate["i"] + radius)
    for anchor_off in range(lo, hi + 1, 4):
        block = jp_data[anchor_off:anchor_off + 16]
        if len(jp_index.get(block, ())) != 1 or len(usa_index.get(block, ())) != 1:
            continue
        usa_anchor = usa_index[block][0]
        deltas[anchor_off - usa_anchor].append(anchor_off)
    viable = []
    for delta, anchors in deltas.items():
        chosen = []
        for off in sorted(anchors, key=lambda x: abs(x - candidate["i"])):
            if all(abs(off - old) >= 16 for old in chosen):
                chosen.append(off)
        mapped = candidate["i"] - delta
        if len(chosen) < 2 or mapped < 0 or mapped + 12 > len(usa_data):
            continue
        usa_words = [struct.unpack_from("<I", usa_data, mapped + rel)[0]
                     for rel in (0, candidate["j"] - candidate["i"],
                                 candidate["k"] - candidate["i"])]
        if [word & 0xFFFF0000 for word in usa_words] == candidate["signature"]:
            viable.append((len(chosen), min(abs(x - candidate["i"]) for x in chosen),
                           delta, mapped))
    if not viable:
        return None
    viable.sort(key=lambda x: (-x[0], x[1]))
    if len(viable) > 1 and viable[0][0] == viable[1][0] and viable[0][2] != viable[1][2]:
        return None
    _, _, delta, mapped = viable[0]
    return mapped, delta


def classify_jp_target(address, main, bss, code_end):
    """Classify JP targets using the independently supplied JP Splat boundary."""
    if main["address"] <= address < main["address"] + code_end:
        return "code"
    if main["address"] + code_end <= address < main["address"] + main["size"]:
        return "main_data"
    if bss["address"] <= address < bss["address"] + bss["size"]:
        return "bss"
    return "other"


def classify_usa_region(address, main, bss):
    """Classify only ELF-backed USA regions; its code/data split is not known."""
    if main["address"] <= address < main["address"] + main["size"]:
        return "main_image_unclassified"
    if bss["address"] <= address < bss["address"] + bss["size"]:
        return "bss"
    return "other"


def run(jp_path: Path, usa_path: Path, jp_yaml: Path):
    jp, usa = read_elf(jp_path), read_elf(usa_path)
    if jp["sha1"] != EXPECTED["jp"] or usa["sha1"] != EXPECTED["usa"]:
        raise ValueError("ELF SHA-1 does not match the audited retail JP/USA pair")
    ranges = parse_code_ranges(jp_yaml, jp["main"]["size"])
    code_end = max(end for _, end in ranges)
    if ranges != [(0, code_end)]:
        raise ValueError("Expected one contiguous Splat code span; inspect ranges manually")
    jp_code = jp["payload"][:code_end]
    # USA has no validated Splat code/data boundary yet. Search the complete
    # USA main image for unique anchors rather than imposing the JP code limit.
    jp_words = [struct.unpack_from("<I", jp_code, off)[0]
                for off in range(0, len(jp_code) - 3, 4)]
    candidates = []
    for index in range(len(jp_words)):
        item = decode_candidate(jp_words, index)
        if item is not None:
            candidates.append(item)
    jp_index = build_anchor_index(jp_code, code_end)
    usa_index = build_anchor_index(usa["payload"], len(usa["payload"]))
    mapped = []
    for item in candidates:
        result = map_code_offset(item, jp_code, usa["payload"], jp_index, usa_index, code_end)
        if result is None:
            continue
        usa_off, code_delta = result
        rel_j, rel_k = item["j"] - item["i"], item["k"] - item["i"]
        usa_words = [struct.unpack_from("<I", usa["payload"], usa_off + rel)[0]
                     for rel in (0, rel_j, rel_k)]
        low = usa_words[1] & 0xFFFF
        usa_target = (((usa_words[0] & 0xFFFF) << 16) +
                      (sign16(low) if (usa_words[1] >> 26) == 0x09 else low)) & 0xFFFFFFFF
        jp_kind = classify_jp_target(item["target"], jp["main"], jp["bss"], code_end)
        usa_region = classify_usa_region(usa_target, usa["main"], usa["bss"])
        # Do not infer USA code/data from the JP code_end.
        effective_address = (item["target"] + item["mem_imm"]) & 0xFFFFFFFF
        alignment_by_opcode = {
            0x21: 2, 0x23: 4, 0x25: 2, 0x27: 4,
            0x29: 2, 0x2B: 4, 0x30: 4, 0x31: 4,
            0x32: 16, 0x34: 8, 0x35: 8, 0x38: 4,
            0x39: 4, 0x3A: 16, 0x3C: 8,
        }
        required_alignment = alignment_by_opcode.get(item["mem_op"])
        alignment_ok = (required_alignment is None or
                        effective_address % required_alignment == 0)
        mapped.append({
            "jp_code_offset": item["i"], "usa_code_offset": usa_off,
            "code_delta": code_delta, "register": item["reg"],
            "jp_target": item["target"], "usa_target": usa_target,
            "jp_target_kind": jp_kind, "usa_target_kind": usa_region,
            "usa_target_region": usa_region,
            "target_delta": item["target"] - usa_target,
            "memory_opcode": item["mem_op"], "memory_immediate": item["mem_imm"],
            "effective_address": effective_address,
            "required_alignment": required_alignment,
            "alignment_ok": alignment_ok,
        })
    page_summary = {}
    for kind in ("main_data", "bss"):
        pages = collections.defaultdict(collections.Counter)
        for item in mapped:
            if (item["jp_target_kind"] == kind and
                    (item["usa_target_region"] == "main_image_unclassified" if kind == "main_data"
                     else item["usa_target_region"] == "bss")):
                base = jp["main"]["address"] if kind == "main_data" else jp["bss"]["address"]
                pages[(item["jp_target"] - base) >> 12][item["target_delta"]] += 1
        rows = []
        for page, counts in sorted(pages.items()):
            total = sum(counts.values())
            if total >= 3:
                base = jp["main"]["address"] if kind == "main_data" else jp["bss"]["address"]
                rows.append({"page_start": base + (page << 12), "count": total,
                             "deltas": [{"delta": delta, "count": count}
                                        for delta, count in counts.most_common(8)]})
        page_summary[kind] = rows
    address_maps = {}
    for kind in ("main_data", "bss"):
        pairs = sorted({(item["jp_target"], item["usa_target"])
                        for item in mapped
                        if item["jp_target_kind"] == kind and
                        (item["usa_target_region"] == "main_image_unclassified" if kind == "main_data"
                         else item["usa_target_region"] == "bss")})
        anomalies = []
        for (jp_a, usa_a), (jp_b, usa_b) in zip(pairs, pairs[1:]):
            if jp_b > jp_a and usa_b <= usa_a:
                anomalies.append({"jp_before": jp_a, "usa_before": usa_a,
                                  "jp_after": jp_b, "usa_after": usa_b})
        address_maps[kind] = {"unique_address_pairs": len(pairs),
                              "nonmonotonic_adjacent_pairs": anomalies}
    return {
        "jp_sha1": jp["sha1"], "usa_sha1": usa["sha1"],
        "jp_gp": jp["gp"], "usa_gp": usa["gp"],
        "jp_bss": {"address": jp["bss"]["address"], "size": jp["bss"]["size"]},
        "usa_bss": {"address": usa["bss"]["address"], "size": usa["bss"]["size"]},
        "code_ranges": ranges, "jp_lui_address_sequences": len(candidates),
        "mapped_sequences": len(mapped),
        "target_kinds": dict(collections.Counter(x["jp_target_kind"] for x in mapped)),
        "target_region_pairs": dict(collections.Counter(
            x["jp_target_kind"] + "->" + x["usa_target_region"] for x in mapped)),
        "page_delta_summary": page_summary,
        "address_map_checks": address_maps,
        "alignment_failures": [item for item in mapped if not item["alignment_ok"]],
        "references": mapped,
        "warning": "Conservative static candidates only; not a complete pointer/relocation map. "
                   "LUI/low-immediate sequences and memory use are pattern-based, and all results "
                   "require semantic review before generating a USA linker map.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jp_elf", type=Path)
    parser.add_argument("usa_elf", type=Path)
    parser.add_argument("jp_yaml", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    result = run(args.jp_elf, args.usa_elf, args.jp_yaml)
    rendered = json.dumps(result, indent=2)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
