#!/usr/bin/env python3
"""Minimal PS2 VU micro-instruction pair disassembler.

Each VU instruction pair is 8 bytes: lower 32-bit word, then upper 32-bit
word, both little-endian. This tool decodes operation names, common register
fields, branch destinations, and upper-word flags. It preserves raw words
because it is not a cycle-accurate semantic decoder.
"""
from __future__ import annotations

import argparse
import struct
from pathlib import Path
from typing import List, Optional

UPPER_NAMES = {
    0x1C: "MULq", 0x1D: "MAXi", 0x1E: "MULi", 0x1F: "MINIi",
    0x20: "ADDq", 0x21: "MADDq", 0x22: "ADDi", 0x23: "MADDi",
    0x24: "SUBq", 0x25: "MSUBq", 0x26: "SUBi", 0x27: "MSUBi",
    0x28: "ADD", 0x29: "MADD", 0x2A: "MUL", 0x2B: "MAX",
    0x2C: "SUB", 0x2D: "MSUB", 0x2E: "OPMSUB", 0x2F: "MINI",
}
UPPER_SPECIAL_NAMES = {
    0x10: "ITOF0", 0x11: "ITOF4", 0x12: "ITOF12", 0x13: "ITOF15",
    0x14: "FTOI0", 0x15: "FTOI4", 0x16: "FTOI12", 0x17: "FTOI15",
    0x1C: "MULAq", 0x1D: "ABS", 0x1E: "MULAi", 0x1F: "CLIP",
    0x20: "ADDAq", 0x21: "MADDAq", 0x22: "ADDAi", 0x23: "MADDAi",
    0x24: "SUBAq", 0x25: "MSUBAq", 0x26: "SUBAi", 0x27: "MSUBAi",
    0x28: "ADDA", 0x29: "MADDA", 0x2A: "MULA", 0x2C: "SUBA",
    0x2D: "MSUBA", 0x2E: "OPMULA", 0x2F: "NOP", 0x30: "NOP",
}
LOWER_NAMES = {
    0x00: "LQ", 0x01: "SQ", 0x04: "ILW", 0x05: "ISW",
    0x08: "IADDIU", 0x09: "ISUBIU", 0x10: "FCEQ", 0x11: "FCSET",
    0x12: "FCAND", 0x13: "FCOR", 0x14: "FSEQ", 0x15: "FSSET",
    0x16: "FSAND", 0x17: "FSOR", 0x18: "FMEQ", 0x1A: "FMAND",
    0x1B: "FMOR", 0x1C: "FCGET", 0x20: "B", 0x21: "BAL",
    0x24: "JR", 0x25: "JALR", 0x28: "IBEQ", 0x29: "IBNE",
    0x2C: "IBLTZ", 0x2D: "IBGTZ", 0x2E: "IBLEZ", 0x2F: "IBGEZ",
}
LOWER_DIRECT_NAMES = {
    0x30: "IADD", 0x31: "ISUB", 0x32: "IADDI", 0x34: "IAND", 0x35: "IOR",
}
LOWER_SPECIAL_NAMES = {
    0x30: "MOVE", 0x31: "MR32", 0x34: "LQI", 0x35: "SQI",
    0x36: "LQD", 0x37: "SQD", 0x38: "DIV", 0x39: "SQRT",
    0x3A: "RSQRT", 0x3B: "WAITQ", 0x3C: "MTIR", 0x3D: "MFIR",
    0x3E: "ILWR", 0x3F: "ISWR", 0x40: "RNEXT", 0x41: "RGET",
    0x42: "RINIT", 0x43: "RXOR", 0x64: "MFP", 0x68: "XTOP",
    0x69: "XITOP", 0x6C: "XGKICK", 0x70: "ESADD", 0x71: "ERSADD",
    0x72: "ELENG", 0x73: "ERLENG", 0x74: "EATANxy", 0x75: "EATANxz",
    0x76: "ESUM", 0x77: "ERSQRT", 0x78: "ESQRT", 0x79: "ESIN",
    0x7A: "ERCPR", 0x7B: "WAITP", 0x7C: "EATAN", 0x7D: "EEXP",
}
BC = "xyzw"


def special(word: int) -> int:
    return (word & 3) | ((word >> 4) & 0x7C)


def upper_name(word: int) -> str:
    op = word & 0x3F
    if op < 0x1C:
        return ["ADD", "SUB", "MADD", "MSUB", "MAX", "MINI", "MUL"][op >> 2] + BC[op & 3]
    if op < 0x3C:
        return UPPER_NAMES.get(op, "reserved")
    sp = special(word)
    if sp <= 0x0F:
        return ["ADDA", "SUBA", "MADDA", "MSUBA"][sp >> 2] + BC[sp & 3]
    if 0x18 <= sp <= 0x1B:
        return "MULA" + BC[sp & 3]
    return UPPER_SPECIAL_NAMES.get(sp, "reserved")


def lower_name(word: int) -> str:
    if word in (0, 0x8000033C):
        return "NOP"
    op = (word >> 25) & 0x7F
    if op != 0x40:
        return LOWER_NAMES.get(op, "reserved")
    direct = word & 0x3F
    if direct < 0x3C:
        return LOWER_DIRECT_NAMES.get(direct, "reserved")
    return LOWER_SPECIAL_NAMES.get(special(word), "reserved")


def signed_imm11(word: int) -> int:
    value = word & 0x7FF
    return value - 0x800 if value & 0x400 else value


def describe_pair(lower: int, upper: int, pc: int, base: int) -> str:
    upper_op = upper_name(upper)
    lower_op = "LOI" if upper & (1 << 31) else lower_name(lower)
    dest = (upper >> 21) & 0xF
    lanes = "".join(c for c, bit in zip(BC, (8, 4, 2, 1)) if dest & bit) or "-"
    fs, ft, fd = (upper >> 11) & 31, (upper >> 16) & 31, (upper >> 6) & 31
    vi_t, vi_s, vi_d = (lower >> 16) & 15, (lower >> 11) & 15, (lower >> 6) & 15
    op = (lower >> 25) & 0x7F
    extra = f"dest={lanes} fs=vf{fs} ft=vf{ft} fd=vf{fd}; it=vi{vi_t} is=vi{vi_s} id=vi{vi_d}"
    if upper & (1 << 31):
        extra += f"; imm=0x{lower:08X}"
    elif op in (0x20, 0x21, 0x28, 0x29, 0x2C, 0x2D, 0x2E, 0x2F):
        target = base + ((pc // 8 + 1 + signed_imm11(lower)) * 8)
        extra += f"; branch_target=0x{target:04X}"
    flags = "".join(letter for letter, bit in (("I", 31), ("E", 30), ("M", 29), ("D", 28), ("T", 27)) if upper & (1 << bit))
    return f"{base + pc:08X}  {upper_op:<10} | {lower_op:<8}  {flags or '-':<5}  {extra}  raw={lower:08X}/{upper:08X}"


def disassemble(data: bytes, base: int = 0, start: int = 0, end: Optional[int] = None, to_ebit: bool = False) -> List[str]:
    if len(data) % 8:
        raise ValueError("VU payload size must be a multiple of 8 bytes")
    stop = min(len(data), end if end is not None else len(data))
    if start < 0 or start % 8 or stop % 8 or start > stop:
        raise ValueError("start/end must be ordered 8-byte-aligned offsets")
    lines = []
    for pc in range(start, stop, 8):
        lower, upper = struct.unpack_from("<II", data, pc)
        lines.append(describe_pair(lower, upper, pc, base))
        if to_ebit and upper & (1 << 30):
            break
    return lines


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("payload", type=Path)
    parser.add_argument("--base", type=lambda s: int(s, 0), default=0, help="VU address of payload start")
    parser.add_argument("--start", type=lambda s: int(s, 0), default=0, help="byte offset in payload")
    parser.add_argument("--end", type=lambda s: int(s, 0), default=None, help="exclusive byte offset")
    parser.add_argument("--to-ebit", action="store_true", help="stop after the first E-bit pair")
    args = parser.parse_args()
    data = args.payload.read_bytes()
    print("\n".join(disassemble(data, args.base, args.start, args.end, args.to_ebit)))


if __name__ == "__main__":
    main()
