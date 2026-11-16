#!/usr/bin/env python3
"""Inspect a PS2 ELF32/MIPS executable and its Sony DVP overlay metadata.

This tool only reads the supplied executable. It does not extract game assets
or modify the input file.
"""

from __future__ import annotations

import argparse
import json
import struct
import zlib
from hashlib import sha1
from pathlib import Path


ELF_HEADER = struct.Struct("<16sHHIIIIIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIIIIIII")
SECTION_HEADER = struct.Struct("<IIIIIIIIII")
DVP_OVERLAY_ENTRY = struct.Struct("<III")


def c_string(table: bytes, offset: int) -> str:
    if offset >= len(table):
        return f"<invalid-string-offset:{offset:#x}>"
    end = table.find(b"\\0", offset)
    if end < 0:
        end = len(table)
    return table[offset:end].decode("ascii", errors="replace")


def inspect(path: Path) -> dict:
    data = path.read_bytes()
    if len(data) < ELF_HEADER.size:
        raise ValueError("File is too small to contain an ELF32 header")

    fields = ELF_HEADER.unpack_from(data)
    ident = fields[0]
    if ident[:4] != b"\\x7fELF":
        raise ValueError("Input is not an ELF file")
    if ident[4] != 1 or ident[5] != 1:
        raise ValueError("Expected ELF32 little-endian input")

    (
        _ident, elf_type, machine, version, entry, phoff, shoff, flags,
        ehsize, phentsize, phnum, shentsize, shnum, shstrndx,
    ) = fields
    if machine != 8:
        raise ValueError(f"Expected MIPS machine type 8, got {machine}")
    if shentsize < SECTION_HEADER.size:
        raise ValueError("Unexpected ELF section-header size")

    sections = []
    for index in range(shnum):
        off = shoff + index * shentsize
        if off + SECTION_HEADER.size > len(data):
            raise ValueError("Section-header table extends beyond end of file")
        sections.append(SECTION_HEADER.unpack_from(data, off))

    if shstrndx >= len(sections):
        raise ValueError("Invalid section-header string-table index")
    shstr = sections[shstrndx]
    shstr_data = data[shstr[4]:shstr[4] + shstr[5]]

    named_sections = []
    by_name = {}
    for index, section in enumerate(sections):
        name = c_string(shstr_data, section[0])
        item = {
            "index": index,
            "name": name,
            "type": section[1],
            "flags": section[2],
            "address": section[3],
            "file_offset": section[4],
            "size": section[5],
            "alignment": section[8],
            "entry_size": section[9],
        }
        named_sections.append(item)
        by_name[name] = (section, item)

    programs = []
    for index in range(phnum):
        off = phoff + index * phentsize
        if off + PROGRAM_HEADER.size > len(data):
            raise ValueError("Program-header table extends beyond end of file")
        p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = (
            PROGRAM_HEADER.unpack_from(data, off)
        )
        programs.append({
            "index": index,
            "type": p_type,
            "file_offset": p_offset,
            "virtual_address": p_vaddr,
            "physical_address": p_paddr,
            "file_size": p_filesz,
            "memory_size": p_memsz,
            "flags": p_flags,
            "alignment": p_align,
        })

    gp_value = None
    if ".reginfo" in by_name:
        reg_section, _ = by_name[".reginfo"]
        reg_data = data[reg_section[4]:reg_section[4] + reg_section[5]]
        if len(reg_data) >= 24:
            gp_value = struct.unpack_from("<I", reg_data, 20)[0]

    overlays = []
    if ".DVP.ovlytab" in by_name and ".DVP.ovlystrtab" in by_name:
        table_section, _ = by_name[".DVP.ovlytab"]
        strings_section, _ = by_name[".DVP.ovlystrtab"]
        table_data = data[table_section[4]:table_section[4] + table_section[5]]
        strings_data = data[strings_section[4]:strings_section[4] + strings_section[5]]
        entry_size = table_section[9] or DVP_OVERLAY_ENTRY.size
        if entry_size < DVP_OVERLAY_ENTRY.size:
            raise ValueError("DVP overlay table entry is smaller than 12 bytes")
        for index, offset in enumerate(range(0, len(table_data), entry_size)):
            chunk = table_data[offset:offset + DVP_OVERLAY_ENTRY.size]
            if len(chunk) != DVP_OVERLAY_ENTRY.size:
                break
            name_offset, ee_address, vu_address = DVP_OVERLAY_ENTRY.unpack(chunk)
            overlays.append({
                "index": index,
                "section_name": c_string(strings_data, name_offset),
                "ee_address": ee_address,
                "vu_address": vu_address,
            })

    overlay_sections = [
        item for item in named_sections if item["name"].startswith(".DVP.overlay.")
    ]

    return {
        "file": path.name,
        "file_size": len(data),
        "sha1": sha1(data).hexdigest(),
        "crc32": f"{zlib.crc32(data) & 0xffffffff:08X}",
        "elf": {
            "class": "ELF32",
            "endianness": "little",
            "type": elf_type,
            "machine": "MIPS" if machine == 8 else machine,
            "entry_point": entry,
            "flags": f"0x{flags:08X}",
            "program_header_count": phnum,
            "section_header_count": shnum,
        },
        "gp_value": gp_value,
        "program_headers": programs,
        "sections": named_sections,
        "dvp_overlay_count": len(overlays),
        "dvp_overlays": overlays,
        "dvp_overlay_sections": overlay_sections,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=Path, help="PS2 ELF32/MIPS executable")
    parser.add_argument("-o", "--output", type=Path, help="Write JSON report to this path")
    args = parser.parse_args()

    report = inspect(args.elf)
    rendered = json.dumps(report, indent=2)
    if args.output:
        args.output.write_text(rendered + "\\n", encoding="utf-8")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
