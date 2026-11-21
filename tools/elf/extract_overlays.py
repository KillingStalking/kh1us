#!/usr/bin/env python3
"""Extract DVP overlay payloads from a PS2 ELF main load image.

The overlay table supplies EE/VU addresses. The matching .DVP.overlay section
supplies the payload size; the actual bytes are taken from the main image at
the EE address. A JSON manifest records each extracted range.
"""
from __future__ import annotations

import argparse
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


def extract(elf_path: Path, output_dir: Path) -> dict[str, Any]:
    data = elf_path.read_bytes()
    report = inspect_elf(elf_path)
    sections = {section["name"]: section for section in report["sections"]}
    main = sections.get("main")
    if main is None:
        raise ValueError("ELF has no main section")

    output_dir.mkdir(parents=True, exist_ok=True)
    records = []
    for overlay in report["dvp_overlays"]:
        marker = sections.get(overlay["section_name"])
        if marker is None:
            raise ValueError(f"Missing marker section {overlay['section_name']}")
        address = overlay["ee_address"]
        start = main["file_offset"] + address - main["address"]
        end = start + marker["size"]
        main_end = main["file_offset"] + main["size"]
        if address < main["address"] or end > main_end or end > len(data):
            raise ValueError(f"Overlay {overlay['index']} is outside main image")
        payload = data[start:end]
        if len(payload) % 8:
            raise ValueError(f"Overlay {overlay['index']} size is not 8-byte aligned")

        filename = (
            f"overlay_{overlay['index']:02d}_"
            f"ee_{address:08X}_vu_{overlay['vu_address']:04X}.bin"
        )
        (output_dir / filename).write_bytes(payload)
        records.append({
            "index": overlay["index"],
            "filename": filename,
            "ee_address": f"0x{address:08X}",
            "vu_address": f"0x{overlay['vu_address']:08X}",
            "file_offset": f"0x{start:X}",
            "size": len(payload),
        })

    manifest = {
        "source": elf_path.name,
        "source_sha1": report["sha1"],
        "entry_point": f"0x{report['elf']['entry_point']:08X}",
        "overlay_count": len(records),
        "overlays": records,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=Path)
    parser.add_argument("-o", "--output-dir", type=Path, required=True)
    args = parser.parse_args()
    manifest = extract(args.elf, args.output_dir)
    print(f"Extracted {manifest['overlay_count']} overlays to {args.output_dir}")


if __name__ == "__main__":
    main()
