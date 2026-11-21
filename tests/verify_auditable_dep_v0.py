#!/usr/bin/env python3
"""Cross-platform ELF & PE `.dep-v0` cargo-auditable verification gate (CSE-29).

Parses ELF32/ELF64 (Linux) and PE32/PE32+ (Windows) binary section headers directly
with strict bounds checking, locates the `.dep-v0` section embedded by
`cargo auditable build --workspace --release --locked`, verifies full zlib EOF/Adler-32
integrity (permitting only trailing null alignment padding), and validates that the
embedded JSON dependency manifest is a JSON object with a non-empty `packages` list
containing at least one OmniConnect Sentinel workspace crate.

Usage:
  python3 tests/verify_auditable_dep_v0.py target/release/sentinel ...
  python3 tests/verify_auditable_dep_v0.py --self-test
"""

from __future__ import annotations

import json
import pathlib
import struct
import sys
import zlib
from typing import Optional

TARGET_SECTION = b".dep-v0"
EXPECTED_SENTINEL_CRATES = {
    "sentinel-cli",
    "sentinel-core",
    "sentinel-cdr",
    "sentinel-sys",
    "sentinel-proto",
}


def extract_dep_v0_elf(data: bytes) -> Optional[bytes]:
    """Extract raw `.dep-v0` section bytes from an ELF32 or ELF64 binary with strict bounds checks."""
    if len(data) < 52 or data[:4] != b"\x7fELF":
        return None
    ei_class = data[4]
    ei_data = data[5]
    if ei_data not in (1, 2):
        return None
    endian = "<" if ei_data == 1 else ">"

    if ei_class == 2:  # ELF64
        if len(data) < 64:
            return None
        e_shoff = struct.unpack_from(f"{endian}Q", data, 40)[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(f"{endian}HHH", data, 58)
        min_shentsize = 64
        off_fmt = f"{endian}QQ"
        off_delta = 24
        off_end = 40
    elif ei_class == 1:  # ELF32
        e_shoff = struct.unpack_from(f"{endian}I", data, 32)[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(f"{endian}HHH", data, 46)
        min_shentsize = 40
        off_fmt = f"{endian}II"
        off_delta = 16
        off_end = 24
    else:
        return None

    if e_shoff == 0 or e_shnum == 0 or e_shentsize < min_shentsize or e_shstrndx >= e_shnum:
        return None
    if e_shoff + e_shnum * e_shentsize > len(data):
        return None

    str_hdr = e_shoff + e_shstrndx * e_shentsize
    if str_hdr + off_end > len(data):
        return None
    str_off, str_size = struct.unpack_from(off_fmt, data, str_hdr + off_delta)
    if str_off + str_size > len(data):
        return None
    shstrtab = data[str_off : str_off + str_size]

    for idx in range(e_shnum):
        hdr = e_shoff + idx * e_shentsize
        if hdr + off_end > len(data):
            return None
        sh_name = struct.unpack_from(f"{endian}I", data, hdr)[0]
        if sh_name >= len(shstrtab):
            continue
        end = shstrtab.find(b"\x00", sh_name)
        name = shstrtab[sh_name : (end if end != -1 else len(shstrtab))]
        if name == TARGET_SECTION:
            sh_offset, sh_size = struct.unpack_from(off_fmt, data, hdr + off_delta)
            if sh_size == 0 or sh_offset + sh_size > len(data):
                return None
            return data[sh_offset : sh_offset + sh_size]
    return None


def extract_dep_v0_pe(data: bytes) -> Optional[bytes]:
    """Extract raw `.dep-v0` section bytes from a Windows PE32/PE32+ binary with strict bounds checks."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return None

    coff_off = pe_offset + 4
    num_sections = struct.unpack_from("<H", data, coff_off + 2)[0]
    ptr_symtab, num_syms = struct.unpack_from("<II", data, coff_off + 8)
    opt_header_size = struct.unpack_from("<H", data, coff_off + 16)[0]
    sec_table = coff_off + 20 + opt_header_size
    if sec_table + num_sections * 40 > len(data):
        return None
    strtab_off = ptr_symtab + num_syms * 18 if ptr_symtab and num_syms else 0

    for idx in range(num_sections):
        entry = sec_table + idx * 40
        raw_name = data[entry : entry + 8]
        if raw_name.startswith(b"/") and strtab_off > 0:
            try:
                offset = int(raw_name[1:].split(b"\x00", 1)[0].decode("ascii"))
            except ValueError:
                name = raw_name.rstrip(b"\x00")
            else:
                if offset < 0 or strtab_off + offset >= len(data):
                    continue
                end = data.find(b"\x00", strtab_off + offset)
                name = data[strtab_off + offset : end] if end != -1 else b""
        else:
            name = raw_name.rstrip(b"\x00")

        if name == TARGET_SECTION:
            virtual_size, _virtual_addr, raw_size, raw_ptr = struct.unpack_from(
                "<IIII", data, entry + 8
            )
            if raw_ptr == 0 or raw_size == 0 or raw_ptr + raw_size > len(data):
                return None
            effective_len = virtual_size if 0 < virtual_size <= raw_size else raw_size
            return data[raw_ptr : raw_ptr + effective_len]
    return None


def verify_bytes(data: bytes, label: str) -> tuple[str, int]:
    """Verify `.dep-v0` presence, full zlib Adler-32/EOF integrity, and JSON manifest on raw binary bytes."""
    if data[:4] == b"\x7fELF":
        fmt = "ELF"
        section = extract_dep_v0_elf(data)
    elif data[:2] == b"MZ":
        fmt = "PE"
        section = extract_dep_v0_pe(data)
    else:
        raise ValueError(f"{label}: unrecognized executable format (expected ELF or PE)")

    if not section:
        raise ValueError(f"{label} ({fmt}): missing or empty '.dep-v0' cargo-auditable section")

    decompressor = zlib.decompressobj()
    try:
        payload = decompressor.decompress(section) + decompressor.flush()
    except zlib.error as exc:
        raise ValueError(f"{label} ({fmt}): '.dep-v0' zlib decompression failed: {exc}") from exc

    if not decompressor.eof:
        raise ValueError(
            f"{label} ({fmt}): '.dep-v0' zlib stream truncated before EOF / Adler-32 checksum"
        )
    if decompressor.unused_data.strip(b"\x00"):
        raise ValueError(
            f"{label} ({fmt}): '.dep-v0' contains non-zero trailing bytes after zlib stream"
        )

    try:
        manifest = json.loads(payload.decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"{label} ({fmt}): '.dep-v0' JSON decode failed: {exc}") from exc

    if not isinstance(manifest, dict):
        raise ValueError(f"{label} ({fmt}): '.dep-v0' JSON root must be an object")

    packages = manifest.get("packages")
    if not isinstance(packages, list) or len(packages) == 0:
        raise ValueError(f"{label} ({fmt}): '.dep-v0' manifest has empty or missing 'packages'")

    names = {pkg.get("name") for pkg in packages if isinstance(pkg, dict)}
    if not (names & EXPECTED_SENTINEL_CRATES):
        raise ValueError(
            f"{label} ({fmt}): '.dep-v0' manifest does not reference any Sentinel crate ({sorted(EXPECTED_SENTINEL_CRATES)})"
        )

    return fmt, len(packages)


def verify_binary(path: pathlib.Path) -> tuple[str, int]:
    """Verify `.dep-v0` presence and valid zlib+JSON dependency manifest on `path`."""
    return verify_bytes(path.read_bytes(), str(path))


def _build_synthetic_pe(section_name: bytes, section_bytes: bytes, virtual_size: int) -> bytes:
    pe_offset = 0x80
    opt_size = 0x10
    sec_table = pe_offset + 24 + opt_size
    raw_ptr = 0x200
    padded_len = max(512, ((len(section_bytes) + 511) // 512) * 512)
    padded_sec = section_bytes + b"\x00" * (padded_len - len(section_bytes))
    pe = bytearray(raw_ptr + len(padded_sec))
    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, pe_offset)
    pe[pe_offset : pe_offset + 4] = b"PE\x00\x00"
    struct.pack_into("<H", pe, pe_offset + 6, 1)  # NumberOfSections = 1
    struct.pack_into("<H", pe, pe_offset + 20, opt_size)  # SizeOfOptionalHeader
    pe[sec_table : sec_table + 8] = section_name.ljust(8, b"\x00")[:8]
    struct.pack_into("<IIII", pe, sec_table + 8, virtual_size, 0x1000, len(padded_sec), raw_ptr)
    pe[raw_ptr : raw_ptr + len(padded_sec)] = padded_sec
    return bytes(pe)


def _build_synthetic_elf64(section_bytes: bytes) -> bytes:
    shstrtab = b"\x00.shstrtab\x00.dep-v0\x00"
    shstr_off = 0x80
    dep_off = 0x100
    shoff = dep_off + max(0x100, len(section_bytes))
    elf = bytearray(shoff + 3 * 64)
    elf[0:4] = b"\x7fELF"
    elf[4] = 2  # ELFCLASS64
    elf[5] = 1  # ELFDATA2LSB
    struct.pack_into("<Q", elf, 40, shoff)
    struct.pack_into("<HHH", elf, 58, 64, 3, 1)  # entsize=64, shnum=3, shstrndx=1
    elf[shstr_off : shstr_off + len(shstrtab)] = shstrtab
    elf[dep_off : dep_off + len(section_bytes)] = section_bytes
    # Section 1: .shstrtab
    struct.pack_into("<I", elf, shoff + 64, 1)
    struct.pack_into("<QQ", elf, shoff + 64 + 24, shstr_off, len(shstrtab))
    # Section 2: .dep-v0
    struct.pack_into("<I", elf, shoff + 128, 11)
    struct.pack_into("<QQ", elf, shoff + 128 + 24, dep_off, len(section_bytes))
    return bytes(elf)


def _expect_value_error(data: bytes, label: str) -> None:
    try:
        verify_bytes(data, label)
    except ValueError:
        return
    raise AssertionError(f"Expected ValueError for adversarial fixture '{label}', but it passed!")


def run_self_test() -> None:
    """Validate positive and adversarial ELF64 & PE32+ `.dep-v0` verification cases."""
    sample_json = json.dumps(
        {"packages": [{"name": "sentinel-core", "version": "0.1.0", "source": "local"}]}
    ).encode("utf-8")
    compressed = zlib.compress(sample_json)

    # 1. Valid PE32+ (exact VirtualSize) & valid PE32+ (VirtualSize=0 with null alignment padding)
    assert verify_bytes(_build_synthetic_pe(b".dep-v0", compressed, len(compressed)), "pe_exact") == ("PE", 1)
    assert verify_bytes(_build_synthetic_pe(b".dep-v0", compressed, 0), "pe_zero_vsize_padded") == ("PE", 1)

    # 2. Valid ELF64
    assert verify_bytes(_build_synthetic_elf64(compressed), "elf64_valid") == ("ELF", 1)

    # 3. Negative PE: missing `.dep-v0` section
    _expect_value_error(_build_synthetic_pe(b".rdata", compressed, len(compressed)), "pe_missing_dep")

    # 4. Adversarial zlib: stripped 4-byte Adler-32 checksum (incomplete stream, eof=False)
    _expect_value_error(
        _build_synthetic_pe(b".dep-v0", compressed[:-4], len(compressed) - 4),
        "pe_stripped_adler32",
    )

    # 5. Adversarial trailing non-zero corruption after zlib stream
    corrupt_trailing = compressed + b"CORRUPT"
    _expect_value_error(
        _build_synthetic_pe(b".dep-v0", corrupt_trailing, len(corrupt_trailing)),
        "pe_nonzero_trailing",
    )

    # 6. Adversarial JSON root (list instead of dict) must raise ValueError, never AttributeError
    non_dict_zlib = zlib.compress(b'[{"name":"sentinel-core"}]')
    _expect_value_error(
        _build_synthetic_elf64(non_dict_zlib),
        "elf_non_dict_json",
    )

    # 7. Malformed / truncated ELF section table must raise ValueError, never struct.error
    bad_elf = bytearray(64)
    bad_elf[0:4] = b"\x7fELF"
    bad_elf[4] = 2
    bad_elf[5] = 1
    struct.pack_into("<Q", bad_elf, 40, 99999)
    struct.pack_into("<HHH", bad_elf, 58, 64, 5, 1)
    _expect_value_error(bytes(bad_elf), "elf_truncated_shoff")

    print("SELF-TEST PASS: ELF64 and PE32+ .dep-v0 positive and adversarial verifiers passed.")


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        run_self_test()
        return 0
    if not argv:
        print("Usage: verify_auditable_dep_v0.py <binary> [<binary> ...] | --self-test", file=sys.stderr)
        return 2

    for arg in argv:
        p = pathlib.Path(arg)
        if not p.is_file():
            print(f"ERROR: Release binary not found: {p}", file=sys.stderr)
            return 1
        try:
            fmt, pkg_count = verify_binary(p)
        except ValueError as exc:
            print(f"FAIL: {exc}", file=sys.stderr)
            return 1
        print(f"PASS: {p} ({fmt}) contains valid '.dep-v0' manifest ({pkg_count} packages)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
