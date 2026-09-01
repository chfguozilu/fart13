#!/usr/bin/env python3
"""Inspect, salvage and extract Android runtime-profile record streams."""

import argparse
import collections
import hashlib
import json
import pathlib
import struct
import sys
import zlib


FILE_HEADER = struct.Struct("<8sII")
RECORD_HEADER = struct.Struct("<IIBBHIIIIIQQQQQI20s")
FILE_FOOTER = struct.Struct("<8sQQQ")
FOOTER_MAGIC = b"RPRDONE\x00"
FILE_MAGICS = {
    b"RTPR13\x00\x00": 0x31525052,  # current: "RPR1"
    b"FART13\x00\x00": 0x31545246,  # legacy files remain readable
}
SUPPORTED_VERSIONS = {1, 2}
DEX_HEADER_SIZE = 0x70
DEX_ENDIAN_CONSTANT = 0x12345678
STAGES = {
    0: "dex-image",
    1: "invoke-pre",
    2: "switch-interpreter-entry",
    3: "nterp-entry",
    4: "quick-to-interpreter-bridge",
    5: "interpreter-from-invoke",
}


def parse_dex_version(value):
    if len(value) != 3 or not value.isdigit():
        raise argparse.ArgumentTypeError("Dex version must contain exactly three digits")
    return value.encode("ascii")


def valid_standard_dex_version(data):
    if (len(data) >= 8 and data[0:4] == b"dex\n" and data[7] == 0 and
            all(48 <= byte <= 57 for byte in data[4:7])):
        return bytes(data[4:7])
    return None


def range_is_valid(file_size, item_count, item_offset, item_size):
    if item_count == 0:
        return item_offset == 0 or item_offset <= file_size
    return (item_offset >= DEX_HEADER_SIZE and item_offset <= file_size and
            item_count <= (file_size - item_offset) // item_size)


def plausible_standard_dex(data):
    """Recognize a standard Dex whose 8-byte magic may have been erased."""
    if len(data) < DEX_HEADER_SIZE:
        return False, "payload is smaller than a standard Dex header"
    file_size, header_size, endian = struct.unpack_from("<III", data, 32)
    if file_size != len(data):
        return False, f"header file_size={file_size}, payload_size={len(data)}"
    if header_size != DEX_HEADER_SIZE:
        return False, f"unexpected header_size={header_size}"
    if endian != DEX_ENDIAN_CONSTANT:
        return False, f"unsupported endian_tag={endian:#x}"

    sections = (
        ("string_ids", 56, 4),
        ("type_ids", 64, 4),
        ("proto_ids", 72, 12),
        ("field_ids", 80, 8),
        ("method_ids", 88, 8),
        ("class_defs", 96, 32),
    )
    for name, header_offset, item_size in sections:
        count, offset = struct.unpack_from("<II", data, header_offset)
        if not range_is_valid(file_size, count, offset, item_size):
            return False, f"invalid {name} range"
    data_size, data_offset = struct.unpack_from("<II", data, 104)
    if data_offset > file_size or data_size > file_size - data_offset:
        return False, "invalid data section range"
    return True, "standard Dex header structure is plausible"


def normalize_dex_image(payload, known_versions, forced_version, repair_enabled):
    """Return standalone Dex bytes plus a detailed repair report."""
    report = {
        "standard_dex": False,
        "changed": False,
        "magic_repaired": False,
        "signature_repaired": False,
        "checksum_repaired": False,
        "version": None,
        "version_source": None,
        "raw_magic": payload[:8].hex(),
    }
    plausible, reason = plausible_standard_dex(payload)
    report["reason"] = reason
    if not plausible:
        report["status"] = "not-standard-dex"
        return payload, report

    report["standard_dex"] = True
    existing_version = valid_standard_dex_version(payload)

    if not repair_enabled:
        report["status"] = "repair-disabled"
        report["version"] = (existing_version.decode("ascii")
                             if existing_version is not None else None)
        if existing_version is not None:
            known_versions[existing_version] += 1
        return payload, report

    if existing_version is not None:
        version = existing_version
        version_source = "existing-magic"
    elif forced_version is not None:
        version = forced_version
        version_source = "command-line"
    elif known_versions:
        version = known_versions.most_common(1)[0][0]
        version_source = "other-captured-dex"
    else:
        # 035 is the oldest broadly supported standard Dex version. Use it only
        # when the shell erased all version evidence and no sibling Dex exists;
        # callers can override this decision with --dex-version.
        version = b"035"
        version_source = "fallback-035"

    result = bytearray(payload)
    expected_magic = b"dex\n" + version + b"\x00"
    if result[:8] != expected_magic:
        result[:8] = expected_magic
        report["magic_repaired"] = True

    expected_signature = hashlib.sha1(result[32:]).digest()
    if result[12:32] != expected_signature:
        result[12:32] = expected_signature
        report["signature_repaired"] = True

    expected_checksum = zlib.adler32(result[12:]) & 0xffffffff
    old_checksum = struct.unpack_from("<I", result, 8)[0]
    if old_checksum != expected_checksum:
        struct.pack_into("<I", result, 8, expected_checksum)
        report["checksum_repaired"] = True

    report["changed"] = (report["magic_repaired"] or
                         report["signature_repaired"] or
                         report["checksum_repaired"])
    report["status"] = "repaired" if report["changed"] else "valid"
    report["version"] = version.decode("ascii")
    report["version_source"] = version_source
    report["output_magic"] = bytes(result[:8]).hex()
    report["output_signature"] = bytes(result[12:32]).hex()
    report["output_checksum"] = f"0x{expected_checksum:08x}"
    known_versions[version] += 1
    return bytes(result), report


def damage(integrity, strict, status, message, offset, file_size):
    integrity.update({
        "status": status,
        "complete": False,
        "message": message,
        "last_good_record_end": integrity["last_good_record_end"],
        "damage_offset": offset,
        "trailing_bytes": file_size - offset,
    })
    if strict:
        raise EOFError(message)
    print(f"warning: {message}; complete records will still be used", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=pathlib.Path, help=".rpr runtime record file")
    parser.add_argument("--extract", type=pathlib.Path,
                        help="directory in which CodeItem .bin files are created")
    parser.add_argument("--summary", action="store_true",
                        help="stream records and print only counts plus Dex image metadata")
    parser.add_argument("--dex-only", action="store_true",
                        help="with --extract, write only stage-0 Dex images")
    parser.add_argument("--strict", action="store_true",
                        help="fail instead of salvaging complete records before a damaged tail")
    parser.add_argument("--no-repair-dex", action="store_true",
                        help="extract stage-0 payloads byte-for-byte without header repair")
    parser.add_argument("--dex-version", type=parse_dex_version,
                        help="three-digit version used when a shell erased the Dex magic")
    args = parser.parse_args()

    if args.extract is not None:
        args.extract.mkdir(parents=True, exist_ok=True)

    records = []
    stage_counts = collections.Counter()
    dex_images = []
    known_dex_versions = collections.Counter()
    file_size = args.input.stat().st_size
    integrity = {
        "status": "unknown",
        "complete": False,
        "format_version": None,
        "footer_present": False,
        "last_good_record_end": FILE_HEADER.size,
        "damage_offset": None,
        "trailing_bytes": 0,
        "message": None,
    }

    with args.input.open("rb") as stream:
        raw_file_header = stream.read(FILE_HEADER.size)
        if len(raw_file_header) != FILE_HEADER.size:
            raise EOFError(
                f"truncated file header: expected {FILE_HEADER.size}, got {len(raw_file_header)}")
        magic, version, endian = FILE_HEADER.unpack(raw_file_header)
        if magic not in FILE_MAGICS:
            raise ValueError(f"bad file magic: {magic!r}")
        record_magic_expected = FILE_MAGICS[magic]
        if version not in SUPPORTED_VERSIONS or endian != DEX_ENDIAN_CONSTANT:
            raise ValueError(f"unsupported version/endian: {version}/{endian:#x}")
        integrity["format_version"] = version

        ordinal = 0
        record_bytes = 0
        while True:
            record_offset = stream.tell()
            prefix = stream.read(8)
            if not prefix:
                if version == 1:
                    integrity.update({
                        "status": "legacy-clean-eof",
                        "complete": True,
                        "message": "v1 has no commit footer; EOF is record-aligned",
                    })
                else:
                    damage(integrity, args.strict, "missing-footer",
                           "v2 stream ended without its commit footer",
                           record_offset, file_size)
                break

            if version >= 2 and prefix == FOOTER_MAGIC:
                footer_tail = stream.read(FILE_FOOTER.size - len(prefix))
                if len(footer_tail) != FILE_FOOTER.size - len(prefix):
                    damage(integrity, args.strict, "truncated-footer",
                           f"truncated commit footer at offset {record_offset}",
                           record_offset, file_size)
                    break
                _, footer_records, footer_record_bytes, footer_file_size = \
                    FILE_FOOTER.unpack(prefix + footer_tail)
                actual_end = stream.tell()
                problems = []
                if footer_records != ordinal:
                    problems.append(
                        f"footer record_count={footer_records}, parsed={ordinal}")
                if footer_record_bytes != record_bytes:
                    problems.append(
                        f"footer record_bytes={footer_record_bytes}, parsed={record_bytes}")
                if footer_file_size != actual_end or footer_file_size != file_size:
                    problems.append(
                        f"footer file_size={footer_file_size}, actual={file_size}")
                integrity["footer_present"] = True
                integrity["footer"] = {
                    "record_count": footer_records,
                    "record_bytes": footer_record_bytes,
                    "file_size": footer_file_size,
                }
                if problems:
                    damage(integrity, args.strict, "footer-mismatch",
                           "; ".join(problems), record_offset, file_size)
                else:
                    integrity.update({
                        "status": "complete",
                        "complete": True,
                        "message": "commit footer and stream lengths are valid",
                        "trailing_bytes": 0,
                    })
                break

            raw_header = prefix + stream.read(RECORD_HEADER.size - len(prefix))
            if len(raw_header) != RECORD_HEADER.size:
                damage(integrity, args.strict, "truncated-record-header",
                       (f"truncated record header at record {ordinal}, offset {record_offset}: "
                        f"expected {RECORD_HEADER.size}, got {len(raw_header)}"),
                       record_offset, file_size)
                break

            fields = RECORD_HEADER.unpack(raw_header)
            (record_magic, record_size, stage, flags, _reserved,
             method_idx, original_code_off, code_item_size,
             header_checksum, location_checksum, dex_size, dex_begin,
             data_begin, data_size, runtime_code_item, location_size,
             signature) = fields

            if record_magic != record_magic_expected:
                damage(integrity, args.strict, "bad-record-magic",
                       f"bad record magic at record {ordinal}, offset {record_offset}",
                       record_offset, file_size)
                break
            expected_size = RECORD_HEADER.size + location_size + code_item_size
            if record_size != expected_size:
                damage(integrity, args.strict, "bad-record-size",
                       (f"record {ordinal} at offset {record_offset}: "
                        f"size={record_size}, expected={expected_size}"),
                       record_offset, file_size)
                break
            if record_size > file_size - record_offset:
                damage(integrity, args.strict, "truncated-record",
                       (f"truncated record {ordinal} at offset {record_offset}: "
                        f"needs {record_size} bytes, has {file_size - record_offset}"),
                       record_offset, file_size)
                break

            raw_location = stream.read(location_size)
            payload = stream.read(code_item_size)
            if len(raw_location) != location_size or len(payload) != code_item_size:
                damage(integrity, args.strict, "truncated-record",
                       f"truncated payload at record {ordinal}, offset {record_offset}",
                       record_offset, file_size)
                break
            location = raw_location.decode("utf-8", errors="replace")
            metadata = {
                "ordinal": ordinal,
                "stage": STAGES.get(stage, f"unknown-{stage}"),
                "has_original_code_off": bool(flags & 1),
                "code_item_in_dex": bool(flags & 2),
                "is_compact_dex": bool(flags & 4),
                "is_dex_image": stage == 0,
                "dex_method_idx": method_idx,
                "original_code_off": original_code_off,
                "code_item_size": code_item_size,
                "dex_header_checksum": f"0x{header_checksum:08x}",
                "dex_location_checksum": f"0x{location_checksum:08x}",
                "dex_size": dex_size,
                "dex_begin": f"0x{dex_begin:x}",
                "data_begin": f"0x{data_begin:x}",
                "data_size": data_size,
                "runtime_code_item": f"0x{runtime_code_item:x}",
                "dex_signature": signature.hex(),
                "dex_location": location,
                "code_item_sha256": hashlib.sha256(payload).hexdigest(),
            }

            extracted_payload = payload
            if stage == 0 and not metadata["is_compact_dex"]:
                extracted_payload, dex_report = normalize_dex_image(
                    payload,
                    known_dex_versions,
                    args.dex_version,
                    not args.no_repair_dex)
                dex_report["applied_to_extracted_file"] = args.extract is not None
                metadata["dex_repair"] = dex_report
                metadata["extracted_sha256"] = hashlib.sha256(extracted_payload).hexdigest()
                if (args.extract is not None and dex_report["changed"]):
                    print(
                        f"warning: repaired standalone Dex header for record {ordinal}: "
                        f"{location}", file=sys.stderr)

            stage_counts[metadata["stage"]] += 1
            if metadata["is_dex_image"]:
                dex_images.append(metadata)
            if not args.summary:
                records.append(metadata)

            if args.extract is not None and (not args.dex_only or stage == 0):
                stem = (f"{ordinal:06d}_m{method_idx}_"
                        f"{STAGES.get(stage, stage)}_{signature.hex()[:12]}")
                suffix = ".dex" if stage == 0 else ".bin"
                (args.extract / f"{stem}{suffix}").write_bytes(extracted_payload)
                (args.extract / f"{stem}.json").write_text(
                    json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8")

            ordinal += 1
            record_bytes += record_size
            integrity["last_good_record_end"] = stream.tell()

    output = ({
        "total_records": sum(stage_counts.values()),
        "stage_counts": dict(stage_counts),
        "dex_images": dex_images,
        "integrity": integrity,
    } if args.summary else records)
    json.dump(output, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
