#!/usr/bin/env python3
import argparse
import os
import struct
import subprocess
import sys
import tempfile

EOCD_SIG = b"PK\x05\x06"
EOCD_MIN_SIZE = 22
EOCD_COMMENT_MAX = 0xFFFF

HAP_SIGN_BLOCK_TAIL_SIZE = 32
SUB_BLOCK_HEAD_SIZE = 12

HAP_SIGNATURE_SCHEME_V1_BLOCK_ID = 0x20000000
HAP_PROOF_OF_ROTATION_BLOCK_ID = 0x20000001
HAP_PROFILE_BLOCK_ID = 0x20000002
HAP_PROPERTY_BLOCK_ID = 0x20000003
HAP_CODE_SIGN_BLOCK_ID = 0x30000001

CODE_SIGN_BLOCK_HEADER_SIZE = 32
SEGMENT_HEADER_SIZE = 12
FS_VERITY_INFO_SEG_SIZE = 64
SIGN_INFO_SALT_SIZE = 32
MERKLE_EXT_DATA_SIZE = 80


def read_eocd(f):
    file_size = os.fstat(f.fileno()).st_size
    if file_size < EOCD_MIN_SIZE:
        return None
    max_search = min(file_size, EOCD_MIN_SIZE + EOCD_COMMENT_MAX)
    f.seek(file_size - max_search)
    buf = f.read(max_search)
    for i in range(max_search - EOCD_MIN_SIZE, -1, -1):
        if buf[i:i + 4] != EOCD_SIG:
            continue
        comment_len = struct.unpack_from("<H", buf, i + 20)[0]
        expected = max_search - i - EOCD_MIN_SIZE
        if comment_len == expected:
            return file_size - max_search + i, buf[i:i + EOCD_MIN_SIZE + comment_len]
    return None


def type_name(type_id):
    return {
        HAP_SIGNATURE_SCHEME_V1_BLOCK_ID: "HAP_SIGNATURE_SCHEME_V1_BLOCK_ID",
        HAP_PROOF_OF_ROTATION_BLOCK_ID: "HAP_PROOF_OF_ROTATION_BLOCK_ID",
        HAP_PROFILE_BLOCK_ID: "HAP_PROFILE_BLOCK_ID",
        HAP_PROPERTY_BLOCK_ID: "HAP_PROPERTY_BLOCK_ID",
        HAP_CODE_SIGN_BLOCK_ID: "HAP_CODE_SIGN_BLOCK_ID",
    }.get(type_id, "UNKNOWN")


def read_u32(b, off):
    return struct.unpack_from("<I", b, off)[0]


def read_i32(b, off):
    return struct.unpack_from("<i", b, off)[0]


def read_i64(b, off):
    return struct.unpack_from("<q", b, off)[0]


def read_le_i32(b, off):
    return struct.unpack_from("<i", b, off)[0]


def read_le_i64(b, off):
    return struct.unpack_from("<q", b, off)[0]


def read_tlv(data, off):
    if off >= len(data):
        return None
    tag = data[off]
    off += 1
    if off >= len(data):
        return None
    length = data[off]
    off += 1
    if length & 0x80:
        num = length & 0x7f
        if num == 0 or off + num > len(data):
            return None
        length = int.from_bytes(data[off:off + num], "big")
        off += num
    value_start = off
    value_end = off + length
    if value_end > len(data):
        return None
    return tag, value_start, value_end


def extract_pkcs7_signed_content(pkcs7_bytes):
    tlv = read_tlv(pkcs7_bytes, 0)
    if not tlv or tlv[0] != 0x30:
        return None
    _, s_start, s_end = tlv
    content = pkcs7_bytes[s_start:s_end]
    off = 0
    tlv = read_tlv(content, off)
    if not tlv or tlv[0] != 0x06:
        return None
    off = tlv[2]
    tlv = read_tlv(content, off)
    if not tlv or tlv[0] != 0xA0:
        return None
    signed_data_bytes = content[tlv[1]:tlv[2]]
    tlv = read_tlv(signed_data_bytes, 0)
    if not tlv or tlv[0] != 0x30:
        return None
    signed_data = signed_data_bytes[tlv[1]:tlv[2]]
    off = 0
    tlv = read_tlv(signed_data, off)
    if not tlv or tlv[0] != 0x02:
        return None
    off = tlv[2]
    tlv = read_tlv(signed_data, off)
    if not tlv or tlv[0] != 0x31:
        return None
    off = tlv[2]
    tlv = read_tlv(signed_data, off)
    if not tlv or tlv[0] != 0x30:
        return None
    eci = signed_data[tlv[1]:tlv[2]]
    off = 0
    tlv = read_tlv(eci, off)
    if not tlv or tlv[0] != 0x06:
        return None
    off = tlv[2]
    tlv = read_tlv(eci, off)
    if not tlv or tlv[0] != 0xA0:
        return None
    econtent_container = eci[tlv[1]:tlv[2]]
    tlv = read_tlv(econtent_container, 0)
    if not tlv or tlv[0] != 0x04:
        return None
    return econtent_container[tlv[1]:tlv[2]]


def parse_digest_list(data):
    if len(data) < 8:
        return None
    version = struct.unpack_from("<i", data, 0)[0]
    count = struct.unpack_from("<i", data, 4)[0]
    off = 8
    pairs = []
    for _ in range(count):
        if off + 12 > len(data):
            return None
        pair_len = struct.unpack_from("<i", data, off)[0]
        off += 4
        alg_id = struct.unpack_from("<i", data, off)[0]
        off += 4
        digest_len = struct.unpack_from("<i", data, off)[0]
        off += 4
        if off + digest_len > len(data):
            return None
        digest = data[off:off + digest_len]
        off += digest_len
        pairs.append((pair_len, alg_id, digest_len, digest))
    return version, count, pairs


def parse_sign_info(data):
    if len(data) < 4 * 3 + 8 + SIGN_INFO_SALT_SIZE + 8:
        return None
    off = 0
    salt_size = read_le_i32(data, off)
    off += 4
    sig_size = read_le_i32(data, off)
    off += 4
    flags = read_le_i32(data, off)
    off += 4
    data_size = read_le_i64(data, off)
    off += 8
    salt = data[off:off + SIGN_INFO_SALT_SIZE]
    off += SIGN_INFO_SALT_SIZE
    extension_num = read_le_i32(data, off)
    off += 4
    extension_offset = read_le_i32(data, off)
    off += 4
    if sig_size < 0 or off + sig_size > len(data):
        return None
    signature = data[off:off + sig_size]
    off += sig_size
    padding_len = (4 - (sig_size % 4)) % 4
    off += padding_len
    merkle = None
    if extension_num > 0:
        if off + 8 + MERKLE_EXT_DATA_SIZE > len(data):
            return None
        ext_type = read_le_i32(data, off)
        off += 4
        ext_size = read_le_i32(data, off)
        off += 4
        merkle_size = read_le_i64(data, off)
        off += 8
        merkle_offset = read_le_i64(data, off)
        off += 8
        root_hash = data[off:off + 64]
        off += 64
        merkle = {
            "type": ext_type,
            "size": ext_size,
            "merkle_size": merkle_size,
            "merkle_offset": merkle_offset,
            "root_hash": root_hash,
        }
    return {
        "salt_size": salt_size,
        "sig_size": sig_size,
        "flags": flags,
        "data_size": data_size,
        "extension_num": extension_num,
        "extension_offset": extension_offset,
        "signature_len": len(signature),
        "merkle": merkle,
    }


def parse_codesign_block(data):
    if len(data) < CODE_SIGN_BLOCK_HEADER_SIZE:
        return None
    magic = read_le_i64(data, 0)
    version = read_le_i32(data, 8)
    block_size = read_le_i32(data, 12)
    segment_num = read_le_i32(data, 16)
    flags = read_le_i32(data, 20)
    reserved = data[24:32]
    off = CODE_SIGN_BLOCK_HEADER_SIZE
    segments = []
    for _ in range(segment_num):
        if off + SEGMENT_HEADER_SIZE > len(data):
            return None
        seg_type = read_le_i32(data, off)
        seg_offset = read_le_i32(data, off + 4)
        seg_size = read_le_i32(data, off + 8)
        segments.append({
            "type": seg_type,
            "offset": seg_offset,
            "size": seg_size,
        })
        off += SEGMENT_HEADER_SIZE
    return {
        "header": {
            "magic": magic,
            "version": version,
            "block_size": block_size,
            "segment_num": segment_num,
            "flags": flags,
            "reserved": reserved,
        },
        "segments": segments,
        "header_end": off,
    }


def segment_name(seg_type):
    return {
        0x1: "FS_VERITY_INFO",
        0x2: "HAP_META",
        0x3: "NATIVE_LIB_INFO",
    }.get(seg_type, "UNKNOWN")


def print_codesign_block(data, indent):
    parsed = parse_codesign_block(data)
    if parsed is None:
        print(f"{indent}codesign_block: <unavailable>")
        return
    header = parsed["header"]
    segments = parsed["segments"]
    print(f"{indent}codesign_block:")
    print(f"{indent}  header: magic={header['magic']} version={header['version']} "
          f"block_size={header['block_size']} segment_num={header['segment_num']} "
          f"flags={header['flags']}")
    if segments:
        min_seg_off = min(s["offset"] for s in segments)
        merkle_len = max(0, min_seg_off - parsed["header_end"])
        print(f"{indent}  merkle_tree_region_len: {merkle_len}")
    for idx, seg in enumerate(sorted(segments, key=lambda x: x["offset"])):
        seg_type = seg["type"]
        name = segment_name(seg_type)
        seg_start = seg["offset"]
        seg_end = seg["offset"] + seg["size"]
        print(f"{indent}  segment[{idx}]: type=0x{seg_type:08x} ({name}) "
              f"offset={seg_start} size={seg['size']}")
        if seg_end > len(data) or seg["size"] <= 0:
            print(f"{indent}    data: <out of range>")
            continue
        seg_bytes = data[seg_start:seg_end]
        if seg_type == 0x1 and len(seg_bytes) >= FS_VERITY_INFO_SEG_SIZE:
            magic = read_le_i32(seg_bytes, 0)
            ver = seg_bytes[4]
            h_alg = seg_bytes[5]
            log2_bs = seg_bytes[6]
            print(f"{indent}    fsverity: magic=0x{magic:08x} version={ver} "
                  f"hash_alg={h_alg} log2_block={log2_bs}")
        elif seg_type == 0x2 and len(seg_bytes) >= 4:
            magic = read_le_i32(seg_bytes, 0)
            sign_info = parse_sign_info(seg_bytes[4:])
            print(f"{indent}    hap_info: magic=0x{magic:08x}")
            if sign_info:
                print(f"{indent}      sign_info: data_size={sign_info['data_size']} "
                      f"sig_size={sign_info['sig_size']} flags={sign_info['flags']} "
                      f"extension_num={sign_info['extension_num']}")
                merkle = sign_info["merkle"]
                if merkle:
                    print(f"{indent}      merkle_ext: size={merkle['merkle_size']} "
                          f"offset={merkle['merkle_offset']} "
                          f"root_hash={merkle['root_hash'].hex()}")
            else:
                print(f"{indent}      sign_info: <unavailable>")
        elif seg_type == 0x3 and len(seg_bytes) >= 12:
            magic = read_le_i32(seg_bytes, 0)
            seg_size = read_le_i32(seg_bytes, 4)
            section_num = read_le_i32(seg_bytes, 8)
            print(f"{indent}    native_lib_info: magic=0x{magic:08x} "
                  f"segment_size={seg_size} section_num={section_num}")
            off = 12
            entries = []
            for _ in range(section_num):
                if off + 16 > len(seg_bytes):
                    break
                file_off = read_le_i32(seg_bytes, off)
                file_size = read_le_i32(seg_bytes, off + 4)
                sig_off = read_le_i32(seg_bytes, off + 8)
                sig_size = read_le_i32(seg_bytes, off + 12)
                entries.append((file_off, file_size, sig_off, sig_size))
                off += 16
            names = []
            for file_off, file_size, _, _ in entries:
                if file_off + file_size <= len(seg_bytes):
                    name_bytes = seg_bytes[file_off:file_off + file_size]
                    names.append(name_bytes.decode("utf-8", errors="replace"))
            if names:
                print(f"{indent}      files: {', '.join(names)}")
def main():
    parser = argparse.ArgumentParser(description="Print HAP signing block structure")
    parser.add_argument("hap", help="Path to .hap file")
    parser.add_argument("--openssl", action="store_true",
                        help="Dump PKCS7 details via openssl (pkcs7 -inform DER -text -print)")
    parser.add_argument("--codesign", action="store_true",
                        help="Parse embedded CodeSignBlock when present")
    args = parser.parse_args()

    with open(args.hap, "rb") as f:
        eocd_info = read_eocd(f)
        if not eocd_info:
            print("EOCD not found; not a valid ZIP/HAP.")
            return 1
        eocd_offset, eocd = eocd_info
        cd_offset = read_u32(eocd, 16)
        cd_size = read_u32(eocd, 12)

        print("HAP summary:")
        print(f"  eocd_offset: {eocd_offset}")
        print(f"  central_dir_offset: {cd_offset}")
        print(f"  central_dir_size: {cd_size}")

        if cd_offset < HAP_SIGN_BLOCK_TAIL_SIZE:
            print("No space for HAP signing block tail before Central Directory.")
            return 0

        tail_offset = cd_offset - HAP_SIGN_BLOCK_TAIL_SIZE
        f.seek(tail_offset)
        tail = f.read(HAP_SIGN_BLOCK_TAIL_SIZE)
        if len(tail) != HAP_SIGN_BLOCK_TAIL_SIZE:
            print("Failed to read signing block tail.")
            return 1

        block_count = read_i32(tail, 0)
        block_size = read_i64(tail, 4)
        magic_lo = read_i64(tail, 12)
        magic_hi = read_i64(tail, 20)
        version = read_i32(tail, 28)

        signing_block_offset = cd_offset - block_size
        if signing_block_offset < 0:
            print("Invalid signing block size or Central Directory offset.")
            return 1

        f.seek(signing_block_offset)
        block = f.read(block_size)
        if len(block) != block_size:
            print("Failed to read signing block.")
            return 1

        print("HAP signing block (address-ordered layout):")
        print(f"  start_offset: {signing_block_offset}")
        print(f"  end_offset: {signing_block_offset + block_size}")
        print(f"  size: {block_size}")

        if block_count <= 0:
            print("  sub-block heads: none")
            print("  sub-block values: none")
            print("  tail (signing block header at end):")
            print(f"    tail_offset: {tail_offset}")
            print(f"    block_count: {block_count}")
            print(f"    block_size: {block_size}")
            print(f"    magic_low: {magic_lo}")
            print(f"    magic_high: {magic_hi}")
            print(f"    version: {version}")
            return 0

        print("  sub-block heads (header region):")
        print(f"    head_region_offset: {signing_block_offset}")
        print(f"    head_region_size: {block_count * SUB_BLOCK_HEAD_SIZE}")
        sub_blocks = []
        for i in range(block_count):
            head_off = i * SUB_BLOCK_HEAD_SIZE
            if head_off + SUB_BLOCK_HEAD_SIZE > len(block):
                sub_blocks.append({"index": i, "error": "head out of range"})
                continue
            type_id = read_u32(block, head_off)
            length = read_u32(block, head_off + 4)
            offset = read_u32(block, head_off + 8)
            sub_blocks.append({
                "index": i,
                "type_id": type_id,
                "length": length,
                "offset": offset,
            })

        for entry in sub_blocks:
            if "error" in entry:
                print(f"    [{entry['index']}] {entry['error']}")
                continue
            type_id = entry["type_id"]
            length = entry["length"]
            offset = entry["offset"]
            abs_off = signing_block_offset + offset
            name = type_name(type_id)
            print(f"    [{entry['index']}] type=0x{type_id:08x} ({name})")
            print(f"         length={length} offset={offset} (abs={abs_off})")

        print("  sub-block values (by address order):")
        for entry in sorted(sub_blocks, key=lambda x: x.get("offset", 0)):
            if "error" in entry:
                continue
            type_id = entry["type_id"]
            length = entry["length"]
            offset = entry["offset"]
            abs_off = signing_block_offset + offset
            name = type_name(type_id)
            print(f"    [{entry['index']}] type=0x{type_id:08x} ({name})")
            print(f"         length={length} offset={offset} (abs={abs_off})")
            print(f"         end_offset: {abs_off + length}")

            data_end = offset + length
            if data_end > len(block):
                print("         data out of range")
                continue

            if type_id == HAP_PROPERTY_BLOCK_ID and length >= SUB_BLOCK_HEAD_SIZE:
                inner_type = read_u32(block, offset)
                inner_len = read_u32(block, offset + 4)
                inner_off = read_u32(block, offset + 8)
                if inner_type == HAP_CODE_SIGN_BLOCK_ID:
                    print("         embedded codesign:")
                    print(f"           type=0x{inner_type:08x} ({type_name(inner_type)})")
                    print(f"           length={inner_len} offset={inner_off} (abs)")
                    if args.codesign:
                        f.seek(inner_off)
                        code_sign_bytes = f.read(inner_len)
                        print_codesign_block(code_sign_bytes, "           ")
                    else:
                        print("           codesign_block: <use --codesign to parse>")
            if type_id == HAP_SIGNATURE_SCHEME_V1_BLOCK_ID:
                pkcs7_bytes = block[offset:offset + length]
                print("         pkcs7: present (use --openssl to dump full content)")
                signed_content = extract_pkcs7_signed_content(pkcs7_bytes)
                if signed_content is None:
                    print("         pkcs7_signed_content: <unavailable>")
                else:
                    parsed = parse_digest_list(signed_content)
                    if parsed is None:
                        print("         digest_list: <unavailable>")
                    else:
                        version_num, count, pairs = parsed
                        print(f"         digest_list: version={version_num} count={count}")
                        for idx, pair in enumerate(pairs):
                            _, alg_id, digest_len, digest = pair
                            print(f"           pair[{idx}]: alg_id={alg_id} digest_len={digest_len} "
                                  f"digest={digest.hex()}")
                if args.openssl:
                    with tempfile.NamedTemporaryFile(delete=False) as tmp:
                        tmp.write(pkcs7_bytes)
                        tmp_path = tmp.name
                    try:
                        result = subprocess.run(
                            ["openssl", "pkcs7", "-inform", "DER", "-print", "-noout", "-text", "-in", tmp_path],
                            capture_output=True,
                            text=True,
                            check=False,
                        )
                        if result.returncode == 0:
                            print("         pkcs7_openssl:")
                            for line in result.stdout.splitlines():
                                print(f"           {line}")
                        else:
                            print("         pkcs7_openssl: <failed>")
                            if result.stderr:
                                for line in result.stderr.splitlines():
                                    print(f"           {line}")
                    finally:
                        try:
                            os.unlink(tmp_path)
                        except OSError:
                            pass

        print("  tail (signing block header at end):")
        print(f"    tail_offset: {tail_offset}")
        print(f"    block_count: {block_count}")
        print(f"    block_size: {block_size}")
        print(f"    magic_low: {magic_lo}")
        print(f"    magic_high: {magic_hi}")
        print(f"    version: {version}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
