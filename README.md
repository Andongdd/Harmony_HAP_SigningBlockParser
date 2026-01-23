# Harmony HAP Parser

This repo documents the HAP signing block format and provides a small parser
to inspect real `.hap` files.

Small, self-contained tools and notes for inspecting HarmonyOS HAP signing
blocks. This repo focuses on the signing block layout, the sub-block types,
and a simple parser that prints a readable structure summary.

## Contents

- `HapStructure.md`
  - A concise description of HAP signing block layout, sub-block types,
    and signing/verify flows (based on open-source code).
- `HapSigning_Overview.md`
  - A higher-level summary of the signing scheme and a brief comparison with
    Android APK signing.
- `sample.hap` (example file)
  - A small test HAP for quick local parsing.
- `print_hap_signing_block.py`
  - A CLI that parses a `.hap` file and prints the HAP signing block structure.
  - It also prints the PKCS7 signed content digest list.
  - Optional flags can expand PKCS7 and CodeSignBlock details.

## Requirements

- Python 3.8+
- Optional: `openssl` in PATH (only needed for `--openssl`)

## Usage

Basic:

```
python3 print_hap_signing_block.py /path/to/app.hap
```

Dump PKCS7 details with OpenSSL:

```
python3 print_hap_signing_block.py /path/to/app.hap --openssl
```

Parse the embedded CodeSignBlock (if present):

```
python3 print_hap_signing_block.py /path/to/app.hap --codesign
```

## What the script prints

- Signing block header (tail) info: size, block count, magic, version.
- Sub-block heads and values (type/length/offset).
- PKCS7 signed content digest list (version, pairs, digest hex).
- Embedded codesign header (and CodeSignBlock details when `--codesign` is set).

If any sub-structure cannot be parsed, it prints `<unavailable>` and continues.

## Notes

- The structure description is derived from open-source code, not an official
  spec. See `HapStructure.md` for details and terminology.
- Source reference:
  `https://gitee.com/openharmony/developtools_hapsigner/tree/OpenHarmony-v6.0-Release`
- PKCS7 parsing in the script is minimal and only extracts the signed content
  needed for the digest list. Use `--openssl` for a full PKCS7 dump.
