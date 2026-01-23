# HAP Signing Overview (Huawei/OpenHarmony)

This overview summarizes the signing scheme and highlights how it compares
to Android APK signing. For byte-level layouts, see `HapStructure.md`.

This document summarizes the HAP signing scheme as implemented in the
open-source toolchain and compares it with Android APK signature schemes.

Source reference:
https://gitee.com/openharmony/developtools_hapsigner/tree/OpenHarmony-v6.0-Release

----------------------------------------------------------------------
1) HAP signing scheme (from code behavior)
----------------------------------------------------------------------

1.1 Package layout
- HAP is a ZIP container.
- The HAP signing block is inserted before the Central Directory.
- The signing block ends with a 32-byte tail (blockCount/size/magic/version).

1.2 Main signature block
- Sub-block type: 0x20000000 (HAP_SIGNATURE_SCHEME_V1_BLOCK_ID).
- Value: PKCS7 SignedData bytes.
- The PKCS7 signed content is an encoded digest list:
  - version (2), blockCount (1), and one (algId, digest) pair in practice.
- The digest is computed over:
  - ZIP entries content (before Central Directory)
  - Central Directory
  - EOCD
  - optional blocks (profile/property/proof)

1.3 Optional blocks
- 0x20000001: proof-of-rotation (optional)
- 0x20000002: profile content (optional)
- 0x20000003: property content (optional)
- Optional blocks are inserted as sub-blocks inside the signing block and
  are included in the main digest.
- Optional blocks are loaded as raw file bytes (no parsing during signing).
- If signCode is enabled, an additional PROPERTY block is inserted with the
  embedded codesign header+payload; it does not remove the original PROPERTY
  block (if present).

1.4 Code sign (optional)
- If signCode is enabled, a codesign payload is generated and embedded as a
  PROPERTY sub-block value with an inner header (type 0x30000001).
- It signs code-related content: the main HAP data region and native entries
  (e.g., libs/* and .an files).
- Purpose: add a dedicated integrity layer for native/executable content.

1.5 Compatibility version
- The signing block tail uses a version (2 or 3) and corresponding magic.
- This is separate from the main signature scheme version (V1).
- Boundary and magic numbers (from code):
  - compatibleVersion >= 8 -> signing block v3
    - magic_lo: 0x676973207061683c
    - magic_hi: 0x3e6b636f6c62206e
  - compatibleVersion < 8 -> signing block v2
    - magic_lo: 0x2067695320504148
    - magic_hi: 0x3234206b636f6c42
  - Older magic is also accepted for legacy verification.

----------------------------------------------------------------------
2) Verification flow (high level)
----------------------------------------------------------------------

1) Locate and parse the signing block; extract main signature and optional blocks.
2) If codesign is present, verify the codesign payload first.
3) Verify PKCS7 SignedData and extract digest algorithm + digest list.
4) Recompute digests from ZIP segments + optional blocks and compare.

----------------------------------------------------------------------
3) Comparison with Android APK signing
----------------------------------------------------------------------

Similarities:
- Both HAP and APK v2/v3 place a signing block before the Central Directory.
- Both provide full-package integrity (not just entry-level hashes).
- Both can carry rotation-related data (HAP proof-of-rotation vs APK v3).

Differences (based on observed code behavior):
- Android v1 is JAR signing (per-entry manifest hashes).
  HAP main signature is a PKCS7 block over a digest list of the ZIP segments.
- Android allows multiple signature schemes (v1/v2/v3) in one APK.
  The HAP toolchain currently uses a single main scheme type (V1 block ID),
  while the signing block has its own version (2/3) for compatibility.
- HAP has an additional codesign layer (fs-verity + native libs) that is
  not part of Android's v1/v2/v3 schemes.

Notes:
- This comparison is functional/behavioral, not a formal spec mapping.
- Refer to HapStructure.md for the exact byte-level layout in this repo.
