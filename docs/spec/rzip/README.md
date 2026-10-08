# rzip (upstream `.rz`)

| 項目 | 内容 |
|------|------|
| 基準仕様 | upstream rzip 2.1 (Andrew Tridgell) の `.rz` container。ソースコードが規範。upstream site (`rzip.samba.org`) は現在 503 で到達不能のため Debian ミラーを参照: [ソース rzip 2.1-5](https://sources.debian.org/src/rzip/2.1-5/)、[rzip(1) man page](https://manpages.debian.org/unstable/rzip/rzip.1.en.html) (CLI 仕様)。ローカルスナップショット: sources/rzip_2.1_rzip.c / rzip_2.1_stream.c / rzip_2.1_rzip.h (Debian pool orig tarball、sha256 は pkg/rzip/PKGBUILD と一致) |
| 参照実装 | upstream rzip 2.1 (GPL-2.0-or-later、ソース自体が規範 — format facts のみの動作参照、コード取り込みなし。GPL-2.0+→GPL-3→AGPL-13 の変換パスあり)、system `rzip` (oracle — 統合テスト実行時に system rzip が生成する archive で相互検証。check-in fixture ではない)。詳細: THIRD_PARTY_NOTICES rzip 項 |
| current scope | decoder は upstream `rzip.samba.org` `.rz` container の 24-byte file header、2-stream chunk multiplex、raw / bzip2 stream payloadを対象にする。encoder は同 subset の crate roundtrip と、system `rzip -d` 相互運用を提供する (text / binary / level-1 multi-chunk / level 0・9 edge、および raw / gzip / lzo / bzip2 全 backend stream で実測済み) |
| intentional scope | upstream option matrix 全体や未検証 payload 分布までの完全な互換性は保証の対象外とする (encode-side system interop は検証済み subset に限定) |
| token layer | long-range match tokenization は shared `rzip` core として `lrzip` でも再利用する |

### テスト対象要件と網羅状況

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | ファイルマジック `RZIP` | upstream `rzip.samba.org` `.rz` header | ✅ | `test_header_format`, `test_decode_public_container` |
| 2 | バージョン `2.1` 検証 | upstream `rzip.samba.org` `.rz` header | ✅ | `test_header_format`, `test_unsupported_version_rejected` |
| 3 | 24-byte header の expected size (big-endian low/high) と reserved 10 bytes = 0 | upstream `rzip.samba.org` `.rz` header | ✅ | `test_header_format`, `test_nonzero_reserved_header_bytes_rejected` |
| 4 | 2-stream chunk multiplex (`stream0` token/meta + `stream1` literals) | upstream `rzip.samba.org` chunk container | ✅ | `test_decode_roundtrip_chunk_streams`, `test_roundtrip_public_container` |
| 5 | stream compression type: raw (`CTYPE_NONE=3`) / bzip2 (`CTYPE_BZIP2=4`) | upstream `rzip.samba.org` chunk container | ✅ | `test_roundtrip_public_container`, `test_rzip_roundtrip_level_matrix`, `test_rzip_roundtrip_binary_payload` |
| 6 | unsupported stream compression type reject | upstream `rzip.samba.org` chunk container | ✅ | `test_unsupported_stream_compression_type_rejected` |
| 7 | literal token (`head=0`, `len:u16LE`) と literal stream 消費 | upstream `rzip.samba.org` token stream | ✅ | `test_decode_roundtrip_chunk_streams`, `test_roundtrip_empty` |
| 8 | match token (`head!=0`, `offset:u32LE`, `len:u16LE`) と offset 検証 | upstream `rzip.samba.org` token stream | ✅ | `test_decode_roundtrip_chunk_streams`, `test_rzip_match_offset_zero_rejected`, `test_rzip_roundtrip_level_matrix` |
| 9 | chunk terminator (`head=0,len=0` + CRC32) と CRC 検証 | upstream `rzip.samba.org` token stream | ✅ | `test_decode_roundtrip_chunk_streams`, `test_decode_public_container`, `test_chunk_crc_mismatch_rejected` |
| 10 | trailing data reject | upstream `rzip.samba.org` `.rz` container | ✅ | `test_trailing_garbage_rejected` |
| 11 | encode → decode roundtrip (empty / binary / level matrix) | crate-local bounded contract for upstream `.rz` emission | ✅ | `test_roundtrip_public_container`, `test_roundtrip_empty`, `test_rzip_roundtrip_binary_payload`, `test_rzip_roundtrip_level_matrix` |
| 12 | system `rzip` 生成 archive の decode | upstream `rzip` interoperability | ✅ | `test_rzip_decode_system_archive` (統合) |
| 13 | crate 出力の system `rzip -d` 相互運用 (level 0/6/9、raw/bzip2 backend stream) | upstream `rzip` interoperability | ✅ | `test_rzip_encode_system_decode_compat`, `test_rzip_encode_system_decode_binary_payload`, `test_rzip_encode_system_decode_multichunk_payload`, `test_rzip_encode_system_decode_level_edges`, `test_rzip_encode_system_decode_backend_matrix` (system decode は NONE/BZIP2 のみ — upstream rzip 2.1 は ctype 1/2 をサポートしないため gzip/lzo は crate roundtrip のみ検証) |
| 14 | CRC-32 variant: ISO 3309 (polynomial 0xEDB88320) | upstream rzip CRC | ✅ | util::crc32 使用 |
| 15 | Match minimum length: 31 bytes (rolling hash window size) | upstream rzip token | ✅ | 実装済み |
| 16 | Match maximum length: u16::MAX (65535) | upstream rzip token | ✅ | u16 field |
| 17 | Chunk 分割: `level * CHUNK_MULTIPLE` (= bzip_level × 100KB) の固定サイズ分割 | upstream rzip chunk (`rzip.c`) | ✅ | `chunk_size_for_level` — level→bzip_level 写像 {0,1,3,5,7,9} は upstream `levels[]` と一致 |
| 18 | Stream compression types: CTYPE_GZIP=1, CTYPE_LZO=2 (lrzip 由来の crate 拡張 — upstream rzip 2.1 は ctype 3/4 のみ) | crate extension | ✅ | `CTYPE_GZIP`/`CTYPE_LZO` decode/encode 対応 (feature-gated)。upstream `rzip -d` とは非互換 |
| 19 | Empty file handling (expected_size=0) | upstream rzip container | ✅ | test_roundtrip_empty |
| 20 | expected_size byte layout: bytes 6-9 = low u32 BE, bytes 10-13 = high u32 BE, combined as low \| (high << 32) | upstream rzip header | ✅ | decode/encode で対応 |
| 21 | stream block の `next` ポインタ chain (upstream は `100KB * bzip_level` の stream bufsize で大きい入力をマルチブロック化)。cycle はブロック数上限で拒否 | upstream `stream.c` / crate hardening | ✅ | `test_stream_chain_multi_block`, `test_stream_chain_cycle_rejected` |

---

## 実装メモ (upstream との差分)

- upstream `open_stream_in` は stream preamble の `ctype==NONE && c_len==0 && u_len==0` を強制するが、本実装は preamble bytes 0..8 を無検証で読み飛ばす (lenient)。
- upstream の "stream close workaround" (i==0 の全ゼロ preamble を 13B skip) は未実装 — 歴史的 quirk で生成側は再現しない。
- upstream decoder は match offset を `fd_hist` 経由で前 chunk に遡及できる (encoder は生成しない)。本実装は chunk 内に限定 — 実害なしだが受理範囲の差異。
- upstream は `total >= expected_size` で打ち止め (超過黙認)。本実装は厳密一致を要求 (stricter)。
- `decode_bounded` は decode 完了後の事後チェックであり、decode 中のメモリ使用量は bounded ではない。
- #2/#3/#10 (version/reserved/trailing reject) は upstream が読み取り側で検証しない項目の crate hardening。

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み  | 21 |
| **合計** | **21** |
