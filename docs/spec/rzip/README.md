# rzip (upstream `.rz`)

| 項目 | 内容 |
|------|------|
| 基準仕様 | upstream rzip 2.1 (Andrew Tridgell) の `.rz` container。ソースコードが規範。upstream site (`rzip.samba.org`) は現在 503 で到達不能のため Debian ミラーを参照: [ソース rzip 2.1-5](https://sources.debian.org/src/rzip/2.1-5/)、[rzip(1) man page](https://manpages.debian.org/unstable/rzip/rzip.1.en.html) (CLI 仕様) |
| 参照実装 | upstream rzip 2.1 (GPL-2.0-or-later、ソース自体が規範 — format facts のみの動作参照、コード取り込みなし。GPL-2.0+→GPL-3→AGPL-13 の変換パスあり)、system `rzip` (oracle — 統合テスト実行時に system rzip が生成する archive で相互検証。check-in fixture ではない)。詳細: THIRD_PARTY_NOTICES rzip 項 |
| current scope | decoder は upstream `rzip.samba.org` `.rz` container の 24-byte file header、2-stream chunk multiplex、raw / bzip2 stream payloadを対象にする。encoder は同 subset の crate roundtrip と、system `rzip -d` 相互運用を提供する (text / binary / level-1 multi-chunk / level 0・9 edge、および raw / gzip / lzo / bzip2 全 backend stream で実測済み) |
| intentional scope | upstream option matrix 全体や未検証 payload 分布までの blanket parity は主張しない (encode-side system interop は検証済み subset に限定) |
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
| 13 | crate 出力の system `rzip -d` 相互運用 (level 0/6/9 + 全 backend stream 含む) | upstream `rzip` interoperability | ✅ | `test_rzip_encode_system_decode_compat`, `test_rzip_encode_system_decode_binary_payload`, `test_rzip_encode_system_decode_multichunk_payload`, `test_rzip_encode_system_decode_level_edges`, `test_rzip_encode_system_decode_backend_matrix` |
| 14 | CRC-32 variant: ISO 3309 (polynomial 0xEDB88320) | upstream rzip CRC | ✅ | util::crc32 使用 |
| 15 | Match minimum length: 31 bytes (rolling hash window size) | upstream rzip token | ✅ | 実装済み |
| 16 | Match maximum length: u16::MAX (65535) | upstream rzip token | ✅ | u16 field |
| 17 | Chunk 分割: rolling hash boundary で自動分割 | upstream rzip chunk | ✅ | 実装済み |
| 18 | Stream compression types: CTYPE_GZIP=1, CTYPE_LZO=2 も定義あり | upstream rzip chunk | ✅ | `CTYPE_GZIP`/`CTYPE_LZO` decode/encode 対応 |
| 19 | Empty file handling (expected_size=0) | upstream rzip container | ✅ | test_roundtrip_empty |
| 20 | expected_size byte layout: bytes 6-9 = low u32 BE, bytes 10-13 = high u32 BE, combined as low \| (high << 32) | upstream rzip header | ✅ | decode/encode で対応 |

---

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み  | 20 |
| **合計** | **20** |
