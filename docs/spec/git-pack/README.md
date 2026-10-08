# Git pack format (`pack-*.pack` / `pack-*.idx`)

| 項目 | 内容 |
|------|------|
| 基準仕様 | [gitformat-pack(5)](https://git-scm.com/docs/gitformat-pack) (ローカルスナップショット: `docs/spec/sources/gitformat-pack.adoc`、git v2.51.0 Documentation) |
| 参照実装 | `git` (GPL-2.0、oracle — `git repack` による fixture 生成と `git index-pack` による encode 検証)。詳細: THIRD_PARTY_NOTICES Git pack format 項 |
| 形式概要 | `PACK` + u32 version + u32 object count の 12B ヘッダのあと、各オブジェクトエントリ (可変長オブジェクトヘッダ + zlib 本体)。delta エントリ (OFS_DELTA/REF_DELTA) は base 参照を伴う。末尾は pack チェックサム (全先行バイトの SHA-1)。オブジェクト ID は git オブジェクトモデルの `SHA-1("<type> <len>\0" + payload)` |
| 実装範囲 | pack v2 (SHA-1) の read/write (write は OFS_DELTA/REF_DELTA 出力対応)、pack v3 (SHA-256) の read/write、idx v2 の read/write (SHA-256 名・checksum 含む)、idx v1 の read/write。delta 解決は pack 内完結のみ (thin pack は reject) |

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| pack v2 (SHA-1) | gitformat-pack "pack-*.pack files" | ✅ | ✅ | encode は `add_delta_object` (OFS_DELTA type 6) / `add_ref_delta_object` (REF_DELTA type 7) 出力対応 |
| pack v1 | 同節 (idx なし旧形式) | ❌ | ❌ | Git 現行ツール未使用の旧形式 (intentional scope) |
| pack v3 (SHA-256 repo) | 同節 | ✅ | ✅ | 32B object name / SHA-256 trailer。write は `new_sha256` |
| idx v2 | gitformat-pack "pack-*.idx files" | ✅ | ✅ | fanout + sorted names + CRC32 + offset 表 |
| idx v1 | 同節 | ✅ | ✅ | fanout + (offset,sha1) sorted table + trailer (pack checksum + idx checksum、計 40B)。decode は `decode_idx_v1` が trailer 必須・idx checksum を SHA-1 検証、encode は `finish_with_index_v1` (#24a/#25d) |

## pack ヘッダ / エントリ

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | 先頭は `PACK` (4B) + network-order version + network-order object count | "pack-*.pack files" 冒頭 | ✅ | `decode_real_pack`, `bad_signature` |
| 2 | version 2/3 を受理 (v3 = SHA-256 repo、32B names + SHA-256 trailer)。それ以外は reject | 同上 ("Currently version 2 and 3") | ✅ | `v3_pack_roundtrip`, `v3_ref_delta_handbuilt`, `v3_bad_checksum_rejected`, `v1_pack_still_rejected`, `reject_version4` |
| 3 | オブジェクトヘッダ: 先頭バイト `(cont\|type:3\|size:4)`、以降は 7-bit chunk を連結した可変長 size | 同上 "object entries" | ✅ | `decode_real_pack`, `encode_roundtrip` |
| 4 | オブジェクト種別 1=commit, 2=tree, 3=blob, 4=tag の 4 種を非 delta オブジェクトとして受理 | 同上 (type 表) | ✅ | `decode_real_pack` (commit/tree/blob 実物), `tag_object_accepted`, `encode_roundtrip` |
| 5 | 種別 0/5 および未定義値は reject | 同上 | ✅ | `bad_object_type_rejected` |
| 6 | 各オブジェクト本体は zlib ストリーム (RFC 1950、内部 deflate 伸張) | 同上 | ✅ | `decode_real_pack`, `bad_zlib_stream` |
| 7 | zlib ストリームは self-terminating であり、実際の消費バイト数で次エントリ位置を決定する | 同上 (連続配置) | ✅ | `deflate::decode::decode_stream` + `BitReader::byte_position` |
| 8 | zlib ヘッダの CM=8/CINFO/FCHECK 検証、FDICT は reject | RFC 1950 | ✅ | `zlib_decode` 内の各ガード |
| 9 | zlib 末尾 Adler-32 を検証 | RFC 1950 | ✅ | `bad_zlib_stream`, ChecksumMismatch |
| 9a | オブジェクトヘッダの size は zlib 展開後ペイロード長 (delta は delta データ長) と一致必須 (crate 防御、gitformat-pack "object entries" のサイズ意味論) | 同上 | ✅ | `object_size_field_mismatch` |

## delta 解決

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 10 | OFS_DELTA (type 6): "offset encoding" の n バイト前エントリを base とする | "object entries" + "offset encoding" 節 | ✅ | `decode_real_pack` (git 実物 ofs-delta), `ofs_delta_handbuilt` |
| 11 | OFS_DELTA の base は必ず先行エントリ (n > 0 かつ pack 内の既知エントリオフセット) | 同上 | ✅ | `ofs_delta_bad_base` |
| 12 | REF_DELTA (type 7): hash 長 (v2=20B / v3=32B) のオブジェクト名で pack 内 base を引く。base は delta エントリでも可 ("The base object could also be deltified") — 名前は解決後にしか判らないため fixpoint パスで解決 | "object entries" | ✅ | `decode_ref_delta_pack` (ref.pack 実物 fixture), `v3_ref_delta_handbuilt`, `ref_delta_chained_onto_delta` |
| 13 | thin pack (REF_DELTA base が pack 内に不在) は reject | 同上 + 通常 pack は self-contained | ✅ | `thin_pack_rejected` |
| 14 | delta データは `size_of_base` `size_of_result` の size encoding に続く命令列 | "deltified representation" 節 | ✅ | `apply_delta_copy_insert`, `delta_chain_depth` |
| 15 | `size_of_base` は実 base サイズと一致必須 | 同上 | ✅ | `apply_delta_errors` (src size mismatch) |
| 16 | copy 命令 (MSB=1): offset 4B / size 3B の optional field、size 0 は 0x10000 | 同上 | ✅ | `apply_delta_copy_insert`, `ofs_delta_handbuilt` |
| 17 | insert 命令 (MSB=0、非ゼロ): 次 n バイトをそのまま出力 | 同上 | ✅ | `apply_delta_copy_insert` |
| 18 | 命令 0 (reserved) は reject | 同上 ("reserved") | ✅ | `apply_delta_errors` |
| 19 | copy が base 範囲外 / insert が delta 残量超過 / 結果が `size_of_result` 不一致は reject | 同上 + crate 防御 | ✅ | `apply_delta_errors` |
| 20 | delta チェーンは base 先解決で再帰適用 (OFS/REF 混在可)。深さ上限 64 (git 既定深さ 50 に十分な余裕) で過剰チェーンを防御。delta cycle は `resolving` フラグで検出 | "deltified representation" 節 + crate 防御 | ✅ | `delta_chain_depth` (2 段), 深さ上限はコード上の上限 |

## pack チェックサム / idx

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 21 | pack 末尾は全先行バイトの SHA-1。不一致は reject | "pack-*.pack files" 末尾 | ✅ | `bad_pack_checksum` |
| 22 | idx v2: magic `FF 74 4F 63` + version 2 | "pack-*.idx files" v2 | ✅ | `decode_real_idx` |
| 23 | idx v2: fanout[256] (単調増加)、sorted SHA-1 名表、CRC32 表、4B offset 表、8B large-offset 表 (MSB=1 のエントリが指す) | 同節 | ✅ | `decode_real_idx`, `idx_large_offset_table` (合成 idx による large offset 経路) |
| 24 | idx 末尾は pack チェックサム + idx チェックサム (自身の SHA-1)。両者を検証 | 同節 | ✅ | `decode_real_idx`, `idx_bad_checksums_rejected` |
| 24a | idx v1: fanout[256] + sorted (u32 offset + 20B sha1) 24B 行 + trailer (pack checksum 20B + idx checksum 20B)。非単調 fanout / サイズ不一致 / 未ソートは reject | "pack-*.idx files" v1 | ✅ | `decode_idx_v1` は `len == 1024 + 24n + 40` (trailer 必須) を要求し、末尾 idx checksum を SHA-1 検証。pack checksum は parse のみ。v1 decode は SHA-1 (20B 行) 専用 — SHA-256 の v1 idx は理論上ありうるが git が生成しないため対象外。`decode_idx_v1_trailer_verified`, `decode_idx_v1_handbuilt`, `decode_idx_v1_rejects_bad_input`, `idx_v1_rejected_for_sha256` |
| 25 | encode: pack v2 を出力し、`finish_with_index` で対応 idx v2 を生成。git `index-pack` が受理する | gitformat-pack 全体 | ✅ | `encode_roundtrip`, `encode_roundtrip_with_index` + git interop (手動確認: `git index-pack`/`verify-pack` が受理、生成 idx は git 生成物とバイト一致) |
| 25a | encode: `add_delta_object` が先行エントリを base とする OFS_DELTA (type 6) を出力。delta 命令列は greedy block matcher で生成 (delta 生成戦略は仕様非規定)。実 `git index-pack`/`verify-pack` が depth-2 chain を受理 | "object entries" + "deltified representation" 節 | ✅ | `delta_encoder_object_roundtrip`, `delta_chain_of_three`, `delta_rejects_bad_base_index`, `create_delta_roundtrip_various`, `delta_with_index_roundtrip`, `ofs_offset_encoding`, `ofs_delta_pack_accepted_by_git_index_pack` |
| 25b | encode: `add_ref_delta_object` が REF_DELTA (type 7) (hash 長の base オブジェクト名埋め込み) を出力。実 `git index-pack --strict` が受理 | "object entries" | ✅ | `ref_delta_roundtrip`, `ref_delta_rejects_bad_base_index`, `ref_delta_pack_accepted_by_git_index_pack` |
| 25c | encode: `new_sha256` が pack v3 (32B オブジェクト名・SHA-256 trailer) を出力。`finish_with_index` は 32B 名・SHA-256 checksum の idx v2 を emit、`decode_idx_v2_sha256` で検証付き読み戻し。実 `git index-pack --strict` (sha256 repo) が受理 | "pack-*.pack files" + "pack-*.idx files" | ✅ | `v3_sha256_roundtrip`, `v3_index_roundtrip`, `v3_pack_accepted_by_git_index_pack` |
| 25d | encode: `finish_with_index_v1` が idx v1 (fanout + u32 offset + 20B id + trailer (pack checksum + idx checksum)) を出力。SHA-256 encoder では `Unsupported` | "pack-*.idx files" v1 | ✅ | `finish_with_index_v1` は trailer (pack checksum + idx checksum) 付き idx v1 を emit。実 git `verify-pack -v` で受理確認。`idx_v1_write_roundtrip` `v1_idx_accepted_by_git_verify_pack` |

## エントリモデル / API

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 26 | エントリ名は小文字 hex オブジェクト ID (`SHA-1("<type> <len>\0" + data)`)。内容と整合することをデコード時に確認できる | git オブジェクトモデル (gitformat-pack 前置き) | ✅ | `decode_real_pack` (再計算照合), `encode_roundtrip` (既知 ID `ce0136…`) |
| 27 | `ArchiveDecode`/`ArchiveEncode`/`ArchiveEntry` trait を実装 | crate trait 規約 | ✅ | `GitPackCodec`, `GitPackEntry`, `GitPackEncoder` |

### CLI / fuzz 連携

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 28 | `PACK` + version 2/3 ヘッダで `.pack` を自動検出 | CLI detection | ✅ | `detect_git_pack` |
| 29 | `archive list`/`read` は hex 名 + `object-type` メタデータで一覧化 | CLI semantics | ✅ | `read.rs` の `Format::GitPack` アーム |
| 30 | `archive extract` は各オブジェクトを hex 名ファイルとして出力 | CLI semantics | ✅ | `extract.rs` の `Format::GitPack` アーム |
| 31 | `archive pack git-pack` は入力ファイルを blob オブジェクトとして格納 (non-deltified) | CLI semantics | ✅ | `write_archive.rs` `pack_git_pack` |
| 32 | fuzz algorithm `git-pack` / `git-pack-delta` / `git-pack-sha256` | fuzz harness | ✅ | `fuzz/src/algorithms.rs` |

### Intentional scope (実装対象外)

| # | 項目 | 理由 |
|---|------|------|
| 33 | thin pack の受理・外部 base 結合 (`index-pack --fix-thin` 相当) | thin pack は送信用途中形式で、リポジトリ上の pack は常に self-contained |
| 34 | pack v1 (idx なし旧形式) の read/write | v1 は現行 Git が出力しない |
| 35 | `.rev` / `.mtimes` / multi-pack-index (`.midx`) / `.bitmap` | いずれも pack 補助・複数 pack 管理用の別形式 (gitformat-pack は MIDX の BTMP/RIDX chunk に言及するのみ。bitmap 本体は別文書、midx は gitformat-multi-pack-index) |
| 36 | SHA-256 リポジトリ層の統合 (loose object、refs) | pack v3 の read/write・idx v2 32B names は行 2/12/25c で対応済み。repo 層の object store 統合は pack コンテナ scope 外 |
| 37 | packed-refs / loose object (`.git/objects/xx/`) の読み書き | pack とは別の object store 形式 |
