# 仕様準拠 & テストケース網羅状況

| 項目 | 内容 |
|------|------|
| この文書の位置づけ | 仕様準拠・共有実装・互換性メモ・テスト網羅状況・残存する制約・今後の優先方針の正本 |
| README との役割分担 | `README.md` は概要と導線のみを保持し、詳細の重複は持たない |
| 要件表の粒度 | 可能な限り **どの仕様書のどの節・見出し・項目に対応するか** を辿れる粒度で記載する |
| 節番号のない仕様書の参照方法 | 見出し名または用語名で参照する |
| 分割ファイル | 各フォーマットの要件表は `docs/spec/` 配下のファイルに分割されている |

## 読み方

| 項目 | 内容 |
|------|------|
| 準拠仕様 / 参照実装一覧 | 各形式で何を基準に実装・検証しているかの一覧 |
| 共有実装 | 複数形式で共有している codec / filter core の由来と責務の整理 |
| 各フォーマット節 | `docs/spec/` 配下に 1 ファイル = 1 フォーマットで要件・仕様参照・テスト名を対応づける |

## 準拠仕様 / 参照実装一覧

| フォーマット | 仕様 | 備考 |
|------------|------|------|
| DEFLATE | RFC 1951 | テストベクターなし (仕様のみ) |
| gzip | RFC 1952 | CRC32 は `util::crc32` で実装し、Appendix 8 の既知値は `test_crc32_known_vectors`、gzip trailer 検証は `test_valid_trailer_crc32_and_isize` / `test_crc32_mismatch` で固定 |
| zstd | RFC 8878 | Appendix A に事前定義FSEテーブル全値、repeat offset例あり |
| bzip2 | リファレンス実装 (bzip2 1.0.x, Julian Seward) | 正式なRFC/ISOなし。リファレンス実装がデファクト仕様 |
| lzip | lzip マニュアル (https://www.nongnu.org/lzip/manual/lzip_manual.html) | LZMA (lc=3/lp=0/pb=2) + シンプルフレーミング |
| `.lzma` | `lzma-file-format.txt` (tukaani-project/xz `doc/`, public domain) | 13B ヘッダ (properties + dict size + unpacked size) + 生 LZMA ストリーム。trailing data は reject |
| LZW | ncompress (compress42.c) | 正式なRFC/ISOなし。Unix compress `.Z` フォーマットのデファクト標準 |
| LZ4 | LZ4 フレームフォーマット仕様 | ブロックフォーマット + フレームヘッダー + xxhash32 チェックサム |
| LZO | LZO1X-1 バイトコード + lzop ファイルフォーマット | Linux kernel Documentation/lzo.txt、lzop ヘッダー仕様 |
| Brotli | RFC 7932 (2016) | decoder は §4-§11 の全必須セクションを実装。encoder は §9.1 stream header + §9.2 uncompressed/metadata/LZ77 compressed metablock (complex prefix codes, distance encoding, context modeling, static dictionary, multi-block-type) を提供 |
| zlib | RFC 1950 | §2.2 CMF/FLG ヘッダー + raw DEFLATE payload + big-endian Adler-32 trailer |
| Snappy | Google snappy `format_description.txt` (raw) + `framing_format.txt` (framed) | raw: varint preamble + 4 種タグ (literal/copy-1/copy-2/copy-4)。framed: stream identifier `sNaPpY` + chunk types 0x00/0x01/0x80-0xFE + masked CRC-32C (Castagnoli polynomial 0x1EDC6F41) |
| ZPAQ | upstream ZPAQ / ZPAQL behavior + crate bounded contract | 正式標準ではなく、コンテキストミキシング + 算術符号化 + ZPAQL VM を current bounded contract で管理 |
| rzip | upstream `rzip.samba.org` `.rz` | decoder は system `rzip` 生成 archive で相互運用確認済み。encoder は crate roundtrip 向け current container/token subset を提供し、current direct tests では text / binary / level-1 multi-chunk の `system rzip -d` interop まで確認済み |
| lrzip | lrzip `.lrz` format (crate-local long-range match layer + 選択可能バックエンド) | 内部 long-range match finder は shared core を再利用しつつ、`.lrz` 側では variable-width match offset token を使う。current scope の system `lrzip` interop は direct tests で確認する |
| xz | xz ファイルフォーマット仕様 (tukaani.org/xz/xz-file-format.txt) | LZMA2 + x86/PowerPC/IA64/SPARC/ARM/ARM-Thumb/ARM64/RISC-V BCJ + Delta フィルター、registry-backed custom filter、CRC-32/CRC-64/SHA-256 チェック、連結ストリーム対応 |
| tar | POSIX.1-1988 UStar / GNU 拡張 / POSIX.1-2001 PAX | デコード: 全形式自動認識。エンコード: GNU/PAX モード選択可能 |
| cpio | POSIX `odc` / SVR4 `newc` / `newcrc` | pathname/data 配置と簡易チェックサムまで実装 |
| ar | IEEE Std 1003.1 / GNU ar / BSD ar | 共通: 8B マジック `!<arch>\n` + 60B 固定長ヘッダー (ar_name[16]/ar_date[12]/ar_uid[6]/ar_gid[6]/ar_mode[8]/ar_size[10]/ar_fmag[2])。GNU 拡張: `//` 文字列テーブル + `/offset` 参照。BSD 拡張: `#1/<len>` 名前埋め込み |
| zip | APPNOTE.TXT 6.3.10 (PKWARE, 2024) | §4.3.7 Local File Header / §4.3.8 Data Descriptor / §4.3.12 Central Directory / §4.3.16 EOCD / §4.3.20-22 ZIP64 / §4.4.1 General Purpose Bit Flag (bit 0,3,11) / Compression method 0,1,2-5,6,8,12,14,93,95,98 / §4.5.2 Traditional PKZIP Encryption / WinZip AES-128/192/256 (extra field 0x9901) |
| 7z | 7zFormat.txt (LZMA SDK 26.00) / Methods.txt | SignatureHeader (`37 7A BC AF 27 1C`) / StartHeader CRC / UINT64 VLI / Header property IDs 0x00-0x19 / Folder DAG with BindPair / Methods: Copy (0x00), LZMA (0x03 0x01 0x01), LZMA2 (0x21), PPMdH (0x03 0x04 0x01), x86/PowerPC/ARM/ARM-Thumb/SPARC/ARM64/RISC-V BCJ, Delta (0x03), BCJ2 (0x03 0x03 0x01 0x1B), Brotli (0x04 0xF7 0x11 0x01), 7zAES (0x06 0xF1 0x07 0x01) / timestamp metadata (ctime/atime/mtime) |

---

## 共有実装

| コンポーネント | 準拠仕様 / 参照実装 | 備考 |
|---|---|---|
| LZMA | lzip manual / xz / 7z の LZMA property semantics | internal `compress::lzma` shared core として再利用 |
| LZMA2 | xz `xz-file-format.txt` / 7z LZMA2 coder semantics | internal `compress::lzma2` shared core として再利用 |
| BCJ (x86/PowerPC/IA64/SPARC/ARM/ARM-Thumb/ARM64/RISC-V) | xz / 7z 系 BCJ filter behavior | liblzma/7-Zip style branch conversion |
| Delta | xz / 7z 系 Delta filter behavior | distance 1..=256 の byte-wise Delta |
| PPMdH / PPMd7 | 7-Zip public-domain `Ppmd.h`, `Ppmd7.c`, `Ppmd7Dec.c`, `Ppmd7Enc.c` | 7z coder `0x030401` と shared core を実装 |

→ 詳細テスト: [util.md](util.md)

---

## 補助検証レーン

| レーン | 目的 | 現在の対象 | 出力 / 備考 |
|---|---|---|---|
| `archive-fuzz` self pattern | crate 内 encode/decode roundtrip を広く反復検証 | compression + archive formats の public fuzz target 群 | failure は signature 単位で dedupe し、最小化後に `.json` + `.bin` artifact として保存 |
| `archive-fuzz` original-compress / original-decompress | system tool との相互運用回帰 | external tool が存在する format の canonical CLI path | `known_issues` に列挙した intentional filter を除き、残存 failure は回帰候補として扱う |
| `archive-fuzz` coverage-guided mode | structured seed + persistent corpus mutation による input variation 拡張 | `fuzz/corpus/` を読む guided lane、novel observation harvest | run ごとに `manifest.json` / `summary.json` / `matrix.json` を出力 |
| `archive-fuzz` special case matrix | archive metadata / encryption / encoded-header variation の deterministic 検証 | `ar` / `tar` / `cpio` / `zip` / `7z` の long-name / metadata / encryption variation | random fuzz の前に固定ケースとして回し、通常 failure と同じ artifact pipeline に流す |
| resource oracle | 正常終了ケースの異常な膨張や過大 runtime を failure 化 | runtime / encoded size / decoded size の bounded check | 成功扱いでも oracle 違反なら failure artifact を残す |

---

## 現在の intentional scope / 残存制約

| 項目 | 現在の扱い | 補足 |
|---|---|---|
| `rzip` encode-side system interop | **intentional scope** | current direct tests では text / binary / level-1 multi-chunk の `system rzip -d` interop を確認済みだが、upstream option matrix 全体や未検証 payload 分布まで blanket parity は主張しない |
| `lrzip` outer container parity | **intentional scope** | shared long-range match finder と supported backend subset は維持するが、outer `.lrz` framing の blanket upstream parity や未検証 option matrix 全体は未主張 |
| `7z` complex graph writer | **intentional scope** | decode 側は supported single-output DAG subset を扱うが、writer 側の current scope は one-folder または two-folder の linear subset と linear 7zAES file-content / encoded-header write に留める。direct `system 7z` 根拠は baseline one-folder、one-folder / two-folder `PPMd`（encoded-header と encrypted / encrypted+encoded-header を含む）、two-folder encrypted / encoded-header / encrypted+encoded-header variants、one-folder / two-folder x86 `BCJ` / `Delta` combinations まで |
| `xz` unregistered custom filter execution | **intentional scope** | application-defined custom filter ID は registry 登録済み codec（identity passthrough helper 含む）で実行できるが、未登録の filter は引き続き適用時に explicit unsupported とする |
| `zip` extra field round-trip | **intentional scope** | 認識する extra field は 0x0001 (ZIP64)、0x9901 (WinZip AES)、0x000a (NTFS)、0x000d (UNIX)、0x5455 (extended timestamp)、0x7075 (Unicode Path)。他の extra field はパース時にスキップし、round-trip では保持しない |
| `zip` multi-disk archives | **intentional scope** | 単一ディスクアーカイブのみ。分割/スパンアーカイブは `Unsupported` として reject |
| `7z` IA64 BCJ encode | **intentional scope** | decode のみ対応。エンコーダーでは IA64 BCJ フィルターを生成しない |
| `7z` empty-stream / empty-file / anti-item entries | **intentional scope** | system `7z` が空ファイルを格納する際に使用する empty-stream エントリー種別はデコーダーが対象外。kEmptyStream / kEmptyFile / kAnti プロパティを検出した時点で `Unsupported` を返す |
| `lzw` / `lzw-bits9` — `ncompress` による空入力拒否 | **intentional scope** | `ncompress` (`compress`/`uncompress`) は空入力に対して exit status 2 で終了する外部ツール固有の動作。ライブラリ自体は空データを正常に処理する |
| `lzw-bits9` — `compress -b 9` の非可逆 roundtrip | **intentional scope** | `ncompress -b 9` は一部の入力に対してロッシーな roundtrip を起こす外部ツール自身のバグ。ライブラリの encode/decode 実装には問題がない |

## 実装対象外フォーマット

本 crate は **書面仕様・フォーマット文書のみを実装の情報源**とし、参照実装のソースコードは実装の情報源としない。以下は仕様不在・ライセンス制約などにより実装対象外とした形式である。アルゴリズム内部の書面仕様が後日公開された場合は再評価する。

| フォーマット | 実装対象外の理由 |
|---|---|
| RAR | unRAR ライセンスの制約により厳密な実装が困難。展開のみでも source-derived 実装の配布リスクを避けるため対象外 |
| ACE | Public UnAce Licence が non-free（圧縮側開発禁止の field-of-use 制限を含む）。ACE 2.x の参照実装も事実上 proprietary `unace.dll` のみ |
| CAB LZX (1997 文書版) | 公式文書に既知の誤記が複数あり、正誤判別の情報源が参照実装のソースコードにのみ存在するため厳密実装が不能 |
| CAB Quantum | 圧縮本体の書面仕様が存在しない |
| WIM / LZMS | 公式仕様なし。WIM 固有の LZX 変種と LZMS ソリッド圧縮の書面仕様が存在しない |
| ZIP method 96 (JPEG) | APPNOTE は ID 割り当てのみで、実態は WinZip 独自の JPEG 再圧縮。書面仕様が非公式文書にのみ存在する |
| ZIP method 97 (WavPack) | 公開文書はコンテナ・ブロックヘッダ層のみで、可逆圧縮コアの bit-level 仕様が存在しない |
| ZIP method 16 Entropy Encoding 拡張 (z14〜) | 特許状況が未確認の新規要素。クラシック辞書ベースの CMPSC は実装候補として残す |
| ZIP method 7 (Tokenizing) | 仕様未公開 |
| bzip3 | 公開文書はコンテナ層のみで、算術符号器・LZP・RLE の内部仕様が文書化されていない |
| LZFSE / LZVN | 書面仕様が存在しない（BSD-3 参照実装が唯一の情報源） |
| LZJB | 書面仕様が存在しない（CDDL 参照実装が唯一の情報源） |
| Heatshrink | コア符号化の書面仕様が存在しない（コンテナ文書のみ存在） |
| Unix `pack` (`.z`) / `squeeze` | bit-level の書面仕様が存在しない |
| UCL / NRV2B | 書面仕様が存在しない（upstream がドキュメント欠如を自認。GPL 参照実装のみ） |
| Exomizer | 書面仕様が存在しない（usage 文書と decruncher ソースのみ） |
| OpenZL | ワイヤーフォーマットの安定した書面仕様が存在しない（公開済みは SDDL 記述言語のみ、unstable 明記）。安定仕様公開で再評価 |
| LHA/LZH 圧縮メソッド (`-lh1-`〜`-lh7-`, `-lzs-`/`-lz4-`/`-lz5-`, `-pm0-`/`-pm2-`) | 圧縮内部の書面仕様が存在しない。コンテナと `-lh0-` (store) は実装候補として残す |
| ARJ method 1-4 | method 1-3 は仕様不在、method 4 は二次文書のみ。コンテナと method 0 は実装候補として残す |
| ARC method 5-9 (Crunch/Squash) | ARC 固有の圧縮内部仕様の書面文書が存在しない。コンテナと method 0-3 は実装候補として残す |
| ZOO | コンテナ・圧縮ともに書面仕様が存在しない |

---

## 次の library 実装候補

| 候補 | 狙い | 前提 |
|---|---|---|
| `zip` extra field round-trip 拡張 | 認識済み extra field の encode/decode 保持 | 0x000a, 0x000d, 0x5455, 0x7075 は対応済み |
| `rzip` / `lrzip` interop 拡張 | system tool parity を encode 側にも広げる | 先に current subset と新規 claim の境界を direct interop test で固定する |

---

## フォーマット別要件表

### 圧縮フォーマット

| フォーマット | ファイル | ✅ | ⚠️ | ❌ | 合計 |
|---|---|---|---|---|---|
| DEFLATE | [deflate.md](deflate.md) | 57 | 0 | 0 | 57 |
| gzip | [gzip.md](gzip.md) | 40 | 0 | 0 | 40 |
| zstd | [zstd.md](zstd.md) | 126 | 0 | 0 | 126 |
| bzip2 | [bzip2.md](bzip2.md) | 68 | 0 | 0 | 68 |
| lzip | [lzip.md](lzip.md) | 39 | 0 | 0 | 39 |
| `.lzma` | [lzma_alone.md](lzma_alone.md) | 24 | 0 | 0 | 24 |
| LZW | [lzw.md](lzw.md) | 21 | 0 | 0 | 21 |
| LZ4 | [lz4.md](lz4.md) | 56 | 0 | 0 | 56 |
| LZO | [lzo.md](lzo.md) | 39 | 0 | 0 | 39 |
| Snappy | [snappy.md](snappy.md) | 35 | 0 | 0 | 35 |
| Brotli | [brotli.md](brotli.md) | 51 | 0 | 0 | 51 |
| zlib | [zlib.md](zlib.md) | 19 | 0 | 0 | 19 |
| rzip | [rzip.md](rzip.md) | 20 | 0 | 0 | 20 |
| lrzip | [lrzip.md](lrzip.md) | 37 | 0 | 0 | 37 |
| xz | [xz.md](xz.md) | 54 | 0 | 0 | 54 |
| ZPAQ | [zpaq.md](zpaq.md) | — | — | — | bounded contract |

### アーカイブフォーマット

| フォーマット | ファイル | ✅ | ⚠️ | ❌ | 合計 |
|---|---|---|---|---|---|
| tar | [tar.md](tar.md) | 59 | 0 | 0 | 59 |
| cpio | [cpio.md](cpio.md) | 35 | 0 | 0 | 35 |
| ar | [ar.md](ar.md) | 26 | 0 | 0 | 26 |
| ZIP | [zip.md](zip.md) | 150 | 0 | 3 | 153 |
| 7z | [sevenz.md](sevenz.md) | 115 | 0 | 0 | 115 |

### 共有コンポーネント

| コンポーネント | ファイル | ✅ | ⚠️ | ❌ | 合計 |
|---|---|---|---|---|---|
| CRC-32 / CRC-64 / XXH32 / XXH64 / Adler-32 / SHA-1 / SHA-256 / MD5 / AES / DES / RC2 / RC4 / BitReader / Error | [util.md](util.md) | 65 | 0 | 0 | 65 |

### 全体集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み | 1136 |
| ⚠️ 部分実装 | 0 |
| ❌ 未実装 | 3 |
| **合計** | **1139** |

**全体カバー率**: 1136 / 1139 = **99.7%** (intentional exclusion 除外後: 1136 / 1136 = **100%**)
