# 仕様準拠 & テストケース網羅状況

| 項目 | 内容 |
|------|------|
| この文書の位置づけ | 仕様準拠・共有実装・テスト網羅状況の集計・実装対象外形式・今後の優先方針の正本。個別フォーマットの要件・制約詳細は各 `docs/spec/<fmt>/` 側にのみ置く |
| README との役割分担 | `README.md` は概要と導線のみを保持し、詳細の重複は持たない |
| 要件表の粒度 | 可能な限り **どの仕様書のどの節・見出し・項目に対応するか** を辿れる粒度で記載する |
| 節番号のない仕様書の参照方法 | 見出し名または用語名で参照する |
| 分割ファイル | 各フォーマットの要件表は `docs/spec/<fmt>/` 配下に分割されている。index は `README.md`、バリアント/トピック別要件は子ファイル |
| 仕様出典の URL | 各 `docs/spec/<fmt>/README.md` の「基準仕様」行に canonical URL を記載する。`docs/spec/sources/` には `manifest.json` でピン留めした版のローカルスナップショットを置く (`make fetch-spec-sources` で取得、ダウンロード物は gitignore)。fetch 不可の出典は manifest の `no_url_available` に `reference_url` で記録する |

## 読み方

| 項目 | 内容 |
|------|------|
| フォーマット別要件表 | 各形式の基準仕様・`docs/spec/<fmt>/` index への導線・集計の一覧。個別フォーマットの要件詳細は各ディレクトリ側にのみ置く |
| 共有実装 | 複数形式で共有している codec / filter core の由来と責務の整理 |
| 各フォーマット節 | `docs/spec/<fmt>/` に 1 ディレクトリ = 1 フォーマットで要件・仕様参照・テスト名を対応づける |
| 対応バリアント・仕様版 | 複数の規格・版・方言を持つフォーマットでは index `README.md` 冒頭のマトリクスで decode/encode の対応可否を一覧化する。バリアント表の行は集計対象外 (要件行は先頭列が `数字` or `数字+1文字` の ID を持つ行のみ) |

## 共有実装

| コンポーネント | 準拠仕様 / 参照実装 | 備考 |
|---|---|---|
| LZMA | lzip manual / xz / 7z の LZMA property semantics | internal `compress::lzma` shared core として再利用 |
| LZMA2 | xz `xz-file-format.txt` / 7z LZMA2 coder semantics | internal `compress::lzma2` shared core として再利用 |
| BCJ (x86/PowerPC/IA64/SPARC/ARM/ARM-Thumb/ARM64/RISC-V) | xz / 7z 系 BCJ filter behavior | liblzma/7-Zip style branch conversion |
| Delta | xz / 7z 系 Delta filter behavior | distance 1..=256 の byte-wise Delta |
| PPMdH / PPMd7 | 7-Zip public-domain `Ppmd.h`, `Ppmd7.c`, `Ppmd7Dec.c`, `Ppmd7Enc.c` | 7z coder `0x030401` と shared core を実装 |
| LZRW family framing | lzrw1/lzrw1-a/lzrw2/lzrw3/lzrw3-a.c の "DEFINITION OF COMPRESSED FILE FORMAT" 節 (Ross Williams, public domain) | 4B copy flag + 16bit control + ≤16 item グループの共通 frame / 検証を crate-private `compress::lzrw` に集約 |

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

## 実装対象外フォーマット

本 crate は **書面仕様・フォーマット文書を第一の実装情報源**とする。仕様書に未記載の挙動がある場合のみ、参照実装の動作観察を補助的に用いる（コードの複製は行わない。個別の出自は `THIRD_PARTY_NOTICES` を参照）。以下は仕様不在・ライセンス制約などにより実装対象外とした形式である。アルゴリズム内部の書面仕様が後日公開された場合は再評価する。

| フォーマット | 実装対象外の理由 |
|---|---|
| RAR | unRAR ライセンスの制約により厳密な実装が困難。展開のみでも source-derived 実装の配布リスクを避けるため対象外 |
| ACE | Public UnAce Licence が non-free（圧縮側開発禁止の field-of-use 制限を含む）。ACE 2.x の参照実装も事実上 proprietary `unace.dll` のみ |
| WIM / LZMS | 公式仕様なし。WIM 固有の LZX 変種と LZMS ソリッド圧縮の書面仕様が存在しない |
| bzip3 | 公開文書はコンテナ層のみで、算術符号器・LZP・RLE の内部仕様が文書化されていない |
| LZFSE / LZVN | 書面仕様が存在しない（BSD-3 参照実装が唯一の情報源） |
| LZJB | 書面仕様が存在しない（CDDL 参照実装が唯一の情報源） |
| Heatshrink | コア符号化の書面仕様が存在しない（コンテナ文書のみ存在） |
| Unix `pack` (`.z`) / `squeeze` | bit-level の書面仕様が存在しない |
| UCL / NRV2B | 書面仕様が存在しない（upstream がドキュメント欠如を自認。GPL 参照実装のみ） |
| Exomizer | 書面仕様が存在しない（usage 文書と decruncher ソースのみ） |
| OpenZL | ワイヤーフォーマットの安定した書面仕様が存在しない（公開済みは SDDL 記述言語のみ、unstable 明記）。安定仕様公開で再評価 |
| ZOO | コンテナ・圧縮ともに書面仕様が存在しない |
| LZRW4 | Ross Williams の付録コードはエントロピー推定器 (実験スケッチ) のみで、production ワイヤーフォーマットが存在しない (lzrw4.txt / lzrw45_covering) |
| LZRW5 | 参照コードが未完 ("half-baked", decompressor の C パス無効化・65536 phrase 超で `exit(1)`・実質 64KB 入力制限)。ワイヤー形式の推定は可能だが production 仕様としての品質を欠くため intentional exclusion (lzrw5.txt) |

---

## 次の library 実装候補

| 候補 | 狙い | 前提 |
|---|---|---|
| [zip](zip/README.md) extra field round-trip 拡張 | 認識済み extra field の encode/decode 保持 | 対応済み field の一覧は zip 側の要件表を参照 |
| [rzip](rzip/README.md) / [lrzip](lrzip/README.md) interop 拡張 | system tool parity を encode 側にも広げる | 先に current subset と新規 claim の境界を direct interop test で固定する |

---

## フォーマット別要件表

### 圧縮フォーマット

| フォーマット | 基準仕様 | ✅ | ⚠️ | ❌ | 合計 |
|---|---|---|---|---|---|
| [DEFLATE](deflate/README.md) | RFC 1951 | 57 | 0 | 0 | 57 |
| [gzip](gzip/README.md) | RFC 1952 | 40 | 0 | 0 | 40 |
| [zstd](zstd/README.md) | RFC 8878 | 126 | 0 | 0 | 126 |
| [bzip2](bzip2/README.md) | bzip2 1.0.x 参照実装 (de facto) | 68 | 0 | 0 | 68 |
| [lzip](lzip/README.md) | lzip マニュアル | 39 | 0 | 0 | 39 |
| [`.lzma`](lzma_alone/README.md) | lzma-file-format.txt (tukaani/xz doc) | 25 | 0 | 0 | 25 |
| [LZW](lzw/README.md) | ncompress `compress42.c` (de facto) | 21 | 0 | 0 | 21 |
| [LZ4](lz4/README.md) | LZ4 Frame/Block Format | 58 | 0 | 0 | 58 |
| [LZO](lzo/README.md) | kernel `Documentation/lzo.txt` + lzop format | 39 | 0 | 0 | 39 |
| [Snappy](snappy/README.md) | snappy format_description / framing_format | 35 | 0 | 0 | 35 |
| [Brotli](brotli/README.md) | RFC 7932 | 51 | 0 | 0 | 51 |
| [zlib](zlib/README.md) | RFC 1950 | 19 | 0 | 0 | 19 |
| [xca](xca/README.md) | [MS-XCA] (Microsoft Open Specifications) | 40 | 0 | 0 | 40 |
| [lzf](lzf/README.md) | liblzf `lzfP.h` / ning LZFFormat (de facto) | 20 | 0 | 0 | 20 |
| [fastlz](fastlz/README.md) | fastlz.c 参照実装 (MIT) | 22 | 0 | 0 | 22 |
| [zx0](zx0/README.md) | ZX0 v2 README (BSD-3) | 20 | 0 | 0 | 20 |
| [lzrw1](lzrw1/README.md) | lzrw1.c 参照実装 (public domain) | 21 | 0 | 0 | 21 |
| [lzrw1a](lzrw1a/README.md) | lzrw1-a.c 参照実装 (public domain) | 20 | 0 | 0 | 20 |
| [lzrw2](lzrw2/README.md) | lzrw2.c 参照実装 (public domain) | 22 | 0 | 0 | 22 |
| [lzrw3](lzrw3/README.md) | lzrw3.c 参照実装 (public domain) | 23 | 0 | 0 | 23 |
| [lzrw3a](lzrw3a/README.md) | lzrw3-a.c 参照実装 (public domain) | 23 | 0 | 0 | 23 |
| [lzsa](lzsa/README.md) | LZSA StreamFormat / BlockFormat_LZSA1/LZSA2 v1.4.1 | 31 | 0 | 0 | 31 |
| [lzxd](lzxd/README.md) | [MS-PATCH] LZX DELTA (Microsoft Open Specifications) | 22 | 0 | 0 | 22 |
| [cmpsc](cmpsc/README.md) | IBM z/Arch POP App.D / ESA/390 Data Compression + APPNOTE method 16 | 20 | 0 | 0 | 20 |
| [rzip](rzip/README.md) | rzip `.rz` format (upstream 2.1) | 20 | 0 | 0 | 20 |
| [lrzip](lrzip/README.md) | lrzip `.lrz` format (crate-local subset) | 37 | 0 | 0 | 37 |
| [xz](xz/README.md) | xz-file-format.txt | 54 | 0 | 0 | 54 |
| [ZPAQ](zpaq/README.md) | ZPAQ Level 1/2 specification (zpaq206.pdf) + crate bounded contract (archive 層) | — | — | — | bounded contract |

### アーカイブフォーマット

| フォーマット | 基準仕様 | ✅ | ⚠️ | ❌ | 合計 |
|---|---|---|---|---|---|
| [tar](tar/README.md) | POSIX.1-1988 ustar / GNU tar / POSIX.1-2001 PAX | 59 | 0 | 0 | 59 |
| [cpio](cpio/README.md) | POSIX `odc` / SVR4 `newc`/`newcrc` | 35 | 0 | 0 | 35 |
| [ar](ar/README.md) | IEEE Std 1003.1 / GNU ar / BSD ar | 26 | 0 | 0 | 26 |
| [deb](deb/README.md) | deb(5) (dpkg) | 20 | 0 | 3 | 23 |
| [rpm](rpm/README.md) | rpm.org Package Format (v4/v6) | 24 | 0 | 3 | 27 |
| [squashfs](squashfs/README.md) | SquashFS 4.0 binary format | 26 | 0 | 5 | 31 |
| [mscab](mscab/README.md) | [MS-CAB] Cabinet File Format | 20 | 0 | 5 | 25 |
| [zim](zim/README.md) | openZIM ZIM file format (v5/v6) | 16 | 0 | 5 | 21 |
| [mtree](mtree/README.md) | FreeBSD mtree(5) / libarchive mtree | 19 | 0 | 3 | 22 |
| [warc](warc/README.md) | ISO 28500:2009 / IIPC WARC 1.1 | 19 | 0 | 4 | 23 |
| [lha](lha/README.md) | lha header documentation (apphead / lzh_note) | 18 | 0 | 3 | 21 |
| [arj](arj/README.md) | ARJ technical note (ARJ 2.x) | 18 | 0 | 4 | 22 |
| [arc](arc/README.md) | SEA ARC file format description | 14 | 0 | 3 | 17 |
| [ZIP](zip/README.md) | APPNOTE.TXT 6.3.10 (PKWARE) | 150 | 0 | 3 | 153 |
| [7z](sevenz/README.md) | 7zFormat.txt / Methods.txt (LZMA SDK 26.00) | 120 | 0 | 0 | 120 |

### 共有コンポーネント

| コンポーネント | ファイル | ✅ | ⚠️ | ❌ | 合計 |
|---|---|---|---|---|---|
| CRC-32 / CRC-64 / XXH32 / XXH64 / Adler-32 / SHA-1 / SHA-256 / MD5 / AES / DES / RC2 / RC4 / BitReader / Error | [util.md](util.md) | 65 | 0 | 0 | 65 |

### 全体集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み | 1622 |
| ⚠️ 部分実装 | 0 |
| ❌ 未実装 | 41 |
| **合計** | **1663** |

**全体カバー率**: 1622 / 1663 = **97.5%** (intentional exclusion 除外後: 1622 / 1622 = **100%**)
