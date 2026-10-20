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
| 対応バリアント・仕様版 | 複数の規格・版・方言を持つフォーマットでは index `README.md` 冒頭のマトリクスで decode/encode の対応可否を一覧化する。バリアント表の行は集計対象外 (要件行は先頭列が `数字` or `数字+1文字` の ID を持ち、かつ状態列 (✅/⚠️/❌/—) を含む行のみ。`docs/spec/sources/` 配下のスナップショットは対象外) |

## 共有実装

| コンポーネント | 準拠仕様 / 参照実装 | 備考 |
|---|---|---|
| LZMA | LZMA SDK `lzma-specification.txt` + lzip manual / xz / 7z の LZMA property semantics | internal `compress::lzma` shared core として再利用 |
| LZMA2 | xz `xz-file-format.txt` / 7z LZMA2 coder semantics | internal `compress::lzma2` shared core として再利用 |
| BCJ (x86/PowerPC/IA64/SPARC/ARM/ARM-Thumb/ARM64/RISC-V) | xz / 7z 系 BCJ filter behavior | liblzma/7-Zip style branch conversion |
| Delta | xz / 7z 系 Delta filter behavior | distance 1..=256 の byte-wise Delta |
| PPMdH / PPMd7 | 7-Zip public-domain `Ppmd.h`, `Ppmd7.c`, `Ppmd7Dec.c`, `Ppmd7Enc.c` | 7z coder `0x030401` と shared core を実装 |
| LZRW family framing | lzrw1/lzrw1-a/lzrw2/lzrw3/lzrw3-a.c の "DEFINITION OF COMPRESSED FILE FORMAT" 節 (Ross Williams, public domain) | 4B copy flag + 16bit control + ≤16 item グループの共通 frame / 検証を crate-private `compress::lzrw` に集約 |
| Deflate64 | APPNOTE method-9 登録 + Info-ZIP `unzip`/`inflate.c` de facto 定義 | internal `compress::deflate64` shared core。要件・テスト網羅は zip README #16 / sevenz README #68b を参照 |
| LZX | MS LZX Data Compression Format doc + cabextract `lzx.c` errata ([MS-PATCH] は LZX DELTA variant) | internal `compress::lzx` shared core — mscab CAB LZX と lzxd で共有 |

→ 詳細テスト: [util.md](util.md)

---

## 補助検証レーン

| レーン | 目的 | 現在の対象 | 出力 / 備考 |
|---|---|---|---|
| `archive-fuzz` self pattern | crate 内 encode/decode roundtrip を広く反復検証 | compression + archive formats の public fuzz target 群 | failure は signature 単位で dedupe し、最小化後に `.json` + `.bin` artifact として保存 |
| `archive-fuzz` original-compress / original-decompress | system tool との相互運用回帰 | external tool が存在する format の canonical CLI path | `known_issues` に列挙した intentional filter を除き、残存 failure は回帰候補として扱う |
| `archive-fuzz` corrupt pattern | 変異した encoded stream および実ツール生成 fixture (`tests/fixtures/`) に対する decoder 耐性 (panic / resource oracle 違反の検出) | encode 可能な全 fuzz target + fixture 存在 format | 通常の decode error は期待動作。変異はランダム byte / prefix 切断 / 境界値書き込みを決定的シードで適用し、失敗時は変異後ストリームを `.mut.bin` sidecar として保存するため replay は fixture や encode 経路に依存しない。fixture は pristine decode でベースラインを取り、decode 不能なもの (補助データ等) はスキップ、出力上限も fixture 由来にする |
| `archive-fuzz` coverage-guided mode | structured seed + persistent corpus mutation による input variation 拡張 | `fuzz/corpus/` を読む guided lane、novel observation harvest | run ごとに `manifest.json` / `summary.json` / `matrix.json` を出力。コーパスは `--corpus-max-entries` (既定 1024/algorithm、0=無制限) で件数を制限し、超過時は load 時に prune・保存時に置換する |
| `archive-fuzz` special case matrix | archive metadata / encryption / encoded-header / multi-entry variation + codec determinism の deterministic 検証 | `ar` / `tar` / `cpio` / `zip` / `7z` の long-name / metadata / encryption variation + 各 archive アルゴリズムの `multi-entry` ケース + 全 codec の `determinism` (2 回 encode のバイト一致) | 通常のランダムファズに先立ち固定ケースとして実行し、通常の failure と同一の artifact パイプラインで処理する |
| resource oracle | 正常終了ケースの異常な膨張や過大 runtime を failure 化 | runtime / encoded size / decoded size の bounded check | 成功扱いでも oracle 違反なら failure artifact を残す。`corrupt` では変異ループの誤検出を避けるため runtime / decode 等価性を免除し、変異ごとの decode 出力上限のみを適用する |
| `archive-fuzz` watchdog | `catch_unwind` が捕捉できない無限ループ / OOM abort の検出 | 全パターンの全 case (case 入口で `inflight-<worker>` breadcrumb を永続化、probe 単位で予算リセット) | 予算超過時に `hang-*` artifact を書き exit code 3 で abort。breadcrumb はプロセスが先に死んでも残るためランが静かに止まることを防ぐ。`hang-*.json` は `archive-fuzz replay` で再現確認できる |
| `archive-fuzz` artifact 管理 | 蓄積した failures/corpus 成果物のライフサイクル管理 | `clean` (内容のみ削除、`.gitkeep` と dir は温存、`--keep-latest N` で直近 `run-*` 保持、`--failures-only` / `--corpus-only` で片側選択) と `summary` (run dir または summary.json の集計表示、read-only) | `run` 起動時に残存 `inflight-*.json` breadcrumb を警告 (同時実行中は false positive になり得る) |

### 32-bit ターゲットの境界

`usize` が 32 bit の i686 / wasm32 では、on-disk の u32 長・オフセット・件数を
`usize` に変換した後の加算・乗算が overflow し得る。decoder は `checked_add` /
`checked_mul` / `checked_shl` を使い、overflow を `Error` として返す
(panic させない)。増分は長さ・件数に比例しており、u32 の全範囲を表現できない
32-bit では確保前に拒否する。`fuzz-i686` と `fuzz-wasm` がこの境界を継続検証し、
見つかった artifact は `tests/integration/generated/` に回帰として取り込む。
境界 escape が巨大な出力を要求するケースは、無制限 `decode()` ではなく
上限付き decoder の unit test で回帰にする。zpaq 系は decode 前にヘッダ由来の
モデルを確保するため import せず、i686 / wasm32 の replay で確認する。

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

## フォーマット別要件表

### 圧縮フォーマット

| フォーマット | 基準仕様 | ✅ | ⚠️ | ❌ | 合計 |
|---|---|---|---|---|---|
| [DEFLATE](deflate/README.md) | RFC 1951 | 64 | 0 | 0 | 64 |
| [gzip](gzip/README.md) | RFC 1952 | 41 | 0 | 1 | 42 |
| [zstd](zstd/README.md) | RFC 8878 | 140 | 0 | 0 | 140 |
| [zstd-seekable](zstd-seekable/README.md) | Zstandard Seekable Format v0.1.0 | 23 | 0 | 0 | 23 |
| [bzip2](bzip2/README.md) | bzip2 1.0.x 参照実装 (de facto) | 76 | 0 | 1 | 77 |
| [lzip](lzip/README.md) | lzip マニュアル | 45 | 0 | 0 | 45 |
| [`.lzma`](lzma_alone/README.md) | lzma-file-format.txt (tukaani/xz doc) | 31 | 0 | 0 | 31 |
| [LZW](lzw/README.md) | ncompress `compress42.c` (de facto) | 26 | 0 | 0 | 26 |
| [LZ4](lz4/README.md) | LZ4 Frame/Block Format | 60 | 0 | 0 | 60 |
| [LZO](lzo/README.md) | kernel `Documentation/staging/lzo.rst` + lzop format | 45 | 0 | 0 | 45 |
| [Snappy](snappy/README.md) | snappy format_description / framing_format | 37 | 0 | 0 | 37 |
| [Brotli](brotli/README.md) | RFC 7932 | 65 | 0 | 0 | 65 |
| [zlib](zlib/README.md) | RFC 1950 | 20 | 0 | 0 | 20 |
| [xca](xca/README.md) | [MS-XCA] (Microsoft Open Specifications) | 40 | 0 | 0 | 40 |
| [lzf](lzf/README.md) | liblzf `lzfP.h` / ning LZFFormat (de facto) | 20 | 0 | 0 | 20 |
| [fastlz](fastlz/README.md) | fastlz.c 参照実装 (MIT) | 24 | 0 | 0 | 24 |
| [zx0](zx0/README.md) | ZX0 v2 README (BSD-3) | 23 | 0 | 0 | 23 |
| [zx1](zx1/README.md) | ZX1 README (BSD-3) | 23 | 0 | 0 | 23 |
| [zx2](zx2/README.md) | ZX2 README (BSD-3) | 22 | 0 | 0 | 22 |
| [zx5](zx5/README.md) | ZX5 README (BSD-3) | 26 | 0 | 0 | 26 |
| [vcdiff](vcdiff/README.md) | RFC 3284 | 30 | 0 | 0 | 30 |
| [mppc](mppc/README.md) | RFC 2118 + [MS-RDPBCGR] | 32 | 0 | 0 | 32 |
| [lzs](lzs/README.md) | RFC 2395 (§2.2 = ANSI X3.241 informational 転記) | 26 | 0 | 0 | 26 |
| [lzrw1](lzrw1/README.md) | lzrw1.c 参照実装 (public domain) | 22 | 0 | 0 | 22 |
| [lzrw1a](lzrw1a/README.md) | lzrw1-a.c 参照実装 (public domain) | 20 | 0 | 0 | 20 |
| [lzrw2](lzrw2/README.md) | lzrw2.c 参照実装 (public domain) | 22 | 0 | 0 | 22 |
| [lzrw3](lzrw3/README.md) | lzrw3.c 参照実装 (public domain) | 23 | 0 | 0 | 23 |
| [lzrw3a](lzrw3a/README.md) | lzrw3-a.c 参照実装 (public domain) | 23 | 0 | 0 | 23 |
| [lzsa](lzsa/README.md) | LZSA StreamFormat / BlockFormat_LZSA1/LZSA2 v1.4.1 | 33 | 0 | 0 | 33 |
| [lzxd](lzxd/README.md) | [MS-PATCH] LZX DELTA (Microsoft Open Specifications) | 22 | 0 | 0 | 22 |
| [cmpsc](cmpsc/README.md) | IBM z/Arch POP App.D / ESA/390 Data Compression + APPNOTE method 16 | 22 | 0 | 0 | 22 |
| [rzip](rzip/README.md) | rzip `.rz` format (upstream 2.1) | 21 | 0 | 0 | 21 |
| [lrzip](lrzip/README.md) | magic.header.txt + upstream de facto facts (crate-local subset) | 43 | 0 | 1 | 44 |
| [packbits](packbits/README.md) | Apple TN1023 + TIFF 6.0 §9 | 12 | 0 | 3 | 15 |
| [xz](xz/README.md) | xz-file-format.txt 1.2.1 | 62 | 0 | 0 | 62 |
| [ZPAQ](zpaq/README.md) | ZPAQ Level 1/2 specification (zpaq206.pdf) | 55 | 0 | 4 | 59 |

### アーカイブフォーマット

| フォーマット | 基準仕様 | ✅ | ⚠️ | ❌ | 合計 |
|---|---|---|---|---|---|
| [tar](tar/README.md) | POSIX.1-1988 ustar / GNU tar / POSIX.1-2017 PAX | 62 | 1 | 0 | 63 |
| [cpio](cpio/README.md) | POSIX `odc` / SVR4 `newc`/`newcrc`/`bin` | 42 | 1 | 0 | 43 |
| [ar](ar/README.md) | IEEE Std 1003.1 Issue 7 (Issue 8 は記述削除) / GNU ar / BSD ar | 29 | 0 | 2 | 31 |
| [deb](deb/README.md) | deb(5) (dpkg) | 27 | 0 | 2 | 29 |
| [rpm](rpm/README.md) | rpm.org Package Format (v4/v6) | 37 | 0 | 2 | 39 |
| [squashfs](squashfs/README.md) | SquashFS 4.0 binary format | 46 | 0 | 1 | 47 |
| [mscab](mscab/README.md) | [MS-CAB] Cabinet File Format | 29 | 0 | 0 | 29 |
| [mscfb](mscfb/README.md) | [MS-CFB] Compound File Binary File Format v20210625 | 22 | 0 | 2 | 24 |
| [cramfs](cramfs/README.md) | Linux kernel cramfs.rst + fs/cramfs/README + cramfs_fs.h | 25 | 0 | 3 | 28 |
| [romfs](romfs/README.md) | Linux kernel romfs.rst | 22 | 0 | 1 | 23 |
| [erofs](erofs/README.md) | Linux kernel erofs.rst + erofs-utils `include/erofs_fs.h` (MIT) | 38 | 0 | 1 | 39 |
| [iso9660](iso9660/README.md) | ECMA-119 + SUSP 1.10 + RRIP 1.12 + Joliet + El Torito 1.0 / zisofs | 44 | 0 | 1 | 45 |
| [crx3](crx3/README.md) | Chromium components/crx_file/crx3.proto | 15 | 0 | 2 | 17 |
| [pea](pea/README.md) | PEA file format spec (pea_help.pdf) + PeaZip pea.pas/pea_utils.pas | 20 | 0 | 3 | 23 |
| [zim](zim/README.md) | openZIM ZIM file format (v5/v6) | 27 | 0 | 2 | 29 |
| [mtree](mtree/README.md) | FreeBSD mtree(5) / libarchive mtree | 25 | 0 | 2 | 27 |
| [warc](warc/README.md) | ISO 28500:2009 / IIPC WARC 1.1 | 34 | 0 | 1 | 35 |
| [lha](lha/README.md) | lha header documentation + jLHA Notes + lzhformat.html + 奥村氏 ar002/lzss.c (PD) + lhasa (ISC) | 24 | 0 | 0 | 24 |
| [arj](arj/README.md) | ARJ technical note (ARJ 2.x) + UNARJ/newtua_dos 参照実装 | 24 | 0 | 3 | 27 |
| [arc](arc/README.md) | SEA ARC file format description + hyc/arc `Arcinfo` | 24 | 0 | 1 | 30 |
| [git-pack](git-pack/README.md) | gitformat-pack(5) (git v2.51.0) | 39 | 0 | 0 | 39 |
| [xar](xar/README.md) | xarformat (mackyle/xar wiki) | 34 | 0 | 3 | 37 |
| [ZIP](zip/README.md) | APPNOTE.TXT 6.3.10 (PKWARE) | 155 | 0 | 5 | 161 |
| [7z](sevenz/README.md) | 7zFormat.txt / Methods.txt (LZMA SDK 26.00) | 123 | 0 | 0 | 123 |

### エンコードフォーマット

| フォーマット | 基準仕様 | ✅ | ⚠️ | ❌ | 合計 |
|---|---|---|---|---|---|
| [uuencode](uuencode/README.md) | IEEE Std 1003.1-2017 uuencode | 21 | 0 | 0 | 21 |
| [ascii85](ascii85/README.md) | PDF 32000-1:2008 §7.4.3 + RFC 1924 | 18 | 0 | 0 | 18 |
| [yenc](yenc/README.md) | yEnc revised draft 1.3 (yenc.org) | 24 | 0 | 2 | 26 |
| [macbinary](macbinary/README.md) | MacBinary II Standard Proposal (24-Jul-1987) | 14 | 0 | 6 | 20 |
| [binhex](binhex/README.md) | BinHex 4.0 Definition (Peter N Lewis 1991) + RFC 1741 | 21 | 0 | 3 | 24 |

### 共有コンポーネント

| コンポーネント | ファイル | ✅ | ⚠️ | ❌ | 合計 |
|---|---|---|---|---|---|
| CRC-32 / CRC-64 / XXH32 / XXH64 / Adler-32 / SHA-1 / SHA-256 / MD5 / AES / DES / RC2 / RC4 / BitReader / Error | [util.md](util.md) | 63 | 0 | 0 | 63 |

### 全体集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み | 2447 |
| ⚠️ 部分実装 | 2 |
| ❌ 未実装 | 58 |
| — 該当なし | 6 |
| **合計** | **2513** |

**全体カバー率**: 2447 / 2507 = **97.6%** (❌ 行 (intentional exclusion・要修正候補を含む) および該当なし除外後: 2447 / 2449 = **99.9%**)
