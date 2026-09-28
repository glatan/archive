# archive

純 Rust 実装のアーカイブ・圧縮ライブラリ。外部依存なし、`no_std` + `alloc` 対応。

README は概要と導線だけを持ちます。仕様準拠、互換性メモ、intentional scope 制約、
要件単位のテスト網羅は [`docs/spec/`](docs/spec/README.md) を正本とします。

## 対応フォーマット

| カテゴリ | フォーマット | デコード | エンコード |
|---------|------------|---------|-----------|
| 圧縮 | DEFLATE (RFC 1951) | ✅ | ✅ |
| 圧縮 | gzip (RFC 1952) | ✅ | ✅ |
| 圧縮 | zstd (RFC 8878 + seekable format) | ✅ | ✅ |
| 圧縮 | bzip2 | ✅ | ✅ |
| 圧縮 | lzip (LZMA) | ✅ | ✅ |
| 圧縮 | LZMA-Alone (`.lzma`) | ✅ | ✅ |
| 圧縮 | xz (LZMA2) | ✅ | ✅ |
| 圧縮 | LZW (Unix compress `.Z`) | ✅ | ✅ |
| 圧縮 | LZ4 | ✅ | ✅ |
| 圧縮 | LZO (lzop) | ✅ | ✅ |
| 圧縮 | zlib (RFC 1950) | ✅ | ✅ |
| 圧縮 | Brotli (RFC 7932) | ✅ | ✅ |
| 圧縮 | ZPAQ (コンテキストミキシング) | ✅ | ✅ |
| 圧縮 | lrzip (LZMA/bzip2/LZO/zlib/ZPAQ/none) | ✅ | ✅ |
| 圧縮 | rzip (`.rz`) | ✅ | ✅ |
| 圧縮 | Snappy | ✅ | ✅ |
| 圧縮 | Xpress (MS-XCA Plain LZ77) | ✅ | ✅ |
| 圧縮 | Xpress Huffman (MS-XCA LZ77+Huffman) | ✅ | ✅ |
| 圧縮 | LZNT1 (MS-XCA) | ✅ | ✅ |
| 圧縮 | LZF (liblzf) | ✅ | ✅ |
| 圧縮 | FastLZ | ✅ | ✅ |
| 圧縮 | ZX0 | ✅ | ✅ |
| 圧縮 | ZX1 | ✅ | ✅ |
| 圧縮 | ZX2 | ✅ | ✅ |
| 圧縮 | ZX5 | ✅ | ✅ |
| 圧縮 | VCDIFF (RFC 3284) | ✅ | ✅ |
| 圧縮 | MPPC (RFC 2118) | ✅ | ✅ |
| 圧縮 | Stac LZS (RFC 2395) | ✅ | ✅ |
| 圧縮 | LZRW1-A | ✅ | ✅ |
| 圧縮 | LZSA (v1/v2 ストリーム + raw ブロック) | ✅ | ✅ |
| アーカイブ | ZPAQ (複数エントリ + crate-local journaling) | ✅ | ✅ |
| アーカイブ | tar (UStar/GNU/PAX) | ✅ | ✅ |
| アーカイブ | cpio (`odc` / SVR4 `newc` / `newcrc` / `bin`) | ✅ | ✅ |
| アーカイブ | ar (GNU/BSD) | ✅ | ✅ |
| アーカイブ | deb (Debian package、read) | ✅ | — |
| アーカイブ | rpm (RPM package、read) | ✅ | — |
| アーカイブ | squashfs | ✅ | ✅ |
| アーカイブ | mscab (cab、MSZIP/stored) | ✅ | ✅ |
| アーカイブ | zim | ✅ | ✅ |
| アーカイブ | mtree (manifest、read) | ✅ | — |
| アーカイブ | warc (read) | ✅ | — |
| アーカイブ | git pack (pack/idx v2) | ✅ | ✅ |
| アーカイブ | xar | ✅ | ✅ |
| アーカイブ | lha/lzh (store のみ) | ✅ | ✅ |
| アーカイブ | arj (store のみ) | ✅ | ✅ |
| アーカイブ | arc (store のみ) | ✅ | ✅ |
| アーカイブ | zip | ✅ | ✅ |
| アーカイブ | 7z | ✅ | ✅ |

## 使い方

```toml
[dependencies]
archive = "0.1"
```

```rust
use archive::compress::gzip;
use archive::archive::tar;

// tar.gz を展開
let gz_data = std::fs::read("archive.tar.gz").unwrap();
let tar_data = gzip::decode::decode(&gz_data).unwrap();
let entries = tar::decode::decode(&tar_data).unwrap();

for entry in &entries {
    println!("{}: {} bytes", entry.header.name, entry.data.len());
}
```

## Trait ベース API

フォーマット横断の汎用コードには `traits` モジュールの共通インターフェースを利用できます。

```rust
use archive::traits::{Decode, Encode};
use archive::compress::bzip2::Bzip2Codec;

let codec = Bzip2Codec;
let compressed = codec.encode(b"hello", &()).unwrap();
let decoded = codec.decode(&compressed, None).unwrap();

// デコンプレッションボム対策: 出力サイズ制限
let err = codec.decode(&compressed, Some(3)).unwrap_err();
```

アーカイブ形式には `ArchiveEntry` / `ArchiveDecode` / `ArchiveEncode` trait があります。
詳細は `cargo doc --open` の [`traits`](https://docs.rs/archive/latest/archive/traits/) モジュールを参照してください。

## Workspace packages

### archive-cli

`archive` コマンドとして library の全フォーマットをコマンドラインから操作できます。

```sh
archive list sample.tar.gz --tree        # ツリー表示
archive extract sample.zip --out /tmp    # 展開
archive pack tar src/ -o backup.tar      # 新規 archive 作成
archive compress gzip data -o data.gz    # 圧縮
archive inspect sample.7z               # フォーマット検出
archive test sample.bz2                  # 整合性検証
```

`list` コマンドは TTY 出力時に自動で pager (`$PAGER`, デフォルト `less -FRX`) を通します。
暗号化 zip/7z は `--password` オプション対応。`--json` で機械可読出力。

詳細: [`archive-cli/README.md`](archive-cli/README.md)

### archive-fuzz

roundtrip / 外部ツール相互運用 / regression 検出の fuzz ハーネス。

```sh
cargo run --release -p archive-fuzz                                         # 全アルゴリズム 60 秒
cargo run --release -p archive-fuzz -- --algorithm gzip,zip --duration 30   # 指定のみ
cargo run --release -p archive-fuzz -- --mode coverage-guided --jobs 2      # corpus-guided
cargo run --release -p archive-fuzz -- --replay fuzz/failures/run-.../f.json  # 再現
```

3 種のテストパターン (`self` / `original-compress` / `original-decompress`) + special case matrix + resource oracle。
failure は最小化・重複排除後に `.json` + `.bin` ペアとして保存され、リグレッションテストに変換可能。

詳細: [`fuzz/README.md`](fuzz/README.md)

## ドキュメント構成

| ドキュメント | 内容 |
|------------|------|
| `README.md` | フォーマット一覧・使い方・導線 |
| `cargo doc --open` | API 概要・feature flag・使用例 |
| [`docs/spec/`](docs/spec/README.md) | 仕様準拠・互換性メモ・テスト網羅・intentional scope の正本 |
| `THIRD_PARTY_NOTICES` | 参照実装・bundled asset の provenance |
| [`archive-cli/README.md`](archive-cli/README.md) | CLI コマンド詳細・オプション一覧 |
| [`fuzz/README.md`](fuzz/README.md) | Fuzz ハーネスの使い方・artifact 構造 |

## 状態の読み方

- 既知の不具合: **現時点では open な一覧なし**
- 形式ごとの current scope / intentional scope 制約: `src/lib.rs` と各 module doc comment
- 仕様準拠、互換性メモ、テスト根拠: [`docs/spec/`](docs/spec/README.md)

## ライセンス

AGPL-3.0-only
