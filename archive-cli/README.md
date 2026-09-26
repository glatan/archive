# archive-cli

`archive` ライブラリの全フォーマットをコマンドラインから操作する binary package。

## インストール

```sh
cargo install --path archive-cli
```

## コマンド一覧

### `archive inspect <input>`

検出フォーマット、entry 数、scope note を表示。

```sh
archive inspect sample.tar.gz
archive inspect sample.7z --json
archive inspect encrypted.zip --password secret
```

### `archive list <input>`

entry 一覧を表示。

```sh
archive list sample.tar.gz                    # 一行一 entry
archive list sample.tar.gz --long             # サイズ・mode・mtime 付き
archive list sample.tar.gz --tree             # ツリー表示
archive list sample.tar.gz --json             # JSON 出力
archive list sample.tar.gz --no-pager         # pager を無効化
```

TTY 出力時は自動的に `$PAGER` (デフォルト `less -FRX`) を通します。
1 画面に収まる場合は即表示、長い場合はスクロール可能です。
`--no-pager` またはパイプ先がある場合は pager を使いません。

### `archive test <input>`

decode と checksum 検証を実行し、整合性を確認。

```sh
archive test sample.tar.gz
archive test encrypted.7z --password secret --json
```

### `archive extract <input>`

archive を展開、または単体圧縮ファイルを復元。

```sh
archive extract sample.tar.gz                          # カレントディレクトリに展開
archive extract sample.tar.gz --out /tmp/dest           # 出力先を指定
archive extract sample.zip --password secret            # 暗号化 zip
archive extract sample.tar.gz dir/file.txt              # 特定 entry のみ
archive extract sample.tar.gz --overwrite               # 既存ファイルを上書き
archive extract sample.deb                              # data.tar ペイロードを展開
archive extract sample.rpm                              # cpio payload の内容を展開
archive extract image.sqfs                              # squashfs 内の regular file を展開
```

`.deb` は `data.tar` の内容を展開します。生の member (`debian-binary` / `control.tar.*`) は `--format ar` で展開してください。

### `archive pack <format> <input...> -o <output>`

新しい archive を作成。

```sh
archive pack tar src/ docs/ -o backup.tar
archive pack zip src/ -o release.zip --password secret
archive pack 7z data/ -o archive.7z
archive pack cpio files/ -o archive.cpio --overwrite
```

対応フォーマット: `tar`, `cpio`, `ar`, `zpaq`, `zip`, `7z`

### `archive compress <format> <input> -o <output>`

単体圧縮ファイルを作成。

```sh
archive compress gzip data.bin -o data.bin.gz
archive compress zstd data.bin -o data.bin.zst
archive compress bzip2 data.bin -o data.bin.bz2 --level 9
archive compress lrzip data.bin -o data.bin.lrz --backend bzip2
```

対応フォーマット: `gzip`, `zstd`, `bzip2`, `lzip`, `lzma`, `lzw`, `lz4`, `lzo`, `lrzip`, `rzip`, `zlib`, `snappy`, `brotli`, `deflate`, `xz`, `zpaq`

`--level` は gzip (0-9), bzip2 (1-9), rzip (1-9), lzw (9-16), zpaq (1-3) で有効。
`--backend` は lrzip のみ (`none`, `bzip2`, `lzo`, `lzma`, `gzip`, `zpaq`)。

## 共通オプション

| オプション | 対応コマンド | 説明 |
|-----------|------------|------|
| `--format <fmt>` | inspect, list, test, extract | フォーマット自動検出を上書き |
| `--password <pw>` | inspect, list, test, extract, pack | 暗号化 zip/7z のパスワード |
| `--json` | inspect, list, test | JSON 形式で出力 |
| `--overwrite` | extract, pack | 既存ファイルを上書き |

## フォーマット自動検出

magic bytes からフォーマットを自動検出します。
`.deb` は `!<arch>\n` の直後の member 名 `debian-binary` で識別され、汎用 `ar` より優先されます。
`.rpm` は Lead magic `ED AB EE DB` で識別されます (read のみ、署名検証は対象外)。
`.squashfs` は `hsqs` magic で識別されます (read のみ、LZMA1 image は非対応)。
検出できない場合 (raw deflate, brotli, snappy, lzma など) は `--format` で明示してください。

## ライセンス

AGPL-3.0-only
