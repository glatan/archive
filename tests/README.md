# Tests layout

`tests/` 配下は、役割ごとに次の 3 つに分けて配置している。

| Path | Role |
| --- | --- |
| `tests/integration.rs` | integration test harness。本体 crate を feature 全載せで読み込み、`tests/integration/*.rs` を module として束ねる |
| `tests/integration/` | format / algorithm ごとの integration test 本体 |
| `tests/fixtures/` | integration test から参照する固定 fixture とその provenance |

## Directory guide

| Path | Contents | Notes |
| --- | --- | --- |
| `tests/integration/README.md` | integration test inventory | coverage と test case の対応表 |
| `tests/integration/*.rs` | algorithm / format 別 test file | `ar.rs`, `gzip.rs`, `xz.rs` など |
| `tests/fixtures/README.md` | fixture provenance | 元データと加工方法の説明 |
| `tests/fixtures/gzip/`, `tests/fixtures/tar/`, `tests/fixtures/zstd/` など | format ごとの fixture | format 別に寄せて配置 |
| `tests/fixtures/fuzz/` | fuzz regression fixture | 外部ツール相互運用の回帰ケースも含む |

## Conventions

- integration test は原則 `tests/integration/<format>.rs` に置く
- fixture は可能な限り `tests/fixtures/<format>/` に寄せる
- fixture を追加したら `tests/fixtures/README.md` に provenance を追記する
- integration coverage を追加したら `tests/integration/README.md` の対応表も更新する

## Quick navigation

- 全 integration test 実行:
  - `cargo test --all-features --test integration`
- fixture provenance:
  - `tests/fixtures/README.md`
- coverage inventory:
  - `tests/integration/README.md`
