---
description: "圧縮ファズテスト実行 → リグレッションテスト作成 → バグ修正"
---

引数: $ARGUMENTS (形式: "<algorithm|all> <duration_seconds>")

共通ルールは `.claude/README.md` を参照。

## Step 1: ファズテスト実行

Podman でコンテナビルド・実行:
```sh
make build-container.fuzz
make fuzz FUZZ_ALGORITHM=<algo> FUZZ_DURATION=<seconds> [FUZZ_PATTERN=<pattern>]
```

補足:
- コンテナ実行前に `fuzz/failures/` の古い artifact を消すか、タイムスタンプで今回生成分だけを見る
- container が重いときはローカル実行:
  ```sh
  cargo run -p archive-fuzz -- --algorithm <algo> --duration <seconds>
  ```

## Step 2: `@fuzz-analyzer` で分析

`@fuzz-analyzer` を起動し、`fuzz/failures/` 内の artifact を分析させる。

分類結果:
| 分類 | 対応 |
|------|------|
| バグ (HIGH) | Step 3-4 で即座に修正 |
| バグ (MEDIUM) | Step 3-4 で調査・修正 |
| 既知の非互換 | フィルタ (対応不要) |
| resource oracle 違反 | 性能問題として記録 |

### 既知の非互換 (フィルタリング対象)

| アルゴリズム | パターン | 想定エラー | 理由 |
|------------|---------|-----------|------|
| lrzip | original-compress | `unsupported compression type` | system `lrzip` の一部 backend 未対応 |
| LZW | original-compress/decompress | 空入力エラー | `ncompress` は空入力を拒否 |
| LzwBits9 | original-compress | `mismatch` | `ncompress -b 9` は一部入力でロッシーな roundtrip を起こす外部ツールのバグ |

詳細フィルター実装: `fuzz/src/known_issues.rs` の `classify()` を参照。

## Step 3: リグレッションテスト作成

`@fuzz-analyzer` の報告に基づき、`@spec-implementer` でテストを追加:

- Pattern `self` → `src/compress/<algorithm>/decode.rs` の `#[cfg(test)]`
- Pattern `original-*` → `tests/integration/<algorithm>.rs`

テスト形式:
```rust
#[test]
fn test_fuzz_regression_<algorithm>_<hash_prefix>() {
    let input: &[u8] = &[/* 失敗入力バイト列 */];
    let encoded = <algorithm>::encode::encode(input);
    let decoded = <algorithm>::decode::decode(&encoded).unwrap();
    assert_eq!(decoded, input);
}
```

入力が 1KB 超 → `tests/fixtures/fuzz/` にバイナリ保存、`include_bytes!` で参照。

## Step 4: バグ修正

`@spec-implementer` でソースコード修正:

1. `cargo test test_fuzz_regression_` で失敗を再現
2. `@fuzz-analyzer` の推定原因を参考に修正
3. 修正後の確認:
   ```sh
   cargo test --all-features
   cargo clippy --all-features --all-targets -- -D warnings
   ```

## Step 5: spec 更新 (必要な場合)

バグ修正で仕様準拠状況が変わった場合、`docs/spec/` を更新。
`/spec-audit <algorithm>` を実行して整合性を確認する。
