# AGENTS.md

このファイルは、このリポジトリで作業するときの **実行ルール** と **文書更新ルール** をまとめたものである。

## テスト / clippy 実行ルール

- コードを変更した場合は、完了前に `cargo fmt` も実行して整形を合わせる。
- 変更中は、変更対象に近い **targeted test** を先に実行してよい。
- テスト確認は原則として **コンテナ内** で行う。既存フローとして `make build-container.test && make test` を優先し、ホスト側の `cargo test ...` は調査・切り分け用の補助として使う。
- ユーザーへ完了報告する前には、コード変更がある場合は原則として次の検証を通過させる。
  - `cargo fmt`
  - `make build-container.test && make test`
  - `cargo clippy --all-features --all-targets -- -D warnings`
- `no_std` / feature gating / `std` 依存境界に関わる変更をした場合は、追加で `cargo test --no-default-features` も確認する。
- `clippy` は現状ホスト側実行を基本とするが、container で再現が必要な failure は debug/test image を使って確認する。
- fuzz / system tool interop は、通常の修正では毎回必須ではない。必要な変更をしたときだけ既存フローに従って追加で確認する。
- ドキュメントのみの変更では、コードの挙動が変わらない限りテスト / clippy の再実行は必須ではない。

## ドキュメント記載ルール

### 役割分担

- `README.md`
  - 概要、導線、基本的な使い方だけを書く。
  - 詳細仕様や網羅表を重複して持たない。
- `docs/spec/`
  - 仕様準拠、テスト網羅、既知制約、優先方針の **正本**。
  - 実装や監査結果に応じてここを最優先で更新する。
  - 各要件は、可能な限り「どの仕様書のどの箇所に対応するか」まで追える形で記載する。
- `src/lib.rs`
  - crate 全体の capabilities、feature flags、documentation map を示す。
  - `README.md` と `docs/spec/` をどう読むかの入口にする。
- `archive-cli/README.md`
  - CLI コマンドの詳細・オプション一覧・使用例を書く。
  - ルート `README.md` からは導線だけ持ち、詳細はここに寄せる。
- `fuzz/README.md`
  - Fuzz ハーネスの使い方・テストパターン・artifact 構造・リグレッション化手順を書く。
  - ルート `README.md` からは導線だけ持ち、詳細はここに寄せる。
- 各 module doc / doc comment
  - そのモジュールの **現在の実装範囲** を正確に書く。
  - 将来やりたいことではなく、今サポートしていることだけを書く。

### 更新ルール

- 挙動・対応範囲・制約が変わったら、必要に応じて次を同じ変更で同期する。
  - `docs/spec/`
  - `README.md`
  - `src/lib.rs`
  - 影響を受ける module doc / doc comment
- `README.md` に細かい仕様表や制約一覧を増やしすぎない。詳細は `docs/spec/` に寄せる。
- doc comment や README では、未実装機能を実装済みのように書かない。過大 claim を避ける。
- テストを追加して coverage claim を強めた場合は、`docs/spec/` の該当行も更新する。
- `docs/spec/` の要件・網羅項目を書くときは、単に仕様名を書くのではなく、対応する仕様書の節・章・項目まで辿れる粒度を意識する。
- 参照実装・外部 oracle・fixture を新たに利用した場合は、次を同一変更で同期する。
  - `docs/spec/<format>/README.md` の `参照実装` 行
  - `THIRD_PARTY_NOTICES` の該当フォーマットエントリ
  - `docs/spec/sources/manifest.json` (fetch 可能な資料は `sources`、URL のない参照物は `no_url_available`)。manifest の対象はソースレベルの参照実装・oracle・仕様資料に限定し、純粋なバイナリツール (system コマンドの oracle) は TPN と fixtures README で記録する
- 意図的な scope 制約を維持する場合は、「未対応」ではなく **intentional scope** と分かる書き方を優先する。
- 他実装参照の原則禁止と例外条件 (実装ポリシー) の正本は `docs/IMPLEMENTATION_POLICY.md` を参照。

## 補足

- 作業計画や進捗メモは session 側の `plan.md` を使い、リポジトリには新しい `TODO.md` / `TASKS.md` を増やさない。
- 新しい運用ルールを追加したら、まずこの `AGENTS.md` に集約できるかを検討する。
