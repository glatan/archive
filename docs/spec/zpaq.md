# ZPAQ

| 項目 | 内容 |
|------|------|
| current scope | 単一 payload codec、basic multi-entry archive、crate-local journaling transaction helper、materialized archive editor を対象にする |
| public encoder / archive writer | low-level encoder は built-in level `1..=3` と validated custom model、archive writer は basic writer / same-block append / journaling / materialized archive editor を持つ |
| decoder acceptance | parsed model/header が妥当なら level byte 自体は固定値に制限しない |

### 現在の bounded contract と網羅状況

| 軸 | 現在の bounded contract | 代表テスト/備考 |
|----|-------------------------|----------------|
| predictor component types | `CONS` / `CM` / `ICM` / `AVG` / `MATCH` / `MIX2` / `MIX` / `ISSE` / `SSE` | low-level fixture + `Predictor::try_new()` success tests |
| size parameter sweep | `CM` / `MATCH` / `MIX2` / `MIX` / `SSE` は `0, 1, 4, 8, 12, 16`、`ICM` / `ISSE` は `0, 1, 4, 8, 12` の bounded sweep を回帰化し、極端値は `invalid component size` として reject | `test_try_new_accepts_bounded_component_size_sweep`, `test_try_new_rejects_extreme_component_sizes` |
| dependency depth / chain shape | 代表的な deeper chain として `CM + ICM + MIX2 + SSE`, `AVG + ISSE + MIX`, `MATCH` を含む deep chain を回帰化 | predictor/decode の deep-chain tests |
| HCOMP corpus | register/jump/arithmetic/logical/shift/memory/hash の representative family に加え、mixed memory/hash/arithmetic sequence、nested conditional branch shape、invalid absolute jump を回帰化 | `zpaql.rs` の extended tests |
| block/model/archive surface | noncanonical level byte accept、multiple named segments、empty payload entries、metadata/truncation/corruption、multi-segment archive boundary、same-block append workflow、crate-local journaling transaction (committed latest view / version history / uncommitted tail ignore) を回帰化 | `decode.rs`, `archive::zpaq`, integration tests |
| public writer parity | public writer が生成する built-in level `1..=3` surface については low-level/archive-level roundtrip、level clamp regression、parsed existing header を再利用する append writer regression、`ZpaqJournalEncoder` の commit/update/delete regression を回帰化 | `compress::zpaq::encode`, `archive::zpaq::encode`, integration tests |
| custom authoring API | low-level `compress::zpaq::encode::CustomModel` は arbitrary validated predictor config / HCOMP / `hh` / `hm` / level byte を受け取り、`encode_with_model()` で emission 可能。validation は HCOMP bytecode と predictor component config を encode 前に通す | `test_encode_with_custom_model_roundtrip`, `test_custom_model_rejects_invalid_memory_size` |
| decoder validation policy | parsed model/header を先に検証し、known component type の不完全 config、unsupported / truncated HCOMP instruction、unknown component type、VM cycle limit exhaustion を payload decode 前に reject する | `decode.rs`, `zpaql.rs` validation tests |
| metadata 制約 | archive writer は filename/comment を NUL-terminated string として格納するため、metadata 内の NUL byte は reject する | archive writer contract |
| journaling semantics | crate-local journaling helper は reserved metadata prefix 付き segment + commit marker を 1 transaction として扱い、`decode_journal_latest()` は committed transaction のみを適用して filename 単位で latest-visible policy を返す。`decode_journal_versions()` は commit ごとの snapshot history を返し、不完全 tail は ignore する | `test_decode_journal_latest_applies_put_update_and_delete`, `test_decode_journal_versions_ignores_uncommitted_tail`, `test_zpaq_journal_latest_view_roundtrip`, `test_zpaq_journal_delete_visibility` |
| archive workflow expansion | `ZpaqArchiveEditor` は plain archive / latest journal view を import し、`push`/`put`/`delete` を staged に適用して 1 つの simplified archive に materialize できる。import 時は parsed existing header/model を再利用する | `test_archive_editor_from_archive_put_and_delete`, `test_archive_editor_from_journal_latest_materializes_plain_archive`, `test_zpaq_archive_editor_rewrites_imported_archive`, `test_zpaq_archive_editor_materializes_journal_latest_view` |
| 未実装事項 | 現時点では open item なし。追加 scope を広げる場合は bounded contract を先に更新する | current contract status |


---

## 集計

ZPAQ は正式な仕様書がないため、bounded contract 形式で管理している。
上記の各軸が current contract を構成し、すべてテスト回帰化済み。
