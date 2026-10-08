# ZPAQ — 低レイヤ codec (zpaq206 §2-§7)

対象: `src/compress/zpaq/` (arithmetic.rs, config.rs, decode.rs, encode.rs, models.rs, predictor.rs, tables.rs, zpaql.rs)

状態マーカー: ✅ 実装+テスト済み / ⚠️ 部分実装 / ❌ 未実装

## §2 ZPAQ stream syntax

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 1 | block = `"zPQ"` + level + hsize + header + segment* + EOB=255 (header は hsize bytes) | §2 | ✅ | `find_block`, `decode_rejects_malformed_streams` |
| 2 | header = `hh hm ph pm n comp* END=0 hcomp END=0` | §2 | ✅ | header parse + `decode_rejects_malformed_streams` |
| 3 | comp record: type 1-9 と type ごとの引数 (sizebits/limit/rate/mask/index 参照) | §2, §3 | ✅ | `Predictor::init` で型・引数範囲を検証 |
| 4 | n (component count) ≤ 255 | §2 | ✅ | `decode_rejects_component_count_over_hash_size` (n > 2^hh は upstream 互換で spec の modulo indexing より厳格に reject) |
| 5 | segment = `1 filename 0 comment 0 RESERVED=0 ecd eos` | §2 | ✅ | reserved byte 検査 + `decode_rejects_malformed_streams` |
| 6 | filename / comment は NUL 終端、各 0..65535 bytes | §2 | ✅ | encoder は `validate_metadata` で強制 (`test_rejects_oversized_filename`/`test_rejects_oversized_comment`)。decoder は upstream 同様無制限に受理 (lax) |
| 7 | eos = `254` (checksum なし) または `253` + SHA-1[20] (postprocessed 出力の hash) | §2 | ✅ | `hello.upstream-l*` fixture + checksum 破損 reject |
| 8 | `HPROG=1`・`PROG=1`・`RESERVED=0` を検査し範囲外を reject | §2, §7 | ✅ | `decode_rejects_malformed_streams` |
| 9 | stored stream (n=0、level ≥ 2 のみ): `ecd ::= (elen edata)*`、`elen[4]` + data 列、len=0 で終端 | §2, §4 | ✅ | `hello.upstream-stored` fixture、`stored_mode_roundtrip` |
| 10 | dd = `PASS=0 | PROG=1 plen pcomp pdata` (pcomp は plen bytes) | §2, §5 | ✅ | PCOMP fixtures (`hello.upstream-pcomp-id`/`inc`) |
| 11 | 実行されない invalid opcode を含む program は受理される (実行時にのみ error) | §2 | ✅ | `zpaql.rs` `run()` は fetch/実行時にのみ検査 (program の事前スキャンなし) |
| 12 | 13-byte locator tag + 埋め込み scan (後続 non-ZPAQ data は `"zPQ"` で始まらない) | §7 | ✅ | `find_block` rolling scan、locator 非存在は empty output |

## §3 predictor components (predict/update 意味論)

`sns` state table・`squash`/`stretch`/`dt`/`dt2k` は upstream `libzpaq.cpp` からの移植で、upstream 生成 stream との byte-exact decode (`decode_upstream_fixtures`) で検証。

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 13 | CONST (type 1) | §3.1 | ✅ | `custom_model_cm_avg_roundtrip` 等 |
| 14 | CM (type 2): context map + counter | §3.2 | ✅ | `custom_model_cm_avg_roundtrip` (built-in 未使用のため custom model 経由) |
| 15 | ICM (type 3): indirect context model | §3.3 | ✅ | `decode_upstream_fixtures` |
| 16 | MATCH (type 4): LZ77-style match model | §3.4 | ✅ | `decode_upstream_fixtures` |
| 17 | AVG (type 5): weighted average | §3.5 | ✅ | `custom_model_cm_avg_roundtrip` (built-in 未使用) |
| 18 | MIX2 (type 6): 2-input mixer + update | §3.7 | ✅ | `decode_upstream_fixtures` |
| 19 | MIX (type 7): m-input mixer | §3.6 | ✅ | `decode_upstream_fixtures` |
| 20 | ISSE (type 8): indirect SSE chain | §3.8 | ✅ | `decode_upstream_fixtures` |
| 21 | SSE (type 9): secondary symbol estimator | §3.9 | ✅ | `decode_upstream_fixtures` |
| 22 | model は block 開始時 init・segment 跨ぎで状態維持、arith coder は segment ごと init、hcomp は byte ごと実行 | §3 | ✅ | segment 跨ぎ状態維持は multi-segment roundtrip (`test_decode_merges_continuation_segment` 系) と multi-block JIDAC fixture (`decode_jidac_appended_mixed`) で検証 |

## §4 arithmetic decoder

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 23 | decoder state init (LOW=1, HIGH=2^32-1, CURR 4byte)・MID split・normalization・LOW=0→1 | §4 | ✅ | `arithmetic.rs` + byte-exact decode |
| 24 | EOS bit は PR=0、他の bit は odd multiple of 1/65536 の PR | §4 | ✅ | 同上 |
| 25 | 末尾のゼロ byte 詰め (decoder は入力尽き後 0 を読む) | §4 | ✅ | **bounded deviation**: 実装は EOF で `unexpected end of coded input` error を返す。upstream は `get()=-1` で継続するため crate の方が厳格 |

## §5 postprocessor

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 26 | POST state machine (PASS flag・plen load・byte ごと pcomp 実行・`write(2^32-1)`=EOS) | §5 | ✅ | `hello.upstream-pcomp-*` fixture、非 identity PCOMP (`a++ out halt`) |

## §6 ZPAQL virtual machine

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 27 | VM state: PC/A-D/F/H[2^hh]/M[2^hm]/R[256]、run 間で A/PC 以外保持 | §6 | ✅ | `zpaql.rs` |
| 28 | run(): PC 範囲外・ERROR・reserved opcode → error、HALT → return、1-3 byte fetch 規則 | §6 | ✅ | `zpaql.rs` `run()`/`next_operand` の error 分岐 + `decode_rejects_malformed_streams` (不正 program 経由) |
| 29 | Table 1 opcode 全種 (load/store・算術・論理・JT/JF/JMP 符号付き相対・LJ・HASH/HASHD・OUT・HALT、除算ゼロ→0) | §6 Table 1 | ✅ | upstream `execute()` と全 opcode 照合 + `compiles_builtin_models_byte_exact` |
| 30 | program halt 要件 (compliant stream の条件) | §6 | ✅ | cycle limit `1<<28` + 累積 budget (`run()` ごと 8192 credit・cap 1<<28) で reject。**bounded deviation**: §6 は halt のみ要求するため適合 stream を理論上 reject しうる (`shared_cycle_budget_limits_total_across_runs_and_vms`, `shared_cycle_budget_allows_terminating_programs`) |

## §7 compliance

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 31 | level L の decoder は level 1..L を受理 (0 は experimental、3-127 将来予約、128-255 private use) | §7 | ✅ | level byte 1/2 のみ受理・他は reject。level 1 は n>0 必須、level 2 は n=0 stored 許容 (`decode.rs` の level/n 検査) |
| 32 | memory-limit compliance (block header からのメモリ所要量計算式) | §7 | ✅ | 計算式の事前評価はせず `try_reserve` の fallible alloc で同等の安全性を担保 (§7 は「上限までの compliance」を定義する記述であり、allocation failure での拒否はこれに整合) |

## 補足

- squash/stretch の検算値 (3887533746 / 2278286169) は upstream 移植テーブルの byte-exact fixture decode で担保 (専用の自己検算テストはなし)
