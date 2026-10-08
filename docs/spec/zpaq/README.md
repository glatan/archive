# ZPAQ (zpaq206.pdf Level 1/2 v2.06)

| 項目 | 内容 |
|------|------|
| 基準仕様 | [ZPAQ Level 1 and Level 2 specification (zpaq206.pdf, 2016-03-22)](https://mattmahoney.net/dc/zpaq206.pdf) (ローカルスナップショット: `docs/spec/sources/zpaq206.pdf`)。低レイヤ codec (§2-§7)、archive format (§8)、encrypted format (§9) はこの仕様が根拠 |
| 監査メモ | zpaq206.pdf は本文テキストは抽出可能だが、表組みと上付き文字が抽出時に劣化する (`2^15` → `215` 等)。state table・coder 定数・opcode 表など表・数式の精度が求められる部分は、仕様自身の参照実装である libzpaq (public domain) を一次参照として補完した (IMPLEMENTATION_POLICY 例外条件: 書面仕様の該当箇所が実用精度を欠く + 権利 clean)。実装は upstream との wire 互換を fixture + oracle で検証済み |
| 参照実装 | zpaq/libzpaq v7.15 (Matt Mahoney、public domain)。predictor state table (sns)・squash/stretch テーブル・built-in level 1-3 model blob・arithmetic coder 意味論を移植し、-DNOJIT でコンパイルして双方向 interop oracle として検証。upstream 生成 fixture は `tests/fixtures/zpaq/` に収録。JIDAC journaling は仕様書 §8 が書面定義であり、upstream `zpaq.cpp` (v7.15) は fragment 境界判定・emit 順序などの動作参照。`.cfg` config 言語は `libzpaq.cpp` の `Compiler` を移植し、upstream mid.cfg/max.cfg の functional text が built-in level 2/3 blob に byte-exact で一致することを回帰化。upstream `zpaq` CLI (v7.15、`pkg/zpaq` でコンテナ導入) は fuzz oracle (`ArchiveSpec::Zpaq`) と JIDAC 双方向 interop に使用。詳細: THIRD_PARTY_NOTICES ZPAQ 項 |
| current scope | upstream wire 互換な low-level codec (level 1/2、stored/modeled、PASS/PROG postprocessor)、§8 streaming archive (named segment・continuation 対応)、§8 journaling (JIDAC decode・single-transaction emit・incremental append・index metadata decode)、crate-local journaling transaction helper、`ZpaqArchiveEditor`、`decode_bounded` 出力上限、upstream `.cfg` config 言語コンパイラ |
| intentional exclusion | §9 encrypted format (AES-256 CTR + Scrypt wrapper)、multi-part archive の分割 emit (§10)、ZPAQL JIT 実行経路 (upstream `libzpaq.cpp` の x86-64 codegen、意味論は interpreter と等価)、upstream compact method string (`-m x6ci1` 系) パース |
| 検証方針 | low-level codec は upstream 生成 stream の byte-exact decode (committed fixture) と crate 出力を upstream が decode する逆方向 oracle で検証。decoder は upstream parity で lax 受理、encoder は strict (§7: compressor は適合データを出力する責任がある) |

## 対応レイヤ・仕様版

| レイヤ | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| zpaq stream level 1 (modeled のみ) | zpaq206 §2/§7 | ✅ | ✅ | level 1 は n>0 必須 |
| zpaq stream level 2 (modeled / stored) | zpaq206 §2/§4 | ✅ | ✅ | built-in level 2/3 + custom model、stored は n=0 |
| streaming archive (named segment・continuation) | zpaq206 §8 | ✅ | ✅ | 空 filename = 前ファイル continuation |
| journaling archive (JIDAC: jDC/c/d/h/i) | zpaq206 §8 | ✅ | ✅ | `decode_jidac` / `encode_jidac` / `JidacAppender` |
| index archive (d block なし) | zpaq206 §8 | ✅ | ❌ | `decode_jidac_index` で metadata decode。emit は対象外 |
| encrypted archive (AES-256 CTR + Scrypt) | zpaq206 §9 | ❌ | ❌ | intentional exclusion |
| multi-part archive (part00 index + partNN) | zpaq206 §10 | ⚠️ | ❌ | part 連結は caller が concat すれば decode 可、part00 index は `decode_jidac_index` で読み取り可。分割 emit は対象外 |

状態マーカー: ✅ 実装+テスト済み / ⚠️ 部分実装 / ❌ 未実装

---

## 子ファイル

| ファイル | 内容 |
|---|---|
| [codec.md](codec.md) | §2-§7: block/segment syntax、predictor component、arithmetic decoder、postprocessor、ZPAQL VM、compliance |
| [archive.md](archive.md) | §8 archive format (streaming/journaling/index)、crate-local 契約、§9 encryption・§10 implementation notes、未実装事項 |

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み | 55 |
| ⚠️ 部分実装 | 0 |
| ❌ 未実装 | 4 |
| **合計** | **59** |

**カバー率**: 55 / 59 = **93.2%** (❌ はすべて intentional exclusion)
