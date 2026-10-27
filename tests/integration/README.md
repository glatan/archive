# Integration tests

このディレクトリ配下の integration test は、crate の public API を format ごとに end-to-end で検証することを目的とする。
主に次の項目を検証する。

- encode/decode の roundtrip
- `encode_writer` / `decode_reader`
- system tool との相互運用
- metadata / dictionary / multi-member / multi-frame
- corruption / malformed input / checksum mismatch

`tests/integration.rs` が harness であり、有効な feature に対応する
`tests/integration/*.rs` のみを module として読み込む。

## 実行方法

- 全体:
  - `cargo test --all-features --test integration`
- 単一 feature のみ:
  - `cargo test --no-default-features --features "xz,std" --test integration`
- CLI を含むリポジトリ標準の検証:
  - `cargo fmt --all`
  - `cargo test --all-features`
  - `cargo test -p archive-cli`
  - `cargo clippy --all-features --all-targets -- -D warnings`

## System tool interop の扱い

一部の integration test は Arch Linux 環境の外部ツールを使用する。
ツールが存在しない環境では、該当テストをスキップする。
`ARCHIVE_REQUIRE_EXTERNAL_TOOLS=1` を設定すると、共通ヘルパー経由で検出した
ツール不在を失敗として扱う（interop coverage を必須にする場合に使う）。

現時点で `Containerfile` に用意している外部ツールは次の通りである。

- `python`
- `brotli`
- `gzip`
- `zip` / `unzip`
- `7zip`
- `libarchive` (`bsdtar`)
- `zstd`
- `bzip2`
- `lzip`
- `xz`
- `ncompress`
- `lz4`
- `lzop`
- `lrzip`
- `cpio`
- `squashfs-tools` (`mksquashfs` / `unsquashfs`)
- `git`
- `unarchiver` (`unar`)
- `lhasa`
- `cabextract`
- custom package:
  - `arc` / `nomarch` (PKGBUILD によるソースビルド、oracle 専用)
  - `rzip`
  - `zpaq`

ただし、ツールが導入されていても相互運用テストを持たないフォーマットが存在する。
これは現在の実装スコープ（current implementation scope）と外部ツールのフォーマット仕様差分に起因する。

- `zpaq`
  - JIDAC journaling archive は対応済み。system `zpaq` との相互運用は fuzz oracle (`ArchiveSpec::Zpaq`) と upstream 生成 fixture (`tests/fixtures/zpaq/`) で固定しており、`tests/integration/zpaq.rs` は crate 内 roundtrip / metadata 検証が対象
- `7z`
  - system `7z` が生成する一部 archive metadata/property variant は未対応
  - 現在は `crate -> system 7z extract` 側を固定している
- `rzip`
  - `system rzip -> crate decode` と `crate -> system rzip decode` を simple payload で固定している
  - large payload や multi-chunk 境界における `system rzip` との同一性は保証の対象外としている

## Test inventory

以下の表は、各 integration test file がどの検証項目をどの test case で固定しているかを対応付けたものである。

### `ar.rs`

| Coverage | Test cases |
| --- | --- |
| GNU/BSD roundtrip baseline | `test_ar_roundtrip_gnu`<br>`test_ar_empty_archive_roundtrip`<br>`test_ar_roundtrip_multiple_long_names_bsd` |
| system archive decode / system listing | `test_ar_decode_system_archive`<br>`test_ar_decode_gnu_thin_fixture`<br>`test_ar_gnu_system_compat`<br>`test_ar_empty_archive_system_list_compat`<br>`test_ar_bsd_system_compat`<br>`test_ar_thin_system_list_compat`<br>`test_ar_gnu_system_extract_content_compat` |
| reader / metadata bridge | `test_ar_decode_reader_roundtrip_integration`<br>`test_ar_add_entry_preserves_metadata` |
| malformed input | `test_ar_decode_rejects_invalid_header_trailer` |

### `deb.rs`

| Coverage | Test cases |
| --- | --- |
| minimal package / member layout | `test_deb_decode_minimal` |
| member compression variants | `test_deb_decode_compressed_members` |
| invalid layout rejection | `test_deb_decode_rejects_invalid_layout` |
| system `ar`+`tar`+`gzip` interop | `test_deb_decode_system_built_package` |
| `bsdtar` member extraction interop | `test_deb_crate_built_extracted_by_bsdtar` |
| encoder roundtrip / `bsdtar` interop | `test_deb_encoder_roundtrip`<br>`test_deb_encoder_bsdtar_interop` |

### `rpm.rs`

| Coverage | Test cases |
| --- | --- |
| uncompressed cpio payload decode | `test_rpm_decode_uncompressed_payload` |
| gzip payload decode | `test_rpm_decode_gzip_payload` |
| xz / zstd payload decode | `test_rpm_decode_xz_and_zstd_payloads` |
| v6 stripped payload (07070X) | `test_rpm_decode_stripped_payload` |
| system cpio+gzip payload interop | `test_rpm_decode_system_compressed_payload` |
| `bsdtar` payload extraction interop | `test_rpm_crate_built_read_by_bsdtar` |
| v6 encoder roundtrip + system oracle | `test_rpm_v6_encoder_roundtrip_and_system_oracle` |
| encoder roundtrip variants | `test_rpm_encode_decode_roundtrip`<br>`test_rpm_encode_uncompressed_roundtrip` |
| encoder `bsdtar` interop | `test_rpm_encode_read_by_bsdtar`<br>`test_rpm_stripped_encoder_roundtrip_and_bsdtar` |

### `squashfs.rs`

| Coverage | Test cases |
| --- | --- |
| `mksquashfs` 生成 image (gzip/zstd/xz/lz4/lzo) の decode | `test_squashfs_decode_mksquashfs_image` |
| xattr / directory index decode | `test_squashfs_decode_xattrs_and_dir_index` |
| 本 writer 出力 (gzip/xz/lz4/lzo/zstd) の `unsquashfs` 展開 | `test_squashfs_encoder_unsquashfs_extract` |
| encoder → decoder roundtrip | `test_squashfs_encoder_roundtrip` |
| symlink / fragment / ID table writer | `test_squashfs_encoder_symlink_fragments_ids` |
| extended writer (`unsquashfs` oracle) | `test_squashfs_encoder_extended_unsquashfs` |

### `mscab.rs`

| Coverage | Test cases |
| --- | --- |
| MSZIP 圧縮 cabinet の decode | `test_mscab_decode_mszip_cabinet` |
| crate 生成 cab の `bsdtar` 展開 interop | `test_mscab_bsdtar_interop` |
| encoder roundtrip / `bsdtar` interop | `test_mscab_encoder_roundtrip`<br>`test_mscab_encoder_bsdtar_interop` |
| LZX フォルダ fixture | `test_mscab_lzx_fixture`<br>`test_mscab_lzx_large_fixture` |
| Quantum 合成・fixture・`cabextract` interop | `test_mscab_quantum_synthesized_cab`<br>`test_mscab_quantum_cabextract_interop`<br>`test_mscab_quantum_fixture` |

### `zim.rs`

| Coverage | Test cases |
| --- | --- |
| stored cluster decode | `test_zim_decode_stored_cluster` |
| xz cluster decode | `test_zim_decode_xz_cluster` |
| zstd cluster decode | `test_zim_decode_zstd_cluster` |
| encoder roundtrip / stored-xz / v6 redirect | `test_zim_encoder_roundtrip`<br>`test_zim_encoder_xz_stored`<br>`test_zim_encoder_v6_extended_with_redirect` |
| truncated header reject | `test_zim_rejects_truncated_header` |

### `mtree.rs`

| Coverage | Test cases |
| --- | --- |
| basic manifest decode (/set・相対 dir 遷移) | `test_mtree_decode_basic` |
| encoder roundtrip / `bsdtar` read interop | `test_mtree_encode_roundtrip`<br>`test_mtree_bsdtar_read_interop` |
| `bsdtar --format=mtree` 生成マニフェストの decode interop | `test_mtree_bsdtar_interop` |

### `warc.rs`

| Coverage | Test cases |
| --- | --- |
| 複数 record ストリーム decode (warcinfo/response/revisit) | `test_warc_decode_records` |
| gzip 伸張経路経由の `.warc.gz` decode | `test_warc_gzip_members` |
| record encoder roundtrip | `test_warc_encode_roundtrip`<br>`test_warc_gzip_write_roundtrip` |
| `WARC-Profile` 検証 (revisit 必須・他型禁止・未知 URI は pass-through) | `test_warc_rejects_revisit_missing_profile`<br>`test_warc_rejects_profile_on_non_revisit`<br>`test_warc_accepts_revisit_with_known_profile` |
| `WARC-Identified-Payload-Type` / `WARC-Payload-Digest` は payload 未定義の型 (warcinfo/metadata) で禁止 | `test_warc_identified_payload_type_needs_payload`<br>`test_warc_payload_digest_needs_payload` |
| warcinfo `Content-Type: application/warc-fields` 必須 (Clause 8) + encoder 側 enforcement | `test_warc_rejects_warcinfo_wrong_content_type`<br>`test_warc_encoder_warcinfo_content_type` |

### `brotli.rs`

| Coverage | Test cases |
| --- | --- |
| system `brotli` decode interop | `test_brotli_decode_system_q0_uncompressed`<br>`test_brotli_decode_system_q3_compressed_run`<br>`test_brotli_decode_system_q5_repeated_pattern`<br>`test_brotli_decode_system_binary_payload`<br>`test_brotli_decode_system_quality_levels`<br>`test_brotli_decode_system_signed_context_mode_regression`<br>`test_brotli_decode_system_utf8_context_table_regression` |
| crate encode / writer path | `test_brotli_encode_roundtrip`<br>`test_brotli_encode_system_decode`<br>`test_brotli_encode_empty_system_decode`<br>`test_brotli_encode_writer_roundtrip`<br>`test_brotli_encode_multi_metablock_roundtrip`<br>`test_brotli_encode_lz77_system_decode`<br>`test_brotli_encode_metablock_boundary_context`<br>`test_brotli_encode_repeated_pattern_system_decode`<br>`test_brotli_encode_low_cardinality_system_decode` |
| malformed input | `test_brotli_decode_rejects_truncated_stream` |

### `bzip2.rs`

| Coverage | Test cases |
| --- | --- |
| roundtrip / multi-block | `test_bzip2_roundtrip_large`<br>`test_bzip2_roundtrip_multi_block` |
| system interop | `test_bzip2_decode_system_compressed`<br>`test_bzip2_encode_decoded_by_system`<br>`test_bzip2_large_interop_with_system`<br>`test_bzip2_decode_system_binary_payload`<br>`test_bzip2_empty_stream_system_decode` |
| writer / reader path | `test_bzip2_encode_writer_decode_reader_roundtrip` |
| validation / corruption | `test_bzip2_decode_rejects_invalid_block_size`<br>`test_bzip2_decode_detects_stream_crc_mismatch` |

### `combined.rs`

| Coverage | Test cases |
| --- | --- |
| stacked formats | `test_tar_gz_decode`<br>`test_tar_zst_roundtrip`<br>`test_cpio_gz_roundtrip`<br>`test_cpio_zst_roundtrip`<br>`test_tar_gz_encode_decode_roundtrip` |
| format mismatch detection | `test_format_mismatch_tar_as_cpio`<br>`test_format_mismatch_cpio_as_tar` |

### `cpio.rs`

| Coverage | Test cases |
| --- | --- |
| fixture / basic roundtrip | `test_cpio_decode_single_file`<br>`test_cpio_directories_only_roundtrip`<br>`test_cpio_empty_archive_roundtrip`<br>`test_cpio_bin_decode_fixture_multi`<br>`test_cpio_bin_decode_fixture_mixed`<br>`test_cpio_bin_roundtrip_integration` |
| reader / format variants | `test_cpio_decode_reader_roundtrip_integration`<br>`test_cpio_odc_roundtrip_integration` |
| system binary format interop | `test_cpio_bin_decode_system_archive`<br>`test_cpio_bin_extract_with_system` |
| metadata / special entries | `test_cpio_symlink_hardlink_and_device_roundtrip` |
| checksum / CRC format | `test_cpio_newcrc_roundtrip_and_checksum_detection` |
| system `cpio` interop | `test_cpio_decode_system_newc_archive`<br>`test_cpio_encode_newc_system_extract_compat`<br>`test_cpio_encode_newcrc_system_extract_compat` |

### `deflate.rs`

| Coverage | Test cases |
| --- | --- |
| fixture decode / level behavior | `test_deflate_decode_hello_gz`<br>`test_deflate_decode_repeated_gz`<br>`test_deflate_encode_roundtrip_all_levels`<br>`test_deflate_compression_level_size_ordering` |
| writer / reader path | `test_deflate_encode_writer_decode_reader_roundtrip` |
| `python3` raw zlib interop | `test_deflate_decode_python_raw_deflate_stream`<br>`test_deflate_encode_raw_stream_decoded_by_python`<br>`test_deflate_encode_empty_raw_stream_decoded_by_python` |
| malformed blocks | `test_deflate_decode_rejects_stored_block_len_mismatch`<br>`test_deflate_decode_rejects_invalid_block_type` |

### `gzip.rs`

| Coverage | Test cases |
| --- | --- |
| baseline / level / options | `test_gzip_decode_hello`<br>`test_gzip_decode_repeated`<br>`test_gzip_roundtrip_large`<br>`test_gzip_roundtrip_all_levels_via_reader`<br>`test_gzip_encode_writer_with_options_roundtrip` |
| multi-member behavior | `test_gzip_multi_member_stream_integration`<br>`test_gzip_multi_member_rejects_corrupt_second_member`<br>`test_gzip_multi_member_system_decode` |
| system `gzip` interop | `test_gzip_encode_decoded_by_system_gzip`<br>`test_gzip_decode_system_encoded_stream`<br>`test_gzip_multi_member_system_decode` |
| header / trailer validation | `test_gzip_decode_rejects_corrupt_header_crc`<br>`test_gzip_decode_detects_trailer_crc_mismatch`<br>`test_gzip_decode_detects_isize_mismatch` |

### `lrzip.rs`

| Coverage | Test cases |
| --- | --- |
| roundtrip baseline | `test_lrzip_roundtrip_hello`<br>`test_lrzip_roundtrip_large` |
| truncation / corruption | `test_lrzip_decode_rejects_truncated_stream`<br>`test_lrzip_decode_detects_output_size_mismatch` |
| system `lrzip` interop | `test_lrzip_decode_system_lzma_archive`<br>`test_lrzip_decode_system_lzma_repeated_archive`<br>`test_lrzip_encode_system_decode_compat`<br>`test_lrzip_encode_bzip2_system_decode_compat`<br>`test_lrzip_encode_gzip_system_decode_compat`<br>`test_lrzip_encode_none_system_decode_compat`<br>`test_lrzip_encode_lzo_system_decode_compat`<br>`test_lrzip_encode_zpaq_system_decode_compat`<br>`test_lrzip_encode_md5_system_decode_compat` |

### `lz4.rs`

| Coverage | Test cases |
| --- | --- |
| roundtrip / block sizing | `test_lz4_roundtrip_hello`<br>`test_lz4_roundtrip_large`<br>`test_lz4_roundtrip_block_sizes` |
| system interop | `test_lz4_decode_system_fixture`<br>`test_lz4_encode_decoded_by_system` |
| writer / reader path | `test_lz4_encode_writer_decode_reader_roundtrip` |
| dictionaries / skippable frame | `test_lz4_dictionary_roundtrip_with_id`<br>`test_lz4_decode_skippable_frame_before_payload` |
| malformed dictionary usage | `test_lz4_decode_rejects_missing_and_mismatched_dictionary` |

### `lzip.rs`

| Coverage | Test cases |
| --- | --- |
| roundtrip matrix | `test_lzip_roundtrip_large`<br>`test_lzip_roundtrip_empty`<br>`test_lzip_roundtrip_tiny`<br>`test_lzip_roundtrip_variable_dict_sizes`<br>`test_lzip_roundtrip_high_entropy` |
| system interop / regressions | `test_lzip_decode_system_compressed`<br>`test_lzip_decode_system_compressed_fuzz_regression`<br>`test_lzip_encode_decoded_by_system`<br>`test_lzip_multi_member_system_decode` |
| multi-member | `test_lzip_multi_member`<br>`test_lzip_multi_member_system_decode` |

### `lzma_alone.rs`

| Coverage | Test cases |
| --- | --- |
| roundtrip baseline | `test_lzma_alone_roundtrip_large`<br>`test_lzma_alone_roundtrip_empty`<br>`test_lzma_alone_roundtrip_tiny`<br>`test_lzma_alone_roundtrip_high_entropy` |
| system `xz --format=lzma` interop | `test_lzma_alone_decode_system_compressed`<br>`test_lzma_alone_encode_decoded_by_system` |
| fuzz regression fixture | `test_fuzz_regression_lzma_original_decompress_1` |

### `lzo.rs`

| Coverage | Test cases |
| --- | --- |
| roundtrip baseline | `test_lzo_roundtrip_hello`<br>`test_lzo_roundtrip_large` |
| system interop | `test_lzo_decode_system_fixture`<br>`test_lzo_encode_decoded_by_system`<br>`test_lzo_decode_system_binary_payload` |
| writer / reader path | `test_lzo_encode_writer_decode_reader_roundtrip` |
| corruption / checksums | `test_lzo_decode_rejects_corrupt_header_checksum`<br>`test_lzo_decode_detects_uncompressed_adler_mismatch` |

### `lzw.rs`

| Coverage | Test cases |
| --- | --- |
| roundtrip / parameter sweep | `test_lzw_roundtrip_hello`<br>`test_lzw_roundtrip_large`<br>`test_lzw_roundtrip_all_max_bits` |
| system fixture / system interop | `test_lzw_decode_system_compress_fixture`<br>`test_lzw_encode_decoded_by_system_uncompress`<br>`test_lzw_encode_bits9_decoded_by_system_uncompress`<br>`test_lzw_decode_system_compressed_stream` |
| writer / reader path | `test_lzw_encode_writer_decode_reader_roundtrip` |
| malformed header | `test_lzw_decode_rejects_reserved_header_flags` |

### `rzip.rs`

| Coverage | Test cases |
| --- | --- |
| crate roundtrip / level API | `test_rzip_roundtrip_level_matrix`<br>`test_rzip_roundtrip_binary_payload` |
| system `rzip` interop | `test_rzip_decode_system_archive`<br>`test_rzip_encode_system_decode_compat`<br>`test_rzip_encode_system_decode_binary_payload`<br>`test_rzip_encode_system_decode_multichunk_payload`<br>`test_rzip_encode_system_decode_level_edges`<br>`test_rzip_encode_system_decode_backend_matrix` |

### `sevenz.rs`

| Coverage | Test cases |
| --- | --- |
| system `7z` extract interop | `test_sevenz_encode_system_extract_compat`<br>`test_sevenz_empty_archive_roundtrip_and_system_list`<br>`test_sevenz_multi_file_system_extract_compat`<br>`test_sevenz_two_folder_system_extract_compat`<br>`test_sevenz_two_folder_encrypted_system_extract_compat`<br>`test_sevenz_two_folder_encoded_header_system_extract_compat`<br>`test_sevenz_two_folder_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_ppmd_method_system_extract_compat`<br>`test_sevenz_ppmd_encoded_header_system_extract_compat`<br>`test_sevenz_ppmd_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_two_folder_ppmd_system_extract_compat`<br>`test_sevenz_two_folder_ppmd_encoded_header_system_extract_compat`<br>`test_sevenz_two_folder_ppmd_encrypted_system_extract_compat`<br>`test_sevenz_two_folder_ppmd_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_x86_bcj_filter_system_extract_compat`<br>`test_sevenz_x86_bcj_encoded_header_system_extract_compat`<br>`test_sevenz_x86_bcj_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_two_folder_x86_bcj_filter_system_extract_compat`<br>`test_sevenz_two_folder_x86_bcj_encoded_header_system_extract_compat`<br>`test_sevenz_two_folder_x86_bcj_encrypted_system_extract_compat`<br>`test_sevenz_two_folder_x86_bcj_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_delta_filter_system_extract_compat`<br>`test_sevenz_delta_encoded_header_system_extract_compat`<br>`test_sevenz_delta_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_two_folder_delta_filter_system_extract_compat`<br>`test_sevenz_two_folder_delta_encoded_header_system_extract_compat`<br>`test_sevenz_two_folder_delta_encrypted_system_extract_compat`<br>`test_sevenz_two_folder_delta_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_encrypted_archive_system_extract_compat`<br>`test_sevenz_encoded_header_roundtrip_and_system_extract`<br>`test_sevenz_encrypted_encoded_header_roundtrip_and_system_extract` |
| method coverage | `test_sevenz_copy_method_roundtrip_integration`<br>`test_sevenz_ppmd_method_roundtrip_integration`<br>`test_sevenz_ppmd_method_system_extract_compat`<br>`test_sevenz_ppmd_encoded_header_system_extract_compat`<br>`test_sevenz_ppmd_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_two_folder_ppmd_system_extract_compat`<br>`test_sevenz_two_folder_ppmd_encoded_header_system_extract_compat`<br>`test_sevenz_two_folder_ppmd_encrypted_system_extract_compat`<br>`test_sevenz_two_folder_ppmd_encrypted_encoded_header_system_extract_compat` |
| `add_entry` / filters | `test_sevenz_add_entry_with_filters_roundtrip`<br>`test_sevenz_delta_filter_roundtrip_integration`<br>`test_sevenz_x86_bcj_filter_system_extract_compat`<br>`test_sevenz_x86_bcj_encoded_header_system_extract_compat`<br>`test_sevenz_x86_bcj_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_two_folder_x86_bcj_filter_system_extract_compat`<br>`test_sevenz_two_folder_x86_bcj_encoded_header_system_extract_compat`<br>`test_sevenz_two_folder_x86_bcj_encrypted_system_extract_compat`<br>`test_sevenz_two_folder_x86_bcj_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_delta_filter_system_extract_compat`<br>`test_sevenz_delta_encoded_header_system_extract_compat`<br>`test_sevenz_delta_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_two_folder_delta_filter_system_extract_compat`<br>`test_sevenz_two_folder_delta_encoded_header_system_extract_compat`<br>`test_sevenz_two_folder_delta_encrypted_system_extract_compat`<br>`test_sevenz_two_folder_delta_encrypted_encoded_header_system_extract_compat` |
| password APIs / failure path | `test_sevenz_password_bytes_roundtrip_and_failures`<br>`test_sevenz_encrypted_archive_system_extract_compat`<br>`test_sevenz_ppmd_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_x86_bcj_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_delta_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_two_folder_ppmd_encrypted_system_extract_compat`<br>`test_sevenz_two_folder_ppmd_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_two_folder_x86_bcj_encrypted_system_extract_compat`<br>`test_sevenz_two_folder_x86_bcj_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_two_folder_delta_encrypted_system_extract_compat`<br>`test_sevenz_two_folder_delta_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_encrypted_encoded_header_roundtrip_and_system_extract` |
| method / folder system interop | `test_sevenz_deflate_method_system_decode_compat`<br>`test_sevenz_deflate64_method_system_decode_compat`<br>`test_sevenz_bzip2_method_system_decode_compat`<br>`test_sevenz_deflate_method_system_extract_compat`<br>`test_sevenz_deflate64_method_system_extract_compat`<br>`test_sevenz_bzip2_method_system_extract_compat`<br>`test_sevenz_large_copy_method_system_decode_compat`<br>`test_sevenz_large_copy_method_system_extract_compat`<br>`test_sevenz_decode_system_created_archive`<br>`test_sevenz_multi_folder_system_extract_compat` |

### `snappy.rs`

| Coverage | Test cases |
| --- | --- |
| framed / raw roundtrip | `test_snappy_roundtrip`<br>`test_snappy_raw_roundtrip`<br>`test_snappy_framed_empty_stream_roundtrip`<br>`test_snappy_raw_large_roundtrip` |
| chunk layout | `test_snappy_chunk_boundary_roundtrip`<br>`test_snappy_emits_uncompressed_chunk_for_small_literal_payload`<br>`test_snappy_decode_accepts_skippable_chunk`<br>`test_snappy_multi_chunk_roundtrip_with_trailing_chunk` |
| validation | `test_snappy_decode_rejects_invalid_stream_identifier`<br>`test_snappy_decode_detects_checksum_mismatch`<br>`test_snappy_raw_decode_rejects_trailing_bytes` |

### `tar.rs`

| Coverage | Test cases |
| --- | --- |
| fixture decode | `test_tar_decode_single_file`<br>`test_tar_empty_archive_roundtrip`<br>`test_tar_decode_multi_file`<br>`test_tar_decode_ustar_fixture`<br>`test_tar_decode_gnu_longname_fixture`<br>`test_tar_decode_pax_fixture` |
| GNU/PAX encode roundtrip | `test_tar_gnu_longname_roundtrip`<br>`test_tar_pax_roundtrip`<br>`test_tar_pax_longname_roundtrip` |
| system `tar` interop | `test_tar_gnu_system_compat`<br>`test_tar_empty_archive_system_list_compat`<br>`test_tar_gnu_longname_system_extract_compat`<br>`test_tar_pax_system_compat`<br>`test_tar_pax_system_extract_compat` |
| reader / directories / metadata | `test_tar_directories_only_roundtrip`<br>`test_tar_decode_reader_roundtrip_integration`<br>`test_tar_link_entries_roundtrip`<br>`test_tar_pax_sparse_roundtrip_integration` |
| GNU sparse layouts / system oracle | `test_tar_gnu_sparse_roundtrip`<br>`test_tar_gnu_sparse_extended_map`<br>`test_tar_gnu_sparse_long_name`<br>`test_tar_gnu_sparse_oracle` |
| malformed input | `test_tar_decode_rejects_truncated_archive` |

### `xz.rs`

| Coverage | Test cases |
| --- | --- |
| baseline roundtrip | `test_xz_roundtrip_hello`<br>`test_xz_roundtrip_empty`<br>`test_xz_roundtrip_large` |
| system interop / regressions | `test_xz_interop_with_system_xz`<br>`test_xz_decode_system_encoded`<br>`test_xz_decode_system_compressed_fuzz_regression`<br>`test_xz_decode_system_compressed_fuzz_regression_multichunk_state`<br>`test_xz_decode_system_compressed_dict_boundary_fuzz_regression`<br>`test_xz_encode_system_decode_fuzz_regression`<br>`test_xz_multi_stream_system_decode` |
| BCJ / Delta filter chains | `test_xz_decode_system_encoded_x86_filter_chain`<br>`test_xz_encode_x86_filter_chain_system_decode`<br>`test_xz_decode_system_encoded_delta_filter_chain`<br>`test_xz_encode_delta_filter_chain_system_decode`<br>`test_xz_decode_system_encoded_powerpc_filter_chain`<br>`test_xz_encode_powerpc_filter_chain_system_decode`<br>`test_xz_decode_system_encoded_ia64_filter_chain`<br>`test_xz_encode_ia64_filter_chain_system_decode`<br>`test_xz_decode_system_encoded_sparc_filter_chain`<br>`test_xz_encode_sparc_filter_chain_system_decode`<br>`test_xz_decode_system_encoded_arm_filter_chain`<br>`test_xz_encode_arm_filter_chain_system_decode`<br>`test_xz_decode_system_encoded_arm64_filter_chain`<br>`test_xz_encode_arm64_filter_chain_system_decode`<br>`test_xz_decode_system_encoded_riscv_filter_chain`<br>`test_xz_encode_riscv_filter_chain_system_decode`<br>`test_xz_decode_system_encoded_riscv_auipc_pair`<br>`test_xz_encode_riscv_filter_chain_system_decode_fuzz_regression`<br>`test_xz_decode_system_encoded_armthumb_filter_chain`<br>`test_xz_encode_armthumb_filter_chain_system_decode` |
| reader path | `test_xz_encode_reader_roundtrip`<br>`test_xz_decode_reader_roundtrip` |
| validation / checks | `test_xz_decode_rejects_invalid_magic`<br>`test_xz_decode_rejects_corrupt_stream_header_crc`<br>`test_xz_decode_rejects_truncated_stream`<br>`test_xz_decode_system_encoded_crc64_check`<br>`test_xz_decode_system_encoded_sha256_check`<br>`test_xz_decode_rejects_corrupt_block_check_crc32`<br>`test_xz_decode_rejects_corrupt_footer_crc` |

### `zip.rs`

| Coverage | Test cases |
| --- | --- |
| system archive decode | `test_zip_decode_system_deflate_archive`<br>`test_zip_decode_system_store_archive` |
| system `unzip` extract/list interop | `test_zip_encode_system_unzip_compat`<br>`test_zip_encode_data_descriptor_system_unzip_compat` |
| ZIP64 system interop | `test_zip_force_zip64_roundtrip`<br>`test_zip_force_zip64_system_unzip_compat` |
| WinZip AES roundtrip / password failure | `test_zip_aes_roundtrip_and_password_failure` |
| reader / finish-to path | `test_zip_decode_reader_finish_to_roundtrip` |
| checksum / size / descriptor validation | `test_zip_decode_detects_checksum_mismatch`<br>`test_zip_decode_detects_size_mismatch`<br>`test_zip_decode_detects_data_descriptor_mismatch`<br>`test_zip_decode_detects_local_and_central_name_mismatch`<br>`test_zip_decode_detects_invalid_local_file_header_signature` |
| metadata / entry bridge | `test_zip_utf8_metadata_roundtrip_via_reader`<br>`test_zip_cp437_metadata_roundtrip_without_utf8_flag`<br>`test_zip_add_entry_roundtrip_preserves_metadata` |
| method 10 (DCL Implode) literal-only encode | `test_zip_method10_encode_roundtrip` |
| multi-disk emit (`finish_parts`) | `test_zip_finish_parts_system_unzip_compat` |
| streaming writer / data descriptor | `test_zip_stream_writer_system_unzip_compat` |
| traditional encryption | `test_zip_decode_system_traditional_encrypted_archive`<br>`test_zip_encode_traditional_system_unzip_compat`<br>`test_zip_encode_traditional_data_descriptor_system_unzip_compat` |
| AES data descriptor / legacy methods | `test_zip_encode_aes_data_descriptor_roundtrip`<br>`test_zip_legacy_methods_roundtrip`<br>`test_zip_legacy_methods_unar_compat`<br>`test_zip_legacy_methods_hwzip_compat` |
| method 16 (CMPSC) encode | `test_zip_method16_encode_roundtrip`<br>`test_zip_method16_encode_header_fields` |

### `zlib.rs`

| Coverage | Test cases |
| --- | --- |
| baseline roundtrip | `test_zlib_roundtrip_large_integration`<br>`test_zlib_empty_stream_roundtrip` |
| Python `zlib` interop | `test_zlib_decode_python_zlib_stream`<br>`test_zlib_encode_stream_decoded_by_python` |
| header / checksum validation | `test_zlib_decode_rejects_preset_dictionary_flag`<br>`test_zlib_decode_detects_adler32_mismatch` |

### `zpaq.rs`

| Coverage | Test cases |
| --- | --- |
| simplified archive roundtrip | `test_zpaq_archive_multi_entry_roundtrip` |
| empty archive | `test_zpaq_archive_empty_roundtrip` |
| empty filename / mixed empty payload | `test_zpaq_archive_accepts_empty_filename`<br>`test_zpaq_archive_roundtrip_mixed_empty_payload_entries` |
| metadata validation | `test_zpaq_archive_rejects_nul_metadata` |
| append workflow | `test_zpaq_archive_append_to_existing_roundtrip` |
| crate-local journaling latest view / delete visibility | `test_zpaq_journal_latest_view_roundtrip`<br>`test_zpaq_journal_delete_visibility` |
| materialized archive editor | `test_zpaq_archive_editor_rewrites_imported_archive`<br>`test_zpaq_archive_editor_materializes_journal_latest_view` |

### `zstd.rs`

| Coverage | Test cases |
| --- | --- |
| baseline decode / roundtrip | `test_zstd_decode_hello`<br>`test_zstd_decode_repeated`<br>`test_zstd_decode_large`<br>`test_zstd_encode_roundtrip`<br>`test_zstd_encode_writer_decode_reader_roundtrip` |
| system interop / regressions | `test_zstd_encode_decoded_by_system`<br>`test_zstd_encode_large_raw_system_compat`<br>`test_zstd_encode_large_text_system_compat`<br>`test_zstd_decode_system_compressed_fuzz_regression` |
| frame layout / large literals | `test_zstd_multi_frame`<br>`test_zstd_encode_large_literals_roundtrip`<br>`test_zstd_encode_with_options_checksum_off_roundtrip`<br>`test_zstd_decode_skippable_frame_before_payload`<br>`test_zstd_decode_reader_with_skippable_frame_before_payload` |
| dictionary coverage | `test_zstd_decode_with_dict_system`<br>`test_zstd_encode_with_dict_system_compat`<br>`test_zstd_train_dictionary_roundtrip`<br>`test_zstd_content_only_dictionary_roundtrip`<br>`test_zstd_decode_rejects_dictionary_mismatch_and_missing_dictionary` |

### `arc.rs`

| Coverage | Test cases |
| --- | --- |
| arc encode decode roundtrip | `test_arc_encode_decode_roundtrip` |
| arc multi entry roundtrip | `test_arc_multi_entry_roundtrip` |
| arc rejects truncated | `test_arc_rejects_truncated` |
| arc rejects compressed method | `test_arc_rejects_compressed_method` |
| arc skips info control items | `test_arc_skips_info_control_items` |
| arc method3 encode decode roundtrip | `test_arc_method3_encode_decode_roundtrip` |
| arc method3 member | `test_arc_method3_member` |
| arc method3 rejects bad crc | `test_arc_method3_rejects_bad_crc` |
| arc method3 rejects malformed rle | `test_arc_method3_rejects_malformed_rle` |
| arc method1 encode decode roundtrip | `test_arc_method1_encode_decode_roundtrip` |
| arc method1 header layout | `test_arc_method1_header_layout` |
| arc rejects unsupported encode method | `test_arc_rejects_unsupported_encode_method` |
| arc method1 member | `test_arc_method1_member` |
| arc method1 rejects bad crc | `test_arc_method1_rejects_bad_crc` |
| arc rejects bad name | `test_arc_rejects_bad_name` |
| arc decode crunched fixture | `test_arc_decode_crunched_fixture` |
| arc decode squashed fixture | `test_arc_decode_squashed_fixture` |
| arc compressed encode decode roundtrip | `test_arc_compressed_encode_decode_roundtrip` |
| arc method5 6 7 edge roundtrip | `test_arc_method5_6_7_edge_roundtrip` |
| arc method0a encode roundtrip | `test_arc_method0a_encode_roundtrip` |
| arc encode extracted by oracle (system arc/nomarch/unar oracle) | `test_arc_encode_extracted_by_oracle` |
| arc method5 6 7 decode | `test_arc_method5_6_7_decode` |
| arc method0a decode | `test_arc_method0a_decode` |
| arc method0b decode | `test_arc_method0b_decode` |
| arc packed oracle crosscheck (system arc/nomarch/unar oracle) | `test_arc_packed_oracle_crosscheck` |
| arc method0b encode roundtrip | `test_arc_method0b_encode_roundtrip` |

### `arj.rs`

| Coverage | Test cases |
| --- | --- |
| arj encode decode roundtrip | `test_arj_encode_decode_roundtrip` |
| arj multi entry roundtrip | `test_arj_multi_entry_roundtrip` |
| arj rejects truncated | `test_arj_rejects_truncated` |
| arj rejects compressed method | `test_arj_rejects_compressed_method` |
| arj 7z list interop (system 7z oracle) | `test_arj_7z_list_interop` |
| arj compressed methods | `test_arj_compressed_methods` |
| arj garbled | `test_arj_garbled` |
| arj multi volume | `test_arj_multi_volume` |
| arj multi volume three way | `test_arj_multi_volume_three_way` |
| arj oracle extract | `test_arj_oracle_extract` |
| arj method4 encode roundtrip | `test_arj_method4_encode_roundtrip` |
| arj method4 incompressible stored | `test_arj_method4_incompressible_stored` |
| arj finish parts roundtrip | `test_arj_finish_parts_roundtrip` |
| arj finish parts mixed entries | `test_arj_finish_parts_mixed_entries` |
| arj finish parts method4 | `test_arj_finish_parts_method4` |
| arj finish parts single volume | `test_arj_finish_parts_single_volume` |
| arj finish parts rejects tiny volume | `test_arj_finish_parts_rejects_tiny_volume` |
| arj st1 encode roundtrip | `test_arj_st1_encode_roundtrip` |
| arj st1 incompressible stored | `test_arj_st1_incompressible_stored` |
| arj encoder rejects unsupported method | `test_arj_encoder_rejects_unsupported_method` |
| arj encoder filename length boundary | `test_arj_encoder_filename_length_boundary` |
| arj garbled write roundtrip | `test_arj_garbled_write_roundtrip` |
| arj volume paths discovery roundtrip | `test_arj_volume_paths_discovery_roundtrip` |

### `ascii85.rs`

| Coverage | Test cases |
| --- | --- |
| ascii85 adobe roundtrip | `test_ascii85_adobe_roundtrip` |
| ascii85 python a85decode compat (system python3 oracle) | `test_ascii85_python_a85decode_compat` |
| ascii85 python a85encode decode (system python3 oracle) | `test_ascii85_python_a85encode_decode` |
| ascii85 rfc1924 python b85 compat (system python3 oracle) | `test_ascii85_rfc1924_python_b85_compat` |

### `binhex.rs`

| Coverage | Test cases |
| --- | --- |
| binhex roundtrip | `test_binhex_roundtrip` |
| binhex crc matches python crc hqx (system python3 oracle) | `test_binhex_crc_matches_python_crc_hqx` |
| binhex decodes reference encoder (system python3 oracle) | `test_binhex_decodes_reference_encoder` |

### `cmpsc.rs`

| Coverage | Test cases |
| --- | --- |
| dictionary expansion / chains / sibling descriptors | `cmpsc_expand_alphabet_and_chains`<br>`cmpsc_compress_expand_roundtrip` |
| method-16 container roundtrip / explicit vector | `cmpsc_method16_roundtrip`<br>`cmpsc_method16_explicit_vector` |
| malformed dictionary / symbol / header rejection | `cmpsc_rejects_malformed` |

### `cramfs.rs`

| Coverage | Test cases |
| --- | --- |
| cramfs decode mkfs image | `test_cramfs_decode_mkfs_image` |
| cramfs fsid crc mismatch is informational | `test_cramfs_fsid_crc_mismatch_is_informational` |
| cramfs fsck extract matches decode (system fsck.cramfs oracle) | `test_cramfs_fsck_extract_matches_decode` |
| cramfs encode fsck extract (system fsck.cramfs oracle) | `test_cramfs_encode_fsck_extract` |
| cramfs mkfs image reencode roundtrip | `test_cramfs_mkfs_image_reencode_roundtrip` |

### `crx3.rs`

| Coverage | Test cases |
| --- | --- |
| crx3 python oracle | `test_crx3_python_oracle` |
| crx3 rejects non zip tail | `test_crx3_rejects_non_zip_tail` |

### `erofs.rs`

| Coverage | Test cases |
| --- | --- |
| erofs mkfs image layout | `test_erofs_mkfs_image_layout` |
| erofs mkfs image contents | `test_erofs_mkfs_image_contents` |
| erofs mkfs image superblock | `test_erofs_mkfs_image_superblock` |
| erofs codec trait | `test_erofs_codec_trait` |
| erofs rejects truncation | `test_erofs_rejects_truncation` |
| erofs rejects bad superblock checksum | `test_erofs_rejects_bad_superblock_checksum` |
| erofs fsck extract matches decode (system fsck.erofs oracle) | `test_erofs_fsck_extract_matches_decode` |
| erofs compressed lz4hc compact | `test_erofs_compressed_lz4hc_compact` |
| erofs compressed lz4 bigpcluster | `test_erofs_compressed_lz4_bigpcluster` |
| erofs compressed lz4 full index | `test_erofs_compressed_lz4_full_index` |
| erofs compressed lz4 extents | `test_erofs_compressed_lz4_extents` |
| erofs compressed microlzma | `test_erofs_compressed_microlzma` |
| erofs compressed multi algorithm | `test_erofs_compressed_multi_algorithm` |
| erofs ztailpacking | `test_erofs_ztailpacking` |
| erofs fragments | `test_erofs_fragments` |
| erofs all fragments | `test_erofs_all_fragments` |
| erofs ztailpacking fragments | `test_erofs_ztailpacking_fragments` |
| erofs encode decode roundtrip | `test_erofs_encode_decode_roundtrip` |
| erofs mkfs image reencode roundtrip | `test_erofs_mkfs_image_reencode_roundtrip` |
| erofs encode fsck extract (system fsck.erofs oracle) | `test_erofs_encode_fsck_extract` |

### `iso9660.rs`

| Coverage | Test cases |
| --- | --- |
| iso9660 plain image | `test_iso9660_plain_image` |
| iso9660 rockridge image | `test_iso9660_rockridge_image` |
| iso9660 joliet image | `test_iso9660_joliet_image` |
| iso9660 path table | `test_iso9660_path_table` |
| iso9660 pvd metadata | `test_iso9660_pvd_metadata` |
| iso9660 codec trait | `test_iso9660_codec_trait` |
| iso9660 rejects truncated | `test_iso9660_rejects_truncated` |
| iso9660 rejects corrupt | `test_iso9660_rejects_corrupt` |
| iso9660 eltorito image | `test_iso9660_eltorito_image` |
| iso9660 encoder roundtrip | `test_iso9660_encoder_roundtrip` |
| iso9660 encoder rockridge | `test_iso9660_encoder_rockridge` |
| iso9660 encoder trait | `test_iso9660_encoder_trait` |
| iso9660 encoder bsdtar oracle (system bsdtar oracle) | `test_iso9660_encoder_bsdtar_oracle` |

### `lha.rs`

| Coverage | Test cases |
| --- | --- |
| lha encode decode roundtrip | `test_lha_encode_decode_roundtrip` |
| lha multi entry roundtrip | `test_lha_multi_entry_roundtrip` |
| lha rejects truncated | `test_lha_rejects_truncated` |
| lha rejects compressed method | `test_lha_rejects_compressed_method` |
| lha 7z list interop (system 7z oracle) | `test_lha_7z_list_interop` |
| lha bsdtar list interop (system bsdtar oracle) | `test_lha_bsdtar_list_interop` |
| lha level1 roundtrip | `test_lha_level1_roundtrip` |
| lha level2 roundtrip | `test_lha_level2_roundtrip` |
| lha level1 7z interop (system 7z oracle) | `test_lha_level1_7z_interop` |
| lha level1 bsdtar interop (system bsdtar oracle) | `test_lha_level1_bsdtar_interop` |
| lha level2 7z interop (system 7z oracle) | `test_lha_level2_7z_interop` |
| lha level3 roundtrip | `test_lha_level3_roundtrip` |
| lha level3 7z interop (system 7z oracle) | `test_lha_level3_7z_interop` |
| lha level3 bsdtar interop (system bsdtar oracle) | `test_lha_level3_bsdtar_interop` |
| lha level2 bsdtar interop (system bsdtar oracle) | `test_lha_level2_bsdtar_interop` |
| lha compressed method fixtures | `test_lha_compressed_method_fixtures` |
| lha legacymethod rejection | `test_lha_legacymethod_rejection` |
| lha level3 fixtures | `test_lha_level3_fixtures` |
| lha pmarc multi entry fixture | `test_lha_pmarc_multi_entry_fixture` |
| lha level3 dir | `test_lha_level3_dir` |
| lha fixture oracle extract | `test_lha_fixture_oracle_extract` |
| lha compressed method roundtrip | `test_lha_compressed_method_roundtrip` |
| lha compressed method stored fallback | `test_lha_compressed_method_stored_fallback` |
| lha lh5 bsdtar interop (system bsdtar oracle) | `test_lha_lh5_bsdtar_interop` |
| lha lzs lz5 bsdtar interop (system bsdtar oracle) | `test_lha_lzs_lz5_bsdtar_interop` |
| lha pmarc oracle interop | `test_lha_pmarc_oracle_interop` |

### `macbinary.rs`

| Coverage | Test cases |
| --- | --- |
| macbinary roundtrip | `test_macbinary_roundtrip` |
| macbinary python reference decodes ours (system python3 oracle) | `test_macbinary_python_reference_decodes_ours` |
| macbinary decodes python reference output (system python3 oracle) | `test_macbinary_decodes_python_reference_output` |

### `mscfb.rs`

| Coverage | Test cases |
| --- | --- |
| mscfb roundtrip via python reference (system python3 oracle) | `test_mscfb_roundtrip_via_python_reference` |
| mscfb rejects truncated fat chain (system python3 oracle) | `test_mscfb_rejects_truncated_fat_chain` |
| mscfb encode python olefile oracle (system python3 oracle) | `test_mscfb_encode_python_olefile_oracle` |

### `packbits.rs`

| Coverage | Test cases |
| --- | --- |
| roundtrip / known vector / truncated rejection | `test_packbits_roundtrip_bytes`<br>`test_packbits_known_vector`<br>`test_packbits_rejects_truncated_packets` |

### `pea.rs`

| Coverage | Test cases |
| --- | --- |
| pea python oracle | `test_pea_python_oracle` |
| pea codec trait | `test_pea_codec_trait` |
| pea rejects truncated | `test_pea_rejects_truncated` |
| pea encode python oracle | `test_pea_encode_python_oracle` |
| pea encode stored python oracle | `test_pea_encode_stored_python_oracle` |
| pea archive encoder trait | `test_pea_archive_encoder_trait` |

### `romfs.rs`

| Coverage | Test cases |
| --- | --- |
| romfs genromfs image layout | `test_romfs_genromfs_image_layout` |
| romfs genromfs image contents | `test_romfs_genromfs_image_contents` |
| romfs codec trait | `test_romfs_codec_trait` |
| romfs rejects truncated image | `test_romfs_rejects_truncated_image` |
| romfs rejects corrupt checksum | `test_romfs_rejects_corrupt_checksum` |
| romfs encoder roundtrip | `test_romfs_encoder_roundtrip` |
| romfs encoder trait | `test_romfs_encoder_trait` |
| romfs encoder fsck romfs oracle (system fsck.romfs oracle) | `test_romfs_encoder_fsck_romfs_oracle` |

### `uuencode.rs`

| Coverage | Test cases |
| --- | --- |
| uuencode roundtrip | `test_uuencode_roundtrip` |
| uuencode python b2a uu decode (system python3 oracle) | `test_uuencode_python_b2a_uu_decode` |
| uuencode python a2b uu decodes ours (system python3 oracle) | `test_uuencode_python_a2b_uu_decodes_ours` |
| uuencode base64 roundtrip | `test_uuencode_base64_roundtrip` |
| uuencode base64 posix doc | `test_uuencode_base64_posix_doc` |
| uuencode base64 python decode (system python3 oracle) | `test_uuencode_base64_python_decode` |
| uuencode base64 python decodes ours (system python3 oracle) | `test_uuencode_base64_python_decodes_ours` |

### `yenc.rs`

| Coverage | Test cases |
| --- | --- |
| yenc roundtrip | `test_yenc_roundtrip` |
| yenc multipart roundtrip | `test_yenc_multipart_roundtrip` |
| yenc python reference decodes ours (system python3 oracle) | `test_yenc_python_reference_decodes_ours` |
| yenc decodes python reference output (system python3 oracle) | `test_yenc_decodes_python_reference_output` |

### `zstd_seekable.rs`

| Coverage | Test cases |
| --- | --- |
| zstd seekable decode reference text | `test_zstd_seekable_decode_reference_text` |
| zstd seekable decode reference binary | `test_zstd_seekable_decode_reference_binary` |
| zstd seekable range reference | `test_zstd_seekable_range_reference` |
| zstd seekable roundtrip | `test_zstd_seekable_roundtrip` |
| zstd seekable plain zstd decodes | `test_zstd_seekable_plain_zstd_decodes` |
| zstd seekable rejects plain zstd | `test_zstd_seekable_rejects_plain_zstd` |

### `fastlz.rs`

| Coverage | Test cases |
| --- | --- |
| fastlz reference vector l1 text | `fastlz_reference_vector_l1_text` |
| fastlz reference vector l1 run | `fastlz_reference_vector_l1_run` |
| fastlz reference vector l2 marker and chain | `fastlz_reference_vector_l2_marker_and_chain` |
| fastlz reference vector l2 far match | `fastlz_reference_vector_l2_far_match` |
| fastlz hand built segments | `fastlz_hand_built_segments` |
| fastlz roundtrips | `fastlz_roundtrips` |
| fastlz rejects malformed | `fastlz_rejects_malformed` |

### `git_pack.rs`

| Coverage | Test cases |
| --- | --- |
| decode real pack | `decode_real_pack` |
| decode real idx | `decode_real_idx` |
| encode roundtrip | `encode_roundtrip` |
| encode roundtrip with index | `encode_roundtrip_with_index` |
| bad signature | `bad_signature` |
| reject version4 | `reject_version4` |
| truncated | `truncated` |
| bad pack checksum | `bad_pack_checksum` |
| bad zlib stream | `bad_zlib_stream` |
| decode ref delta pack | `decode_ref_delta_pack` |
| apply delta copy insert | `apply_delta_copy_insert` |
| apply delta errors | `apply_delta_errors` |
| ofs delta pack accepted by git index pack (system git oracle) | `ofs_delta_pack_accepted_by_git_index_pack` |
| ref delta pack accepted by git index pack (system git oracle) | `ref_delta_pack_accepted_by_git_index_pack` |
| v3 pack accepted by git index pack (system git oracle) | `v3_pack_accepted_by_git_index_pack` |
| v1 idx accepted by git verify pack (system git oracle) | `v1_idx_accepted_by_git_verify_pack` |

### `lzf.rs`

| Coverage | Test cases |
| --- | --- |
| lzf hand built literal run | `lzf_hand_built_literal_run` |
| lzf hand built matches | `lzf_hand_built_matches` |
| lzf roundtrip text and binary | `lzf_roundtrip_text_and_binary` |
| lzf rejects malformed | `lzf_rejects_malformed` |

### `lzrw1.rs`

| Coverage | Test cases |
| --- | --- |
| lzrw1 reference vector fox | `lzrw1_reference_vector_fox` |
| lzrw1 reference vector a300 | `lzrw1_reference_vector_a300` |
| lzrw1 reference vector startstr | `lzrw1_reference_vector_startstr` |
| lzrw1 reference vector binary | `lzrw1_reference_vector_binary` |
| lzrw1 reference vector mixed | `lzrw1_reference_vector_mixed` |
| lzrw1 reference vector noise | `lzrw1_reference_vector_noise` |
| lzrw1 roundtrips | `lzrw1_roundtrips` |
| lzrw1 rejects malformed | `lzrw1_rejects_malformed` |

### `lzrw1a.rs`

| Coverage | Test cases |
| --- | --- |
| lzrw1a reference vector verbatim | `lzrw1a_reference_vector_verbatim` |
| lzrw1a reference vector compressed | `lzrw1a_reference_vector_compressed` |
| lzrw1a reference vector max offset | `lzrw1a_reference_vector_max_offset` |
| lzrw1a hand built | `lzrw1a_hand_built` |
| lzrw1a roundtrips | `lzrw1a_roundtrips` |
| lzrw1a rejects malformed | `lzrw1a_rejects_malformed` |

### `lzrw2.rs`

| Coverage | Test cases |
| --- | --- |
| lzrw2 reference vector fox | `lzrw2_reference_vector_fox` |
| lzrw2 reference vector a300 | `lzrw2_reference_vector_a300` |
| lzrw2 reference vector startstr | `lzrw2_reference_vector_startstr` |
| lzrw2 reference vector binary | `lzrw2_reference_vector_binary` |
| lzrw2 reference vector mixed | `lzrw2_reference_vector_mixed` |
| lzrw2 reference vector noise | `lzrw2_reference_vector_noise` |
| lzrw2 roundtrips | `lzrw2_roundtrips` |
| lzrw2 rejects malformed | `lzrw2_rejects_malformed` |

### `lzrw3.rs`

| Coverage | Test cases |
| --- | --- |
| lzrw3 reference vector fox | `lzrw3_reference_vector_fox` |
| lzrw3 reference vector a300 | `lzrw3_reference_vector_a300` |
| lzrw3 reference vector startstr | `lzrw3_reference_vector_startstr` |
| lzrw3 reference vector binary | `lzrw3_reference_vector_binary` |
| lzrw3 reference vector mixed | `lzrw3_reference_vector_mixed` |
| lzrw3 reference vector noise | `lzrw3_reference_vector_noise` |
| lzrw3 roundtrips | `lzrw3_roundtrips` |
| lzrw3 rejects malformed | `lzrw3_rejects_malformed` |

### `lzrw3a.rs`

| Coverage | Test cases |
| --- | --- |
| lzrw3a reference vector fox | `lzrw3a_reference_vector_fox` |
| lzrw3a reference vector a300 | `lzrw3a_reference_vector_a300` |
| lzrw3a reference vector startstr | `lzrw3a_reference_vector_startstr` |
| lzrw3a reference vector binary | `lzrw3a_reference_vector_binary` |
| lzrw3a reference vector mixed | `lzrw3a_reference_vector_mixed` |
| lzrw3a reference vector noise | `lzrw3a_reference_vector_noise` |
| lzrw3a roundtrips | `lzrw3a_roundtrips` |
| lzrw3a rejects malformed | `lzrw3a_rejects_malformed` |

### `lzs.rs`

| Coverage | Test cases |
| --- | --- |
| decode fixtures | `decode_fixtures` |
| encode decode roundtrip | `encode_decode_roundtrip` |
| window span roundtrip | `window_span_roundtrip` |
| truncated payload rejected | `truncated_payload_rejected` |

### `lzsa.rs`

| Coverage | Test cases |
| --- | --- |
| lzsa1 stream reference vector | `lzsa1_stream_reference_vector` |
| lzsa2 stream reference vector | `lzsa2_stream_reference_vector` |
| lzsa1 raw block reference vector | `lzsa1_raw_block_reference_vector` |
| lzsa2 raw block reference vector | `lzsa2_raw_block_reference_vector` |
| decode bounded enforces limit | `decode_bounded_enforces_limit` |
| encode roundtrips and redecodes | `encode_roundtrips_and_redecodes` |
| multi frame roundtrip | `multi_frame_roundtrip` |
| lzsa1 block with dictionary | `lzsa1_block_with_dictionary` |
| lzsa2 block with dictionary | `lzsa2_block_with_dictionary` |
| lzsa stream with dictionary | `lzsa_stream_with_dictionary` |
| lzsa1 raw block backwards reference vector | `lzsa1_raw_block_backwards_reference_vector` |
| lzsa2 raw block backwards reference vector | `lzsa2_raw_block_backwards_reference_vector` |
| backwards block byte reversal property | `backwards_block_byte_reversal_property` |
| backwards raw block roundtrip | `backwards_raw_block_roundtrip` |
| backwards block with dictionary | `backwards_block_with_dictionary` |

### `lzxd.rs`

| Coverage | Test cases |
| --- | --- |
| lzxd verbatim literals vector | `lzxd_verbatim_literals_vector` |
| lzxd reference data vector | `lzxd_reference_data_vector` |
| lzxd mixed blocks vector | `lzxd_mixed_blocks_vector` |
| lzxd generated matches and repeats | `lzxd_generated_matches_and_repeats` |
| lzxd generated extra lengths | `lzxd_generated_extra_lengths` |
| lzxd generated aligned block | `lzxd_generated_aligned_block` |
| lzxd generated multichunk span | `lzxd_generated_multichunk_span` |
| lzxd generated e8 | `lzxd_generated_e8` |
| lzxd decode all matches decode | `lzxd_decode_all_matches_decode` |
| lzxd rejects invalid | `lzxd_rejects_invalid` |
| lzxd encode decode roundtrip | `lzxd_encode_decode_roundtrip` |
| lzxd rejects match crossing chunk boundary | `lzxd_rejects_match_crossing_chunk_boundary` |

### `mppc.rs`

| Coverage | Test cases |
| --- | --- |
| decode single packet fixtures | `decode_single_packet_fixtures` |
| decode multi packet streams | `decode_multi_packet_streams` |
| encode decode roundtrip | `encode_decode_roundtrip` |
| oversized input rejected | `oversized_input_rejected` |
| decode rdp5 external fixtures | `decode_rdp5_external_fixtures` |
| decode rdp5 stream fixture | `decode_rdp5_stream_fixture` |
| rdp5 encode decode roundtrip | `rdp5_encode_decode_roundtrip` |
| rdp4 encode decode roundtrip | `rdp4_encode_decode_roundtrip` |
| rdp5 oversized input rejected | `rdp5_oversized_input_rejected` |
| rdp6 rejected | `rdp6_rejected` |

### `vcdiff.rs`

| Coverage | Test cases |
| --- | --- |
| vcdiff xdelta3 source window | `vcdiff_xdelta3_source_window` |
| vcdiff xdelta3 no source | `vcdiff_xdelta3_no_source` |
| vcdiff xdelta3 near same caches | `vcdiff_xdelta3_near_same_caches` |
| vcdiff roundtrips | `vcdiff_roundtrips` |
| vcdiff rejects malformed | `vcdiff_rejects_malformed` |
| vcdiff rejects bad checksum | `vcdiff_rejects_bad_checksum` |

### `xar.rs`

| Coverage | Test cases |
| --- | --- |
| decode real | `decode_real` |
| decode md5 checksums | `decode_md5_checksums` |
| decode stored no checksum | `decode_stored_no_checksum` |
| decode bzip2 encoding | `decode_bzip2_encoding` |
| decode xz and lzma encodings | `decode_xz_and_lzma_encodings` |
| reject corrupt encoded data | `reject_corrupt_encoded_data` |
| encode roundtrip | `encode_roundtrip` |
| archived checksum catches tampered heap | `archived_checksum_catches_tampered_heap` |
| archived checksum verified on valid archive | `archived_checksum_verified_on_valid_archive` |
| encode xml escape | `encode_xml_escape` |
| bad magic | `bad_magic` |
| truncated | `truncated` |
| bad toc checksum | `bad_toc_checksum` |
| bad extracted checksum | `bad_extracted_checksum` |
| bad version rejected | `bad_version_rejected` |
| xar encoded data unar oracle (system unar oracle) | `xar_encoded_data_unar_oracle` |

### `xca.rs`

| Coverage | Test cases |
| --- | --- |
| xpress spec example literals | `xpress_spec_example_literals` |
| xpress spec example match | `xpress_spec_example_match` |
| xpress windows vector mixed | `xpress_windows_vector_mixed` |
| xpress windows vector shared nibble | `xpress_windows_vector_shared_nibble` |
| xpress windows vector flag overflow | `xpress_windows_vector_flag_overflow` |
| xpress windows vector empty tail flags | `xpress_windows_vector_empty_tail_flags` |
| xpress huffman spec example literals | `xpress_huffman_spec_example_literals` |
| xpress huffman spec example match | `xpress_huffman_spec_example_match` |
| lznt1 stored chunk | `lznt1_stored_chunk` |
| lznt1 compressed chunk literals | `lznt1_compressed_chunk_literals` |
| lznt1 compressed chunk match | `lznt1_compressed_chunk_match` |
| xca roundtrips | `xca_roundtrips` |

### `zx0.rs`

| Coverage | Test cases |
| --- | --- |
| zx0 reference vector text | `zx0_reference_vector_text` |
| zx0 reference vector rep offset | `zx0_reference_vector_rep_offset` |
| zx0 reference vector long match | `zx0_reference_vector_long_match` |
| zx0 roundtrips | `zx0_roundtrips` |
| zx0 rejects malformed | `zx0_rejects_malformed` |
| zx0 prefix history | `zx0_prefix_history` |
| zx0 classic v1 stream | `zx0_classic_v1_stream` |
| zx0 backwards reference vectors | `zx0_backwards_reference_vectors` |
| zx0 backwards suffix history | `zx0_backwards_suffix_history` |
| zx0 backwards roundtrips | `zx0_backwards_roundtrips` |
| zx0 backwards suffix roundtrips | `zx0_backwards_suffix_roundtrips` |
| zx0 backwards rejects malformed | `zx0_backwards_rejects_malformed` |
| zx0 backwards empty | `zx0_backwards_empty` |

### `zx1.rs`

| Coverage | Test cases |
| --- | --- |
| zx1 reference vector text | `zx1_reference_vector_text` |
| zx1 reference vector rep offset | `zx1_reference_vector_rep_offset` |
| zx1 reference vector long match | `zx1_reference_vector_long_match` |
| zx1 reference vector mixed | `zx1_reference_vector_mixed` |
| zx1 reference vector far offset | `zx1_reference_vector_far_offset` |
| zx1 roundtrips | `zx1_roundtrips` |
| zx1 rejects malformed | `zx1_rejects_malformed` |
| zx1 prefix history | `zx1_prefix_history` |
| zx1 backwards reference vector text | `zx1_backwards_reference_vector_text` |
| zx1 backwards reference vector rep offset | `zx1_backwards_reference_vector_rep_offset` |
| zx1 backwards reference vector long match | `zx1_backwards_reference_vector_long_match` |
| zx1 backwards reference vector suffix | `zx1_backwards_reference_vector_suffix` |
| zx1 backwards roundtrips | `zx1_backwards_roundtrips` |
| zx1 backwards suffix roundtrips | `zx1_backwards_suffix_roundtrips` |
| zx1 backwards rejects malformed | `zx1_backwards_rejects_malformed` |

### `zx2.rs`

| Coverage | Test cases |
| --- | --- |
| zx2 reference vector text | `zx2_reference_vector_text` |
| zx2 reference vector rep offset | `zx2_reference_vector_rep_offset` |
| zx2 reference vector long match | `zx2_reference_vector_long_match` |
| zx2 reference vector mixed | `zx2_reference_vector_mixed` |
| zx2 reference vector far offset | `zx2_reference_vector_far_offset` |
| zx2 roundtrips | `zx2_roundtrips` |
| zx2 rejects malformed | `zx2_rejects_malformed` |
| zx2 no default offset | `zx2_no_default_offset` |
| zx2 no length increment | `zx2_no_length_increment` |
| zx2 prefix history | `zx2_prefix_history` |
| zx2 variant encode roundtrips | `zx2_variant_encode_roundtrips` |
| zx2b reference vector text | `zx2b_reference_vector_text` |
| zx2b reference vector rep offset | `zx2b_reference_vector_rep_offset` |
| zx2b reference vector long match | `zx2b_reference_vector_long_match` |
| zx2b variant vectors | `zx2b_variant_vectors` |
| zx2b suffix vector | `zx2b_suffix_vector` |
| zx2b roundtrips | `zx2b_roundtrips` |
| zx2b rejects malformed | `zx2b_rejects_malformed` |

### `zx5.rs`

| Coverage | Test cases |
| --- | --- |
| zx5 reference vector text | `zx5_reference_vector_text` |
| zx5 reference vector rep offset | `zx5_reference_vector_rep_offset` |
| zx5 reference vector long match | `zx5_reference_vector_long_match` |
| zx5 reference vector mixed | `zx5_reference_vector_mixed` |
| zx5 reference vector alt offsets | `zx5_reference_vector_alt_offsets` |
| zx5 roundtrips | `zx5_roundtrips` |
| zx5 rejects malformed | `zx5_rejects_malformed` |
| zx5 prefix history | `zx5_prefix_history` |
| zx5 classic v1 stream | `zx5_classic_v1_stream` |
| zx5b reference vector text | `zx5b_reference_vector_text` |
| zx5b reference vector rep offset | `zx5b_reference_vector_rep_offset` |
| zx5b reference vector long match | `zx5b_reference_vector_long_match` |
| zx5b reference vector suffix | `zx5b_reference_vector_suffix` |
| zx5b roundtrips | `zx5b_roundtrips` |
| zx5b rejects malformed | `zx5b_rejects_malformed` |

### `generated/`

`tests/integration/generated/` は fuzz failure から自動生成された回帰テスト群である。
ファイル名・テスト名は failure signature に由来するため、個別の coverage 表には載せず、
ここにまとめて扱う。現在は 40 件の `test_fuzz_regression_*` があり、いずれも
decode が panic せずに完了することを検証する。

## Related files

- fixture provenance:
  - `tests/fixtures/README.md`
- harness:
  - `tests/integration.rs`
