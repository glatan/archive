# Integration tests

このディレクトリ配下の integration test は、crate の public API を format ごとに end-to-end で確認するためのものです。
主に次の観点を扱います。

- encode/decode の roundtrip
- `encode_writer` / `decode_reader`
- system tool との相互運用
- metadata / dictionary / multi-member / multi-frame
- corruption / malformed input / checksum mismatch

`tests/integration.rs` が harness になっており、各 `tests/integration/*.rs` を module として読み込みます。

## 実行方法

- 全体:
  - `cargo test --all-features --test integration`
- リポジトリ標準の検証:
  - `cargo fmt --all`
  - `cargo test --all-features`
  - `cargo clippy --all-features --all-targets -- -D warnings`

## System tool interop の扱い

一部の integration test は Arch Linux 側の外部ツールを使います。
ツールが見つからない環境では、それらの test は skip されます。

現時点で `Containerfile` では次を用意しています。

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
- custom package:
  - `rzip`
  - `zpaq`

ただし、**tool が入っていても相互運用 test を持たない format はあります**。
これは current implementation scope と upstream tool の format 差分によるものです。

- `zpaq`
  - crate 側は simplified archive layout を対象としており、system `zpaq` の journaling archive とは直接互換ではない
- `7z`
  - system `7z` が生成する一部 archive metadata/property variant は未対応
  - 現在は `crate -> system 7z extract` 側を固定している
- `rzip`
  - `system rzip -> crate decode` と `crate -> system rzip decode` を simple payload で固定している
  - large payload や multi-chunk 境界の `system rzip` parity はまだ主張していない

## Test inventory

以下の表では、各 integration test file がどの観点をどの test case で固定しているかを対応付けています。

### `ar.rs`

| Coverage | Test cases |
| --- | --- |
| GNU/BSD roundtrip baseline | `test_ar_roundtrip_gnu`<br>`test_ar_empty_archive_roundtrip`<br>`test_ar_roundtrip_multiple_long_names_bsd` |
| system archive decode / system listing | `test_ar_decode_system_archive`<br>`test_ar_gnu_system_compat`<br>`test_ar_empty_archive_system_list_compat`<br>`test_ar_bsd_system_compat`<br>`test_ar_gnu_system_extract_content_compat` |
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

### `rpm.rs`

| カバー項目 | テスト |
|---|---|
| uncompressed cpio payload decode | `test_rpm_decode_uncompressed_payload` |
| gzip payload decode | `test_rpm_decode_gzip_payload` |
| xz / zstd payload decode | `test_rpm_decode_xz_and_zstd_payloads` |
| v6 stripped payload (07070X) | `test_rpm_decode_stripped_payload` |
| system cpio+gzip payload interop | `test_rpm_decode_system_compressed_payload` |
| `bsdtar` payload extraction interop | `test_rpm_crate_built_read_by_bsdtar` |

### `squashfs.rs`

| カバー項目 | テスト |
|---|---|
| `mksquashfs` 生成 image (gzip/zstd/xz/lz4/lzo) の decode | `test_squashfs_decode_mksquashfs_image` |
| 本 writer 出力 (gzip/xz/lz4/lzo/zstd) の `unsquashfs` 展開 | `test_squashfs_encoder_unsquashfs_extract` |
| encoder → decoder roundtrip | `test_squashfs_encoder_roundtrip` |

### `mscab.rs`

| 内容 | テスト名 |
|------|----------|
| MSZIP 圧縮 cabinet の decode | `test_mscab_decode_mszip_cabinet` |
| crate 生成 cab の `bsdtar` 展開 interop | `test_mscab_bsdtar_interop` |

### `zim.rs`

| 内容 | テスト名 |
|------|----------|
| stored cluster decode | `test_zim_decode_stored_cluster` |
| xz cluster decode | `test_zim_decode_xz_cluster` |
| zstd cluster decode | `test_zim_decode_zstd_cluster` |
| truncated header reject | `test_zim_rejects_truncated_header` |

### `mtree.rs`

| 内容 | テスト名 |
|------|----------|
| basic manifest decode (/set・相対 dir 遷移) | `test_mtree_decode_basic` |
| `bsdtar --format=mtree` 生成マニフェストの decode interop | `test_mtree_bsdtar_interop` |

### `warc.rs`

| 内容 | テスト名 |
|------|----------|
| 複数 record ストリーム decode (warcinfo/response/revisit) | `test_warc_decode_records` |
| gzip 伸張経路経由の `.warc.gz` decode | `test_warc_gzip_members` |

### `brotli.rs`

| Coverage | Test cases |
| --- | --- |
| system `brotli` decode interop | `test_brotli_decode_system_q0_uncompressed`<br>`test_brotli_decode_system_q3_compressed_run`<br>`test_brotli_decode_system_q5_repeated_pattern`<br>`test_brotli_decode_system_binary_payload` |
| crate encode / writer path | `test_brotli_encode_roundtrip`<br>`test_brotli_encode_system_decode`<br>`test_brotli_encode_empty_system_decode`<br>`test_brotli_encode_writer_roundtrip`<br>`test_brotli_encode_multi_metablock_roundtrip`<br>`test_brotli_encode_repeated_pattern_system_decode`<br>`test_brotli_encode_low_cardinality_system_decode` |
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
| fixture / basic roundtrip | `test_cpio_decode_single_file`<br>`test_cpio_directories_only_roundtrip`<br>`test_cpio_empty_archive_roundtrip` |
| reader / format variants | `test_cpio_decode_reader_roundtrip_integration`<br>`test_cpio_odc_roundtrip_integration` |
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
| system `lrzip` interop | `test_lrzip_decode_system_lzma_archive`<br>`test_lrzip_decode_system_lzma_repeated_archive`<br>`test_lrzip_encode_system_decode_compat`<br>`test_lrzip_encode_bzip2_system_decode_compat`<br>`test_lrzip_encode_gzip_system_decode_compat`<br>`test_lrzip_encode_none_system_decode_compat`<br>`test_lrzip_encode_lzo_system_decode_compat`<br>`test_lrzip_encode_zpaq_system_decode_compat` |

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
| system fixture / system interop | `test_lzw_decode_system_compress_fixture`<br>`test_lzw_encode_decoded_by_system_uncompress`<br>`test_lzw_decode_system_compressed_stream` |
| writer / reader path | `test_lzw_encode_writer_decode_reader_roundtrip` |
| malformed header | `test_lzw_decode_rejects_reserved_header_flags` |

### `rzip.rs`

| Coverage | Test cases |
| --- | --- |
| crate roundtrip / level API | `test_rzip_roundtrip_level_matrix`<br>`test_rzip_roundtrip_binary_payload` |
| system `rzip` interop | `test_rzip_decode_system_archive`<br>`test_rzip_encode_system_decode_compat`<br>`test_rzip_encode_system_decode_binary_payload`<br>`test_rzip_encode_system_decode_multichunk_payload` |

### `sevenz.rs`

| Coverage | Test cases |
| --- | --- |
| system `7z` extract interop | `test_sevenz_encode_system_extract_compat`<br>`test_sevenz_empty_archive_roundtrip_and_system_list`<br>`test_sevenz_multi_file_system_extract_compat`<br>`test_sevenz_two_folder_system_extract_compat`<br>`test_sevenz_two_folder_encrypted_system_extract_compat`<br>`test_sevenz_two_folder_encoded_header_system_extract_compat`<br>`test_sevenz_two_folder_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_ppmd_method_system_extract_compat`<br>`test_sevenz_ppmd_encoded_header_system_extract_compat`<br>`test_sevenz_ppmd_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_two_folder_ppmd_system_extract_compat`<br>`test_sevenz_two_folder_ppmd_encoded_header_system_extract_compat`<br>`test_sevenz_two_folder_ppmd_encrypted_system_extract_compat`<br>`test_sevenz_two_folder_ppmd_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_x86_bcj_filter_system_extract_compat`<br>`test_sevenz_x86_bcj_encoded_header_system_extract_compat`<br>`test_sevenz_x86_bcj_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_two_folder_x86_bcj_filter_system_extract_compat`<br>`test_sevenz_two_folder_x86_bcj_encoded_header_system_extract_compat`<br>`test_sevenz_two_folder_x86_bcj_encrypted_system_extract_compat`<br>`test_sevenz_two_folder_x86_bcj_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_delta_filter_system_extract_compat`<br>`test_sevenz_delta_encoded_header_system_extract_compat`<br>`test_sevenz_delta_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_two_folder_delta_filter_system_extract_compat`<br>`test_sevenz_two_folder_delta_encoded_header_system_extract_compat`<br>`test_sevenz_two_folder_delta_encrypted_system_extract_compat`<br>`test_sevenz_two_folder_delta_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_encrypted_archive_system_extract_compat`<br>`test_sevenz_encoded_header_roundtrip_and_system_extract`<br>`test_sevenz_encrypted_encoded_header_roundtrip_and_system_extract` |
| method coverage | `test_sevenz_copy_method_roundtrip_integration`<br>`test_sevenz_ppmd_method_roundtrip_integration`<br>`test_sevenz_ppmd_method_system_extract_compat`<br>`test_sevenz_ppmd_encoded_header_system_extract_compat`<br>`test_sevenz_ppmd_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_two_folder_ppmd_system_extract_compat`<br>`test_sevenz_two_folder_ppmd_encoded_header_system_extract_compat`<br>`test_sevenz_two_folder_ppmd_encrypted_system_extract_compat`<br>`test_sevenz_two_folder_ppmd_encrypted_encoded_header_system_extract_compat` |
| `add_entry` / filters | `test_sevenz_add_entry_with_filters_roundtrip`<br>`test_sevenz_delta_filter_roundtrip_integration`<br>`test_sevenz_x86_bcj_filter_system_extract_compat`<br>`test_sevenz_x86_bcj_encoded_header_system_extract_compat`<br>`test_sevenz_x86_bcj_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_two_folder_x86_bcj_filter_system_extract_compat`<br>`test_sevenz_two_folder_x86_bcj_encoded_header_system_extract_compat`<br>`test_sevenz_two_folder_x86_bcj_encrypted_system_extract_compat`<br>`test_sevenz_two_folder_x86_bcj_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_delta_filter_system_extract_compat`<br>`test_sevenz_delta_encoded_header_system_extract_compat`<br>`test_sevenz_delta_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_two_folder_delta_filter_system_extract_compat`<br>`test_sevenz_two_folder_delta_encoded_header_system_extract_compat`<br>`test_sevenz_two_folder_delta_encrypted_system_extract_compat`<br>`test_sevenz_two_folder_delta_encrypted_encoded_header_system_extract_compat` |
| password APIs / failure path | `test_sevenz_password_bytes_roundtrip_and_failures`<br>`test_sevenz_encrypted_archive_system_extract_compat`<br>`test_sevenz_ppmd_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_x86_bcj_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_delta_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_two_folder_ppmd_encrypted_system_extract_compat`<br>`test_sevenz_two_folder_ppmd_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_two_folder_x86_bcj_encrypted_system_extract_compat`<br>`test_sevenz_two_folder_x86_bcj_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_two_folder_delta_encrypted_system_extract_compat`<br>`test_sevenz_two_folder_delta_encrypted_encoded_header_system_extract_compat`<br>`test_sevenz_encrypted_encoded_header_roundtrip_and_system_extract` |

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
| malformed input | `test_tar_decode_rejects_truncated_archive` |

### `xz.rs`

| Coverage | Test cases |
| --- | --- |
| baseline roundtrip | `test_xz_roundtrip_hello`<br>`test_xz_roundtrip_empty`<br>`test_xz_roundtrip_large` |
| system interop / regressions | `test_xz_interop_with_system_xz`<br>`test_xz_decode_system_encoded`<br>`test_xz_decode_system_compressed_fuzz_regression`<br>`test_xz_decode_system_compressed_fuzz_regression_multichunk_state`<br>`test_xz_encode_system_decode_fuzz_regression`<br>`test_xz_multi_stream_system_decode` |
| BCJ / Delta filter chains | `test_xz_decode_system_encoded_x86_filter_chain`<br>`test_xz_encode_x86_filter_chain_system_decode`<br>`test_xz_decode_system_encoded_delta_filter_chain`<br>`test_xz_encode_delta_filter_chain_system_decode`<br>`test_xz_decode_system_encoded_powerpc_filter_chain`<br>`test_xz_encode_powerpc_filter_chain_system_decode`<br>`test_xz_decode_system_encoded_ia64_filter_chain`<br>`test_xz_encode_ia64_filter_chain_system_decode`<br>`test_xz_decode_system_encoded_sparc_filter_chain`<br>`test_xz_encode_sparc_filter_chain_system_decode`<br>`test_xz_decode_system_encoded_arm_filter_chain`<br>`test_xz_encode_arm_filter_chain_system_decode`<br>`test_xz_decode_system_encoded_arm64_filter_chain`<br>`test_xz_encode_arm64_filter_chain_system_decode`<br>`test_xz_decode_system_encoded_riscv_filter_chain`<br>`test_xz_encode_riscv_filter_chain_system_decode`<br>`test_xz_decode_system_encoded_armthumb_filter_chain`<br>`test_xz_encode_armthumb_filter_chain_system_decode` |
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
| checksum / size / descriptor validation | `test_zip_decode_detects_checksum_mismatch`<br>`test_zip_decode_detects_size_mismatch`<br>`test_zip_decode_detects_data_descriptor_mismatch` |
| metadata / entry bridge | `test_zip_utf8_metadata_roundtrip_via_reader`<br>`test_zip_cp437_metadata_roundtrip_without_utf8_flag`<br>`test_zip_add_entry_roundtrip_preserves_metadata` |

### `zlib.rs`

| Coverage | Test cases |
| --- | --- |
| baseline roundtrip | `test_zlib_roundtrip_large_integration`<br>`test_zlib_empty_stream_roundtrip` |
| Python `zlib` interop | `test_zlib_decode_python_zlib_stream`<br>`test_zlib_encode_stream_decoded_by_python` |
| header / checksum validation | `test_zlib_decode_rejects_preset_dictionary_flag`<br>`test_zlib_decode_detects_adler32_mismatch` |
| malformed headers | `test_zip_decode_detects_local_and_central_name_mismatch`<br>`test_zip_decode_detects_invalid_local_file_header_signature` |

### `zpaq.rs`

| Coverage | Test cases |
| --- | --- |
| simplified archive roundtrip | `test_zpaq_archive_multi_entry_roundtrip` |
| empty archive | `test_zpaq_archive_empty_roundtrip` |
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
| encoder analysis helpers | `test_zstd_encode_large_single_sequence_debug`<br>`test_zstd_encode_analyze_blocks`<br>`test_zstd_lz77_analyze`<br>`test_single_sequence_fse_minimal` |

## Related files

- fixture provenance:
  - `tests/fixtures/README.md`
- harness:
  - `tests/integration.rs`
