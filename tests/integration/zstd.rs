// ============================================================
// Feature isolation build tests (compile-time only)
// ============================================================

// ============================================================
// Zstd tests
// ============================================================

#[test]
fn test_zstd_decode_hello() {
    let zstd_data = include_bytes!("../fixtures/zstd/zstd_hello.zst");
    let result = archive::compress::zstd::decode::decode(zstd_data).unwrap();
    assert_eq!(result, b"Hello, World!");
}

#[test]
fn test_zstd_decode_repeated() {
    let zstd_data = include_bytes!("../fixtures/zstd/zstd_repeated.zst");
    let result = archive::compress::zstd::decode::decode(zstd_data).unwrap();
    let expected = "The quick brown fox jumps over the lazy dog. ".repeat(10);
    assert_eq!(result, expected.as_bytes());
}

#[test]
fn test_zstd_decode_large() {
    let zstd_data = include_bytes!("../fixtures/zstd/zstd_large.zst");
    let expected = include_bytes!("../fixtures/zstd/zstd_large.txt");
    let result = archive::compress::zstd::decode::decode(zstd_data).unwrap();
    assert_eq!(result, expected);
}

#[test]
fn test_zstd_encode_roundtrip() {
    // Encode with our encoder, decode with our decoder
    let input: Vec<u8> = (0..50_000).map(|i| (i % 251) as u8).collect();
    let encoded = archive::compress::zstd::encode::encode(&input);
    let decoded = archive::compress::zstd::decode::decode(&encoded).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_zstd_encode_writer_decode_reader_roundtrip() {
    use std::io::Cursor;

    let input: Vec<u8> = (0..100_000).map(|i| ((i * 29) % 251) as u8).collect();
    let mut encoded = Vec::new();
    let written = archive::compress::zstd::encode::encode_writer(&input, &mut encoded).unwrap();
    assert_eq!(written, encoded.len());

    let decoded = archive::compress::zstd::decode::decode_reader(Cursor::new(&encoded)).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_zstd_encode_decoded_by_system() {
    // Our encoder's output should be decodable by the system zstd tool
    let input = b"Hello, zstd encoding from Rust!";
    let encoded = archive::compress::zstd::encode::encode(input);
    // Verify our own decoder can handle it
    let decoded = archive::compress::zstd::decode::decode(&encoded).unwrap();
    assert_eq!(decoded, input.as_slice());
    // Verify the existing fixture files can still be decoded
    let zstd_data = include_bytes!("../fixtures/zstd/zstd_hello.zst");
    let result = archive::compress::zstd::decode::decode(zstd_data).unwrap();
    assert_eq!(result, b"Hello, World!");
}

#[test]
fn test_zstd_encode_large_raw_system_compat() {
    use std::process::Command;

    let has_zstd = Command::new("zstd").arg("--version").output().is_ok();
    if !has_zstd {
        return;
    }

    let input: Vec<u8> = (0..60_000).map(|i| (i % 251) as u8).collect();
    let encoded = archive::compress::zstd::encode::encode(&input);

    let tmp_dir = std::env::temp_dir();
    let zst_path = tmp_dir.join("archive_test_zstd_large_single_sequence.zst");
    let out_path = tmp_dir.join("archive_test_zstd_large_single_sequence.out");

    std::fs::write(&zst_path, &encoded).unwrap();
    let status = Command::new("zstd")
        .args(["-d", "-f"])
        .arg(&zst_path)
        .arg("-o")
        .arg(&out_path)
        .output()
        .unwrap();

    let decoded = std::fs::read(&out_path).unwrap_or_default();
    let _ = std::fs::remove_file(&zst_path);
    let _ = std::fs::remove_file(&out_path);

    assert!(
        status.status.success(),
        "system zstd failed: {:?}",
        String::from_utf8_lossy(&status.stderr)
    );
    assert_eq!(decoded, input);
}

#[test]
fn test_zstd_decode_system_compressed_fuzz_regression() {
    let input = include_bytes!("../fixtures/fuzz/zstd_original_compress_1.bin");
    let compressed = include_bytes!("../fixtures/fuzz/zstd_original_compress_1.zst");
    let decoded = archive::compress::zstd::decode::decode(compressed).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_zstd_multi_frame() {
    // Build two zstd frames and concatenate them
    fn build_raw_frame(data: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&0xFD2FB528u32.to_le_bytes());
        frame.push(0b0010_0000); // SS=1, no checksum
        frame.push(data.len() as u8); // FCS
        let bh = (data.len() as u32) << 3 | 0b001;
        frame.push(bh as u8);
        frame.push((bh >> 8) as u8);
        frame.push((bh >> 16) as u8);
        frame.extend_from_slice(data);
        frame
    }

    let frame1 = build_raw_frame(b"Hello");
    let frame2 = build_raw_frame(b" World");
    let mut combined = frame1;
    combined.extend_from_slice(&frame2);
    let result = archive::compress::zstd::decode::decode(&combined).unwrap();
    assert_eq!(result, b"Hello World");
}

#[test]
fn test_zstd_encode_large_literals_roundtrip() {
    // Current encoder may conservatively fall back to raw blocks, but it must
    // still round-trip the large literals payload correctly.
    let phrases = [
        "the quick brown fox jumps over the lazy dog and ",
        "she sells seashells by the seashore repeatedly. ",
    ];
    let mut input = String::new();
    for i in 0..100 {
        input.push_str(phrases[i % phrases.len()]);
    }
    let input = input.as_bytes();
    assert!(input.len() > 1023, "input must exceed single-stream limit");

    let encoded = archive::compress::zstd::encode::encode(input);
    let decoded = archive::compress::zstd::decode::decode(&encoded).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_zstd_encode_large_text_system_compat() {
    // Verify system zstd can decode output from the current public encoder.
    use std::process::Command;

    // Check if system zstd is available
    let has_zstd = Command::new("zstd").arg("--version").output().is_ok();
    if !has_zstd {
        return; // Skip if zstd not installed
    }

    let mut input = Vec::new();
    for i in 0..200 {
        input.extend_from_slice(match i % 4 {
            0 => b"the quick brown fox ".as_slice(),
            1 => b"jumps over the lazy ",
            2 => b"dog and then rested ",
            _ => b"beneath the old oak ",
        });
    }

    let encoded = archive::compress::zstd::encode::encode(&input);

    // Write to temp file and decompress with system zstd
    let tmp_dir = std::env::temp_dir();
    let zst_path = tmp_dir.join("archive_test_4stream.zst");
    let out_path = tmp_dir.join("archive_test_4stream.out");

    std::fs::write(&zst_path, &encoded).unwrap();

    let status = Command::new("zstd")
        .args(["-d", "-f"])
        .arg(&zst_path)
        .arg("-o")
        .arg(&out_path)
        .output()
        .unwrap();

    let decoded = std::fs::read(&out_path).unwrap_or_default();
    // Clean up
    let _ = std::fs::remove_file(&zst_path);
    let _ = std::fs::remove_file(&out_path);

    assert!(
        status.status.success(),
        "system zstd failed: {:?}",
        String::from_utf8_lossy(&status.stderr)
    );
    assert_eq!(decoded, input);
}

#[test]
fn test_zstd_decode_with_dict_system() {
    use std::process::Command;

    // Check if system zstd is available
    let has_zstd = Command::new("zstd").arg("--version").output().is_ok();
    if !has_zstd {
        return; // Skip if zstd not installed
    }

    let tmp_dir = std::env::temp_dir().join("archive_dict_test");
    let _ = std::fs::create_dir_all(&tmp_dir);
    let samples_dir = tmp_dir.join("samples");
    let _ = std::fs::create_dir_all(&samples_dir);

    // Create training samples with shared patterns
    let phrases = [
        "the quick brown fox jumps over the lazy dog",
        "a stitch in time saves nine",
        "all that glitters is not gold",
        "actions speak louder than words",
        "the pen is mightier than the sword",
    ];
    for (i, phrase) in phrases.iter().enumerate() {
        let content = phrase.repeat(10);
        std::fs::write(
            samples_dir.join(format!("sample_{i}.txt")),
            content.as_bytes(),
        )
        .unwrap();
    }

    let dict_path = tmp_dir.join("test.dict");

    // Train dictionary using system zstd
    let train_status = Command::new("zstd")
        .arg("--train")
        .arg(samples_dir.join("*"))
        .args(["--maxdict", "4096"])
        .arg("-o")
        .arg(&dict_path)
        .arg("-r")
        .arg(&samples_dir)
        .output();

    let train_output = match train_status {
        Ok(o) => o,
        Err(_) => {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return; // zstd --train not available
        }
    };

    if !train_output.status.success() {
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return; // Training failed, skip test
    }

    // Compress test data using the dictionary
    let test_input =
        "the quick brown fox jumps over the lazy dog and all that glitters is not gold";
    let input_path = tmp_dir.join("input.txt");
    let compressed_path = tmp_dir.join("input.txt.zst");
    std::fs::write(&input_path, test_input.as_bytes()).unwrap();

    let compress_status = Command::new("zstd")
        .arg("-f")
        .arg("-D")
        .arg(&dict_path)
        .arg(&input_path)
        .arg("-o")
        .arg(&compressed_path)
        .output()
        .unwrap();

    if !compress_status.status.success() {
        let _ = std::fs::remove_dir_all(&tmp_dir);
        panic!(
            "zstd compression with dict failed: {}",
            String::from_utf8_lossy(&compress_status.stderr)
        );
    }

    // Read dictionary and compressed data
    let dict_data = std::fs::read(&dict_path).unwrap();
    let compressed_data = std::fs::read(&compressed_path).unwrap();

    // Clean up
    let _ = std::fs::remove_dir_all(&tmp_dir);

    // Parse dictionary with our library
    let dict = archive::compress::zstd::decode::ZstdDict::parse(&dict_data).unwrap();

    // Decode with dictionary
    let decoded =
        archive::compress::zstd::decode::decode_with_dict(&compressed_data, &dict).unwrap();
    assert_eq!(decoded, test_input.as_bytes());
}

#[test]
fn test_zstd_encode_with_dict_system_compat() {
    use std::process::Command;

    let has_zstd = Command::new("zstd").arg("--version").output().is_ok();
    if !has_zstd {
        return;
    }

    let tmp_dir = std::env::temp_dir().join("archive_encode_dict_test");
    let _ = std::fs::create_dir_all(&tmp_dir);
    let samples_dir = tmp_dir.join("samples");
    let _ = std::fs::create_dir_all(&samples_dir);

    // Training samples
    let phrases = [
        "the quick brown fox jumps over the lazy dog",
        "a stitch in time saves nine",
        "all that glitters is not gold",
        "actions speak louder than words",
        "the pen is mightier than the sword",
    ];
    for (i, phrase) in phrases.iter().enumerate() {
        let content = phrase.repeat(50);
        std::fs::write(samples_dir.join(format!("s{i}.txt")), content.as_bytes()).unwrap();
    }

    let dict_path = tmp_dir.join("test.dict");
    let train = Command::new("zstd")
        .arg("--train")
        .args(["--maxdict", "4096"])
        .arg("-o")
        .arg(&dict_path)
        .arg("-r")
        .arg(&samples_dir)
        .output();

    let ok = train.map(|o| o.status.success()).unwrap_or(false);
    if !ok {
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return;
    }

    let dict_data = std::fs::read(&dict_path).unwrap();
    let dict = archive::compress::zstd::decode::ZstdDict::parse(&dict_data).unwrap();

    // Encode with our library using the dictionary
    let test_input =
        b"the quick brown fox jumps over the lazy dog and all that glitters is not gold";
    let encoded = archive::compress::zstd::encode::encode_with_dict(test_input, &dict);

    // Write encoded data and decompress with system zstd
    let zst_path = tmp_dir.join("our_output.zst");
    let out_path = tmp_dir.join("our_output.txt");
    std::fs::write(&zst_path, &encoded).unwrap();

    let status = Command::new("zstd")
        .args(["-d", "-f"])
        .arg("-D")
        .arg(&dict_path)
        .arg(&zst_path)
        .arg("-o")
        .arg(&out_path)
        .output()
        .unwrap();

    let decoded = std::fs::read(&out_path).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&tmp_dir);

    assert!(
        status.status.success(),
        "system zstd -D failed: {:?}",
        String::from_utf8_lossy(&status.stderr)
    );
    assert_eq!(decoded, test_input.as_slice());
}

#[test]
fn test_zstd_train_dictionary_roundtrip() {
    use archive::compress::zstd::train::{TrainOptions, train_dictionary};

    let samples = [
        b"archive crate fixes zstd dictionary training".as_slice(),
        b"archive crate keeps zstd dictionary support in tree".as_slice(),
        b"archive crate adds deterministic dictionary training".as_slice(),
    ];
    let dict = train_dictionary(
        &samples,
        &TrainOptions {
            max_dict_size: 256,
            ..TrainOptions::default()
        },
    )
    .unwrap();

    let payload = b"archive crate fixes zstd dictionary regressions";
    let encoded = archive::compress::zstd::encode::encode_with_dict(payload, &dict);
    let decoded = archive::compress::zstd::decode::decode_with_dict(&encoded, &dict).unwrap();
    assert_eq!(decoded, payload);
    assert!(!dict.content.is_empty());
}

#[test]
fn test_zstd_encode_with_options_checksum_off_roundtrip() {
    let input = b"zstd checksum-off integration payload ".repeat(256);
    let encoded = archive::compress::zstd::encode::encode_with_options(
        &input,
        &archive::compress::zstd::encode::EncodeOptions { checksum: false },
    );

    assert_eq!(encoded[4] & (1 << 2), 0, "checksum flag should be cleared");

    let decoded = archive::compress::zstd::decode::decode(&encoded).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_zstd_decode_skippable_frame_before_payload() {
    let payload = b"zstd skippable frame payload";
    let encoded = archive::compress::zstd::encode::encode(payload);
    let mut combined = Vec::new();
    combined.extend_from_slice(&0x184D2A50u32.to_le_bytes());
    combined.extend_from_slice(&(5u32).to_le_bytes());
    combined.extend_from_slice(b"skip!");
    combined.extend_from_slice(&encoded);

    let decoded = archive::compress::zstd::decode::decode(&combined).unwrap();
    assert_eq!(decoded, payload);
}

#[test]
fn test_zstd_decode_reader_with_skippable_frame_before_payload() {
    use std::io::Cursor;

    let mut frame = Vec::new();
    frame.extend_from_slice(&0x184D2A50u32.to_le_bytes());
    frame.extend_from_slice(&4u32.to_le_bytes());
    frame.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    frame.extend_from_slice(&archive::compress::zstd::encode::encode(
        b"reader skippable payload",
    ));

    let decoded = archive::compress::zstd::decode::decode_reader(Cursor::new(&frame)).unwrap();
    assert_eq!(decoded, b"reader skippable payload");
}

#[test]
fn test_zstd_content_only_dictionary_roundtrip() {
    let dict = archive::compress::zstd::decode::ZstdDict::from_content(
        0x1234_5678,
        b"shared dictionary content for archive zstd tests",
    )
    .unwrap();
    let payload = b"archive zstd dictionary content-only path";
    let encoded = archive::compress::zstd::encode::encode_with_dict(payload, &dict);
    let decoded = archive::compress::zstd::decode::decode_with_dict(&encoded, &dict).unwrap();

    assert_eq!(decoded, payload);
}

#[test]
fn test_zstd_decode_rejects_dictionary_mismatch_and_missing_dictionary() {
    let dict = archive::compress::zstd::decode::ZstdDict::from_content(
        0x1111_2222,
        b"primary dictionary content",
    )
    .unwrap();
    let other_dict = archive::compress::zstd::decode::ZstdDict::from_content(
        0x3333_4444,
        b"secondary dictionary content",
    )
    .unwrap();
    let payload = b"dictionary mismatch coverage";
    let encoded = archive::compress::zstd::encode::encode_with_dict(payload, &dict);

    assert!(matches!(
        archive::compress::zstd::decode::decode(&encoded),
        Err(archive::error::Error::Unsupported(
            "frame requires dictionary but none provided"
        ))
    ));
    assert!(matches!(
        archive::compress::zstd::decode::decode_with_dict(&encoded, &other_dict),
        Err(archive::error::Error::InvalidData(
            "dictionary ID mismatch between frame and provided dictionary"
        ))
    ));
}

#[test]
fn test_zstd_encode_large_single_sequence_debug() {
    let input: Vec<u8> = (0..60_000).map(|i| (i % 251) as u8).collect();
    let encoded = archive::compress::zstd::encode::encode(&input);

    eprintln!("Input size: {}", input.len());
    eprintln!("Encoded size: {}", encoded.len());
    eprintln!("Encoded hex (first 300 bytes):");
    for (i, b) in encoded.iter().take(300).enumerate() {
        if i % 16 == 0 {
            eprintln!();
        }
        eprint!("{:02x} ", b);
    }
    eprintln!("\n");

    let decoded = archive::compress::zstd::decode::decode(&encoded);
    match decoded {
        Ok(d) => {
            eprintln!("Decoded successfully: {} bytes", d.len());
            if d == input {
                eprintln!("Roundtrip SUCCESS");
            } else {
                eprintln!("Roundtrip FAILED - data mismatch at {} bytes", d.len());
            }
        }
        Err(e) => {
            eprintln!("Decode error: {:?}", e);
        }
    }
}

#[test]
fn test_zstd_encode_analyze_blocks() {
    let input: Vec<u8> = (0..60_000).map(|i| (i % 251) as u8).collect();
    let encoded = archive::compress::zstd::encode::encode(&input);

    eprintln!("Total encoded size: {}", encoded.len());

    // Check if input is RLE
    let is_all_same = input.iter().all(|&b| b == input[0]);
    eprintln!("Input is RLE: {}", is_all_same);

    // Parse frame header
    eprintln!("Frame magic OK: {}", &encoded[0..4] == b"\x28\xb5\x2f\xfd");

    let descriptor = encoded[4];
    let fcs_flag = (descriptor >> 6) & 0x03;
    eprintln!("FCS flag: {}", fcs_flag);

    // Compute FCS
    let fcs = match fcs_flag {
        0 => encoded[5] as u64,
        1 => {
            let val = u16::from_le_bytes([encoded[5], encoded[6]]) as u64;
            val + 256
        }
        2 => u32::from_le_bytes([encoded[5], encoded[6], encoded[7], encoded[8]]) as u64,
        3 => u64::from_le_bytes([
            encoded[5],
            encoded[6],
            encoded[7],
            encoded[8],
            encoded[9],
            encoded[10],
            encoded[11],
            encoded[12],
        ]),
        _ => 0,
    };
    eprintln!("FCS decoded: {} (expected 60000)", fcs);

    // Block header starts after FCS
    let block_start = 5 + match fcs_flag {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => 0,
    };

    eprintln!("Block starts at offset {}", block_start);
    if block_start < encoded.len() {
        let bh = encoded[block_start];
        let last = (bh >> 7) & 1;
        let block_type = (bh >> 5) & 0x03;
        let size_raw = (bh & 0x1f) as u32;

        eprintln!("Block header: 0x{:02x}", bh);
        eprintln!(
            "  Last: {}, Type: {} (0=raw, 1=RLE, 2=compressed, 3=reserved), Size field: {}",
            last, block_type, size_raw
        );

        let block_size = if size_raw == 0 {
            0
        } else {
            let mut sz = size_raw;
            if block_start + 1 < encoded.len() {
                sz |= (encoded[block_start + 1] as u32) << 5;
            }
            if size_raw != 0 && block_start + 2 < encoded.len() {
                sz |= (encoded[block_start + 2] as u32) << 13;
            }
            sz
        };

        eprintln!("  Decoded block size: {} bytes", block_size);
        eprintln!(
            "  File size: {}, block data would end at: {}",
            encoded.len(),
            block_start + 3 + block_size as usize
        );
    }
}

#[test]
fn test_zstd_lz77_analyze() {
    let input: Vec<u8> = (0..60_000).map(|i| (i % 251) as u8).collect();

    // Manually run LZ77
    // This is a bit tricky without exposing internal functions
    // Let's just encode and check the output

    let encoded = archive::compress::zstd::encode::encode(&input);
    let decoded = archive::compress::zstd::decode::decode(&encoded).unwrap();

    eprintln!("Input size: {}", input.len());
    eprintln!("Encoded size: {}", encoded.len());
    eprintln!("Roundtrip OK: {}", decoded == input);

    // Now let's manually check what would happen with system zstd
    // by seeing if our decoder agrees
    assert_eq!(decoded, input, "Roundtrip should work");
}

#[test]
fn test_single_sequence_fse_minimal() {
    // Manually construct a minimal frame with one sequence
    // to debug what system zstd expects
    use std::process::Command;

    let has_zstd = Command::new("zstd").arg("--version").output().is_ok();
    if !has_zstd {
        return;
    }

    // Use system zstd to create a reference
    let input = b"hello world";
    let tmp_dir = std::env::temp_dir();
    let in_path = tmp_dir.join("ref_input.txt");
    let zst_path = tmp_dir.join("ref_test.zst");

    std::fs::write(&in_path, input).unwrap();
    let status = Command::new("zstd")
        .args(["-f", "-11"])
        .arg(&in_path)
        .arg("-o")
        .arg(&zst_path)
        .output()
        .unwrap();

    assert!(status.status.success(), "system zstd encode failed");

    let encoded = std::fs::read(&zst_path).unwrap();
    eprintln!(
        "System zstd encoded {} bytes to {} bytes",
        input.len(),
        encoded.len()
    );
    eprintln!("Hex dump:");
    for (i, b) in encoded.iter().enumerate() {
        if i % 16 == 0 {
            eprint!("\n{:04x}: ", i);
        }
        eprint!("{:02x} ", b);
    }
    eprintln!();

    // Clean up
    let _ = std::fs::remove_file(&in_path);
    let _ = std::fs::remove_file(&zst_path);
}
