use super::*;

// ============================================================
// Zstd tests
// ============================================================

/// Decode `encoded` with the system `zstd` binary.
///
/// Returns `None` only when `zstd` is not installed. A present-but-failing
/// tool is a test failure rather than a silent skip.
fn zstd_system_decode_with_args(args: &[&str], encoded: &[u8]) -> Option<Vec<u8>> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = match Command::new("zstd")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if require_external_tools() {
                panic!("required external tool is unavailable: zstd");
            }
            return None;
        }
        Err(error) => panic!("failed to run zstd: {error}"),
    };
    child.stdin.as_mut().unwrap().write_all(encoded).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "system zstd failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(output.stdout)
}

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
    let input = b"Hello, zstd encoding from Rust!";
    let encoded = archive::compress::zstd::encode::encode(input);

    assert_eq!(
        archive::compress::zstd::decode::decode(&encoded).unwrap(),
        input.as_slice()
    );

    let Some(decoded) = zstd_system_decode_with_args(&["-d", "-c"], &encoded) else {
        return;
    };
    assert_eq!(decoded, input);
}

#[test]
fn test_zstd_encode_large_raw_system_compat() {
    let input: Vec<u8> = (0..60_000).map(|i| (i % 251) as u8).collect();
    let encoded = archive::compress::zstd::encode::encode(&input);

    let Some(decoded) = zstd_system_decode_with_args(&["-d", "-c"], &encoded) else {
        return;
    };
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
    let Some(decoded) = zstd_system_decode_with_args(&["-d", "-c"], &encoded) else {
        return;
    };
    assert_eq!(decoded, input);
}

#[test]
fn test_zstd_decode_with_dict_system() {
    use std::process::Command;

    if !command_available("zstd", &["--version"]) {
        return;
    }

    let tmp_dir = unique_temp_dir("zstd_dict_decode");
    let samples_dir = tmp_dir.join("samples");
    std::fs::create_dir_all(&samples_dir).unwrap();

    // Create distinct, sufficiently large training samples.
    let phrases = [
        "the quick brown fox jumps over the lazy dog",
        "a stitch in time saves nine",
        "all that glitters is not gold",
        "actions speak louder than words",
        "the pen is mightier than the sword",
    ];
    for i in 0..10 {
        let content = format!("sample {i} {} ", phrases[i % phrases.len()]).repeat(200);
        std::fs::write(samples_dir.join(format!("sample_{i}.txt")), content).unwrap();
    }

    let dict_path = tmp_dir.join("test.dict");

    // Train dictionary using system zstd
    let train_status = Command::new("zstd")
        .arg("--train")
        .arg(samples_dir.join("*"))
        .args(["--maxdict", "1024"])
        .arg("-o")
        .arg(&dict_path)
        .arg("-r")
        .arg(&samples_dir)
        .output();

    let train_output = train_status.unwrap();
    assert!(
        train_output.status.success(),
        "zstd --train failed: {}",
        String::from_utf8_lossy(&train_output.stderr)
    );

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

    if !command_available("zstd", &["--version"]) {
        return;
    }

    let tmp_dir = unique_temp_dir("zstd_dict_encode");
    let samples_dir = tmp_dir.join("samples");
    std::fs::create_dir_all(&samples_dir).unwrap();

    // Distinct, sufficiently large training samples.
    let phrases = [
        "the quick brown fox jumps over the lazy dog",
        "a stitch in time saves nine",
        "all that glitters is not gold",
        "actions speak louder than words",
        "the pen is mightier than the sword",
    ];
    for i in 0..10 {
        let content = format!("sample {i} {} ", phrases[i % phrases.len()]).repeat(200);
        std::fs::write(samples_dir.join(format!("s{i}.txt")), content).unwrap();
    }

    let dict_path = tmp_dir.join("test.dict");
    let train = Command::new("zstd")
        .arg("--train")
        .args(["--maxdict", "1024"])
        .arg("-o")
        .arg(&dict_path)
        .arg("-r")
        .arg(&samples_dir)
        .output()
        .unwrap();
    assert!(
        train.status.success(),
        "zstd --train failed: {}",
        String::from_utf8_lossy(&train.stderr)
    );

    let dict_data = std::fs::read(&dict_path).unwrap();
    let dict = archive::compress::zstd::decode::ZstdDict::parse(&dict_data).unwrap();

    // Encode with our library using the dictionary
    let test_input =
        b"the quick brown fox jumps over the lazy dog and all that glitters is not gold";
    let encoded = archive::compress::zstd::encode::encode_with_dict(test_input, &dict);

    let dict_arg = dict_path.to_str().unwrap();
    let decoded = zstd_system_decode_with_args(&["-d", "-D", dict_arg, "-c"], &encoded)
        .expect("zstd disappeared after dictionary training");
    let _ = std::fs::remove_dir_all(&tmp_dir);
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
