// ============================================================
// ZIM archive tests
// ============================================================

/// Build a minimal ZIM v5 archive with a single compressed cluster.
fn build_zim(_data: &[u8], compressed_cluster: &[u8], info: u8) -> Vec<u8> {
    let mime = b"text/plain\0\0";
    let mut dirent = Vec::new();
    dirent.extend_from_slice(&0u16.to_le_bytes());
    dirent.push(0);
    dirent.push(b'C');
    dirent.extend_from_slice(&0u32.to_le_bytes());
    dirent.extend_from_slice(&0u32.to_le_bytes());
    dirent.extend_from_slice(&0u32.to_le_bytes());
    dirent.extend_from_slice(b"test.txt");
    dirent.push(0);
    dirent.push(0);

    let dirent_pos = 80 + mime.len();
    let path_ptr_pos = dirent_pos + dirent.len();
    let title_ptr_pos = path_ptr_pos + 8;
    let cluster_ptr_pos = title_ptr_pos + 4;
    let cluster_pos = cluster_ptr_pos + 8;

    let mut cluster = Vec::new();
    cluster.push(info);
    cluster.extend_from_slice(compressed_cluster);
    let checksum_pos = (cluster_pos + cluster.len()) as u64;

    let mut out = Vec::new();
    out.extend_from_slice(&0x044D_495Au32.to_le_bytes());
    out.extend_from_slice(&5u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&[0u8; 16]);
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&(path_ptr_pos as u64).to_le_bytes());
    out.extend_from_slice(&(title_ptr_pos as u64).to_le_bytes());
    out.extend_from_slice(&(cluster_ptr_pos as u64).to_le_bytes());
    out.extend_from_slice(&80u64.to_le_bytes());
    out.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    out.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    out.extend_from_slice(&checksum_pos.to_le_bytes());
    out.extend_from_slice(mime);
    out.extend_from_slice(&dirent);
    out.extend_from_slice(&(dirent_pos as u64).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(cluster_pos as u64).to_le_bytes());
    out.extend_from_slice(&cluster);
    out
}

fn stored_cluster(data: &[u8]) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&8u32.to_le_bytes());
    c.extend_from_slice(&((8 + data.len()) as u32).to_le_bytes());
    c.extend_from_slice(data);
    c
}

#[test]
fn test_zim_decode_stored_cluster() {
    let payload = b"zim integration test";
    let zim = build_zim(payload, &stored_cluster(payload), 1);
    let entries = archive::archive::zim::decode::decode(&zim).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "C/test.txt");
    assert_eq!(entries[0].data, payload);
}

#[test]
fn test_zim_decode_xz_cluster() {
    let payload = b"xz compressed zim blob";
    let plain = stored_cluster(payload);
    let compressed = archive::compress::xz::encode::encode(&plain);
    let zim = build_zim(payload, &compressed, 4);
    let entries = archive::archive::zim::decode::decode(&zim).unwrap();
    assert_eq!(entries[0].data, payload);
}

#[test]
fn test_zim_decode_zstd_cluster() {
    let payload = b"zstd compressed zim blob";
    let plain = stored_cluster(payload);
    let compressed = archive::compress::zstd::encode::encode(&plain);
    let zim = build_zim(payload, &compressed, 5);
    let entries = archive::archive::zim::decode::decode(&zim).unwrap();
    assert_eq!(entries[0].data, payload);
}

#[test]
fn test_zim_rejects_truncated_header() {
    let zim = build_zim(b"x", &stored_cluster(b"x"), 1);
    assert!(archive::archive::zim::decode::decode(&zim[..30]).is_err());
}
