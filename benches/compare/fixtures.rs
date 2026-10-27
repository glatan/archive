//! Generated benchmark fixtures for read-only formats.
//!
//! These files are written under `target/bench/fixtures` at startup so the
//! repository does not need to carry binary fixtures that are only used by
//! the benchmark harness.

use std::fs;
use std::path::Path;

use archive::archive;

pub const DEB: &str = "target/bench/fixtures/bench.deb";
pub const RPM: &str = "target/bench/fixtures/bench.rpm";
pub const MTREE: &str = "target/bench/fixtures/bench.mtree";
pub const WARC: &str = "target/bench/fixtures/bench.warc";
pub const ZIM: &str = "target/bench/fixtures/bench.zim";
pub const SQUASHFS: &str = "target/bench/fixtures/bench.sqfs";
pub const CRAMFS: &str = "target/bench/fixtures/bench.cramfs";
pub const PEA: &str = "target/bench/fixtures/bench.pea";
pub const MSCFB: &str = "target/bench/fixtures/bench.cfb";
pub const CRX3: &str = "target/bench/fixtures/bench.crx";

const TEXT: &[u8] = b"benchmark fixture payload\n";
const EMPTY: &[u8] = b"";

pub fn ensure() -> Result<(), String> {
    let dir = Path::new("target/bench/fixtures");
    fs::create_dir_all(dir).map_err(|error| format!("create fixture dir: {error}"))?;
    write(DEB, build_deb()?)?;
    write(RPM, build_rpm()?)?;
    write(MTREE, build_mtree())?;
    write(WARC, build_warc())?;
    write(ZIM, build_zim()?)?;
    write(SQUASHFS, build_squashfs()?)?;
    write(CRAMFS, build_cramfs()?)?;
    write(PEA, build_pea()?)?;
    write(MSCFB, build_mscfb()?)?;
    write(CRX3, build_crx3()?)?;
    Ok(())
}

fn write(path: &str, bytes: impl AsRef<[u8]>) -> Result<(), String> {
    fs::write(path, bytes.as_ref()).map_err(|error| format!("write {path}: {error}"))
}

fn build_deb() -> Result<Vec<u8>, String> {
    let mut enc = archive::deb::encode::DebEncoder::new();
    enc.add_control_file(
        "control",
        b"Package: bench\nVersion: 1.0\nArchitecture: all\nMaintainer: bench\n",
    );
    enc.add_data_file("usr/share/bench/file.txt", TEXT);
    enc.add_data_file("usr/share/bench/empty", EMPTY);
    enc.finish()
        .map_err(|error| format!("build deb fixture: {error}"))
}

fn build_rpm() -> Result<Vec<u8>, String> {
    let mut enc = archive::rpm::encode::RpmEncoder::new()
        .lead_name("bench-1.0-1")
        .map_err(|error| format!("build rpm fixture: {error}"))?
        .name("bench")
        .version("1.0")
        .release("1")
        .arch("x86_64");
    enc.add_file("usr/share/bench/file.txt", TEXT);
    enc.add_file("usr/share/bench/empty", EMPTY);
    enc.finish()
        .map_err(|error| format!("build rpm fixture: {error}"))
}

fn build_mtree() -> Vec<u8> {
    b"#mtree\n\
/set type=file uid=0 gid=0 mode=644\n\
./file.txt size=25\n\
./dir type=dir mode=755\n\
./dir/inner.txt size=0\n\
..\n"
        .to_vec()
}

fn build_warc() -> Vec<u8> {
    b"WARC/1.0\r\n\
WARC-Type: warcinfo\r\n\
WARC-Record-ID: <urn:uuid:bench-warcinfo>\r\n\
WARC-Date: 2026-01-01T00:00:00Z\r\n\
Content-Type: application/warc-fields\r\n\
Content-Length: 25\r\n\
\r\n\
software: archive-bench\r\n\
\r\n\
WARC/1.0\r\n\
WARC-Type: response\r\n\
WARC-Record-ID: <urn:uuid:bench-response>\r\n\
WARC-Target-URI: http://example.org/bench\r\n\
WARC-Date: 2026-01-01T00:00:00Z\r\n\
Content-Type: application/http;msgtype=response\r\n\
Content-Length: 5\r\n\
\r\n\
hello\r\n\
\r\n"
        .to_vec()
}

fn build_zim() -> Result<Vec<u8>, String> {
    let mut enc = archive::zim::encode::ZimEncoder::with_compression(
        archive::zim::encode::ZimCompression::Zstd,
    );
    enc.add_file("C/index.html", b"<html><body>bench</body></html>");
    enc.add_file("C/file.txt", TEXT);
    enc.finish()
        .map_err(|error| format!("build zim fixture: {error}"))
}

fn build_squashfs() -> Result<Vec<u8>, String> {
    let mut enc = archive::squashfs::encode::SquashfsEncoder::new();
    enc.add_file("file.txt", TEXT);
    enc.add_file("empty", EMPTY);
    enc.finish()
        .map_err(|error| format!("build squashfs fixture: {error}"))
}

fn build_cramfs() -> Result<Vec<u8>, String> {
    let mut enc = archive::cramfs::encode::CramfsEncoder::new();
    enc.add_file("file.txt", TEXT);
    enc.add_file("empty", EMPTY);
    enc.finish()
        .map_err(|error| format!("build cramfs fixture: {error}"))
}

fn build_pea() -> Result<Vec<u8>, String> {
    let mut enc = archive::pea::encode::PeaEncoder::new();
    enc.add_file("file.txt", TEXT);
    enc.add_file("empty", EMPTY);
    enc.finish()
        .map_err(|error| format!("build pea fixture: {error}"))
}

fn varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

fn length_field(field: u64, data: &[u8]) -> Vec<u8> {
    let mut out = varint((field << 3) | 2);
    out.extend_from_slice(&varint(data.len() as u64));
    out.extend_from_slice(data);
    out
}

fn build_crx3() -> Result<Vec<u8>, String> {
    let mut zip = archive::zip::encode::ZipEncoder::new();
    zip.add_file("manifest.json", b"{\"manifest_version\":3}");
    zip.add_file("js/worker.js", TEXT);
    let zip = zip
        .finish()
        .map_err(|error| format!("build crx3 zip: {error}"))?;

    let mut proof = length_field(1, b"PUBKEY-DER-BYTES");
    proof.extend_from_slice(&length_field(2, b"SIGNATURE-BYTES"));
    let signed = length_field(1, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    let mut header = length_field(2, &proof);
    header.extend_from_slice(&length_field(10000, &signed));

    let mut out = b"Cr24".to_vec();
    out.extend_from_slice(&3u32.to_le_bytes());
    out.extend_from_slice(&(header.len() as u32).to_le_bytes());
    out.extend_from_slice(&header);
    out.extend_from_slice(&zip);
    Ok(out)
}

fn build_mscfb() -> Result<Vec<u8>, String> {
    let mut enc = archive::mscfb::encode::CfbEncoder::new();
    enc.add_stream("Storage/file.txt", TEXT);
    enc.add_stream("Storage/empty", EMPTY);
    enc.finish()
        .map_err(|error| format!("build mscfb fixture: {error}"))
}
