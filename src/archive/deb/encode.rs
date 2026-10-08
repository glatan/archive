//! `.deb` package encoding (deb(5)).
//!
//! Composes a `.deb` from the crate's `ar` + `tar` + codec layers:
//! `debian-binary` (format version), `control.tar<ext>` (package
//! metadata), `data.tar<ext>` (payload), plus any extra members
//! (e.g. signatures) which deb(5) permits after the required ones.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::archive::deb::decode::DebCompression;
use crate::archive::{ar, tar};
use crate::compress::{bzip2, deflate, gzip, lzma_alone, lzw, xz, zstd};
use crate::error::Error;

/// Encoder for `.deb` packages.
///
/// Control/data payloads can be supplied either as file lists
/// (encoded into `tar` members internally) or as ready-made tar
/// bytes via [`DebEncoder::set_control_tar`] /
/// [`DebEncoder::set_data_tar`].
pub struct DebEncoder {
    version: String,
    control_compression: DebCompression,
    data_compression: DebCompression,
    control_files: Vec<(String, Vec<u8>)>,
    data_files: Vec<(String, Vec<u8>)>,
    control_tar: Option<Vec<u8>>,
    data_tar: Option<Vec<u8>>,
    extra_members: Vec<(String, Vec<u8>)>,
}

impl DebEncoder {
    /// New encoder for format version `2.0` with uncompressed
    /// members.
    pub fn new() -> Self {
        DebEncoder {
            version: "2.0".to_string(),
            control_compression: DebCompression::None,
            data_compression: DebCompression::None,
            control_files: Vec::new(),
            data_files: Vec::new(),
            control_tar: None,
            data_tar: None,
            extra_members: Vec::new(),
        }
    }

    /// Set the `debian-binary` format version. Only `2.<num>` is
    /// accepted (deb(5) defines major `2`; a changed major number is an
    /// incompatible format).
    pub fn version(mut self, v: &str) -> Result<Self, Error> {
        if !v.split_once('.').is_some_and(|(a, b)| {
            a == "2" && !b.is_empty() && b.bytes().all(|c| c.is_ascii_digit())
        }) {
            return Err(Error::InvalidData("deb: bad version"));
        }
        self.version = v.to_string();
        Ok(self)
    }

    /// Compress both tar members with `c`.
    pub fn compression(mut self, c: DebCompression) -> Self {
        self.control_compression = c;
        self.data_compression = c;
        self
    }

    /// Compress `control.tar` with `c` (name gains the suffix).
    pub fn control_compression(mut self, c: DebCompression) -> Self {
        self.control_compression = c;
        self
    }

    /// Compress `data.tar` with `c` (name gains the suffix).
    pub fn data_compression(mut self, c: DebCompression) -> Self {
        self.data_compression = c;
        self
    }

    /// Add a file to the control member (encoded into `control.tar`).
    pub fn add_control_file(&mut self, name: &str, data: &[u8]) {
        self.control_files.push((name.to_string(), data.to_vec()));
    }

    /// Add a file to the data member (encoded into `data.tar`).
    pub fn add_data_file(&mut self, name: &str, data: &[u8]) {
        self.data_files.push((name.to_string(), data.to_vec()));
    }

    /// Supply ready-made `control.tar` bytes instead of file lists.
    pub fn set_control_tar(&mut self, tar_bytes: Vec<u8>) {
        self.control_tar = Some(tar_bytes);
    }

    /// Supply ready-made `data.tar` bytes instead of file lists.
    pub fn set_data_tar(&mut self, tar_bytes: Vec<u8>) {
        self.data_tar = Some(tar_bytes);
    }

    /// Add an extra member after the required ones (e.g. a signature
    /// member). Extra members are written in call order.
    pub fn add_extra_member(&mut self, name: &str, data: &[u8]) {
        self.extra_members.push((name.to_string(), data.to_vec()));
    }

    /// Emit the `.deb` bytes.
    pub fn finish(self) -> Result<Vec<u8>, Error> {
        let control = match self.control_tar {
            Some(t) => t,
            None => build_tar(&self.control_files),
        };
        let data = match self.data_tar {
            Some(t) => t,
            None => build_tar(&self.data_files),
        };
        // deb(5): control.tar permits only none/gzip/xz/zstd.
        match self.control_compression {
            DebCompression::None
            | DebCompression::Gzip
            | DebCompression::Xz
            | DebCompression::Zstd => {}
            _ => {
                return Err(Error::InvalidData(
                    "deb: control.tar compression is limited to none/gz/xz/zst",
                ));
            }
        }
        let control = compress(&control, self.control_compression)?;
        let data = compress(&data, self.data_compression)?;

        let mut enc = ar::encode::ArEncoder::new();
        let mut version_line = self.version;
        version_line.push('\n');
        enc.add_file("debian-binary", version_line.as_bytes());
        enc.add_file(
            &alloc::format!("control.tar{}", self.control_compression.extension()),
            &control,
        );
        enc.add_file(
            &alloc::format!("data.tar{}", self.data_compression.extension()),
            &data,
        );
        for (name, bytes) in &self.extra_members {
            enc.add_file(name, bytes);
        }
        enc.finish()
    }
}

impl Default for DebEncoder {
    fn default() -> Self {
        Self::new()
    }
}

fn build_tar(files: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut enc = tar::encode::TarEncoder::new();
    for (name, data) in files {
        enc.add_file(name, data);
    }
    enc.finish()
}

fn compress(data: &[u8], c: DebCompression) -> Result<Vec<u8>, Error> {
    Ok(match c {
        DebCompression::None => data.to_vec(),
        DebCompression::Gzip => gzip::encode::encode(data, deflate::encode::Level::Default),
        DebCompression::Xz => xz::encode::encode(data),
        DebCompression::Zstd => zstd::encode::encode(data),
        DebCompression::Bzip2 => bzip2::encode::encode(data),
        DebCompression::Lzma => lzma_alone::encode::encode(data),
        DebCompression::Lzw => lzw::encode::encode(data),
    })
}

/// Convenience: build a `.deb` from control/data file lists with one
/// compression applied to both tar members.
pub fn encode(
    control_files: &[(&str, &[u8])],
    data_files: &[(&str, &[u8])],
    compression: DebCompression,
) -> Result<Vec<u8>, Error> {
    let mut enc = DebEncoder::new().compression(compression);
    for (n, d) in control_files {
        enc.add_control_file(n, d);
    }
    for (n, d) in data_files {
        enc.add_data_file(n, d);
    }
    enc.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::deb::decode::{self, DebMemberKind};

    #[test]
    fn roundtrip_uncompressed() {
        let deb = encode(
            &[("./control", b"Package: demo\nVersion: 1.0\n")],
            &[("./usr/bin/demo", b"#!/bin/sh\n")],
            DebCompression::None,
        )
        .unwrap();
        let pkg = decode::decode(&deb).unwrap();
        assert_eq!(pkg.version, "2.0");
        assert_eq!(pkg.members.len(), 3);
        let c = pkg.control_entries().unwrap();
        assert_eq!(c[0].header.name, "./control");
        let d = pkg.data_entries().unwrap();
        assert_eq!(d[0].data, b"#!/bin/sh\n");
    }

    #[test]
    fn roundtrip_compressed_members() {
        // Permitted for both members per deb(5): none/gz/xz/zst.
        for c in [
            DebCompression::Gzip,
            DebCompression::Xz,
            DebCompression::Zstd,
        ] {
            let deb = encode(&[("./control", b"Package: p\n")], &[("./f", b"payload")], c)
                .unwrap_or_else(|e| panic!("encode failed for {c:?}: {e}"));
            let pkg = decode::decode(&deb).unwrap_or_else(|e| panic!("decode {c:?}: {e}"));
            let dm = pkg.data_member().unwrap();
            assert_eq!(dm.compression, Some(c));
            assert_eq!(dm.name, alloc::format!("data.tar{}", c.extension()));
            assert_eq!(pkg.data_entries().unwrap()[0].data, b"payload");
        }
        // data.tar-only compressions per deb(5): bz2/lzma
        // (`.Z`/lzw is a legacy extension supported by neither list).
        for c in [
            DebCompression::Bzip2,
            DebCompression::Lzma,
            DebCompression::Lzw,
        ] {
            let mut enc = DebEncoder::new().data_compression(c);
            enc.add_control_file("./control", b"Package: p\n");
            enc.add_data_file("./f", b"payload");
            let pkg = decode::decode(&enc.finish().unwrap())
                .unwrap_or_else(|e| panic!("decode {c:?}: {e}"));
            let dm = pkg.data_member().unwrap();
            assert_eq!(dm.compression, Some(c));
            assert_eq!(pkg.data_entries().unwrap()[0].data, b"payload");
        }
    }

    #[test]
    fn separate_compressions() {
        let mut enc = DebEncoder::new()
            .control_compression(DebCompression::None)
            .data_compression(DebCompression::Gzip);
        enc.add_control_file("./control", b"Package: p\n");
        enc.add_data_file("./f", b"x");
        let pkg = decode::decode(&enc.finish().unwrap()).unwrap();
        assert_eq!(
            pkg.control_member().unwrap().compression,
            Some(DebCompression::None)
        );
        assert_eq!(
            pkg.data_member().unwrap().compression,
            Some(DebCompression::Gzip)
        );
    }

    #[test]
    fn raw_tar_and_extra_members() {
        let control_tar = build_tar(&[("./control".into(), b"Package: p\n".to_vec())]);
        let data_tar = build_tar(&[("./f".into(), b"y".to_vec())]);
        let mut enc = DebEncoder::new();
        enc.set_control_tar(control_tar);
        enc.set_data_tar(data_tar);
        enc.add_extra_member("_gpgorigin", b"sig-bytes");
        let pkg = decode::decode(&enc.finish().unwrap()).unwrap();
        assert_eq!(pkg.members.len(), 4);
        assert_eq!(pkg.members[3].kind, DebMemberKind::Other);
        assert_eq!(pkg.members[3].name, "_gpgorigin");
        assert_eq!(pkg.data_entries().unwrap()[0].data, b"y");
    }

    #[test]
    fn version_validation() {
        assert!(DebEncoder::new().version("2.0").is_ok());
        assert!(DebEncoder::new().version("3.1").is_err());
        assert!(DebEncoder::new().version("2").is_err());
        assert!(DebEncoder::new().version("x.y").is_err());
        assert!(DebEncoder::new().version("").is_err());
        assert!(DebEncoder::new().version("2.0.1").is_err());

        let pkg =
            decode::decode(&DebEncoder::new().version("2.1").unwrap().finish().unwrap()).unwrap();
        assert_eq!(pkg.version, "2.1");
    }

    #[test]
    fn control_tar_compression_restricted() {
        // deb(5): control.tar permits only none/gz/xz/zst.
        assert!(
            DebEncoder::new()
                .control_compression(DebCompression::Bzip2)
                .finish()
                .is_err()
        );
        assert!(
            DebEncoder::new()
                .control_compression(DebCompression::Zstd)
                .finish()
                .is_ok()
        );
    }
}
