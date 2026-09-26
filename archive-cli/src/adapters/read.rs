use std::path::Path;

use ::archive::archive as archive_formats;
use ::archive::archive::cpio::header::CpioHeader;
use ::archive::archive::tar::header::FileType as TarFileType;
use ::archive::compress as compress_formats;

use crate::detect::{ContentKind, Format, checksum_verified_by_default, scope_notes};
use crate::error::CliError;
use crate::output::{EntrySummary, InspectReport};

const MAX_LIST_NESTING: usize = 8;

pub struct Analysis {
    pub kind: ContentKind,
    pub entries: Vec<EntrySummary>,
    pub warnings: Vec<String>,
    pub notes: Vec<String>,
    pub verified_checksums: bool,
}

#[derive(Debug, Clone)]
struct DecodedItem {
    summary: EntrySummary,
    payload: Option<Vec<u8>>,
}

pub fn inspect_path(
    path: &Path,
    format: Format,
    password: Option<&str>,
) -> Result<InspectReport, CliError> {
    let input = std::fs::read(path)?;
    let analysis = analyze_bytes(path, &input, format, password)?;
    Ok(InspectReport {
        detected_format: format,
        kind: analysis.kind,
        entry_count: Some(analysis.entries.len()),
        warnings: analysis.warnings,
        notes: analysis.notes,
        entries: analysis.entries,
    })
}

pub fn list_bytes(
    path: &Path,
    input: &[u8],
    format: Format,
    password: Option<&str>,
) -> Result<InspectReport, CliError> {
    let mut notes = scope_notes(format);
    notes.push(format!(
        "nested list traversal descends into supported embedded payloads up to depth {MAX_LIST_NESTING}"
    ));
    let (kind, items) = decode_items(path, input, format, password)?;
    let mut entries = Vec::new();
    flatten_list_items(&mut entries, items, password, 0, None);
    Ok(InspectReport {
        detected_format: format,
        kind,
        entry_count: Some(entries.len()),
        warnings: Vec::new(),
        notes,
        entries,
    })
}

pub fn analyze_bytes(
    path: &Path,
    input: &[u8],
    format: Format,
    password: Option<&str>,
) -> Result<Analysis, CliError> {
    let (kind, items) = decode_items(path, input, format, password)?;
    let mut notes = scope_notes(format);
    if matches!(format, Format::Snappy) {
        notes.push(
            "snappy auto-detection is limited; use --format snappy when the stream lacks an obvious framed signature".to_owned(),
        );
    }
    if matches!(format, Format::Brotli) {
        notes.push(
            "brotli has no stable magic header; auto-detection normally requires --format brotli"
                .to_owned(),
        );
    }
    if matches!(format, Format::Deflate) {
        notes.push(
            "raw deflate has no container header; auto-detection normally requires --format deflate"
                .to_owned(),
        );
    }
    if matches!(format, Format::LzmaAlone) {
        notes.push(
            "lzma-alone streams have no magic signature; auto-detection normally requires --format lzma"
                .to_owned(),
        );
    }
    if matches!(format, Format::Xpress | Format::XpressHuff | Format::Lznt1) {
        notes.push(
            "MS-XCA streams have no magic signature; auto-detection normally requires --format xpress, xpress-huff, or lznt1"
                .to_owned(),
        );
    }

    Ok(Analysis {
        kind,
        entries: items.into_iter().map(|item| item.summary).collect(),
        warnings: Vec::new(),
        notes,
        verified_checksums: checksum_verified_by_default(format),
    })
}

fn decode_items(
    path: &Path,
    input: &[u8],
    format: Format,
    password: Option<&str>,
) -> Result<(ContentKind, Vec<DecodedItem>), CliError> {
    let password_provided = password.is_some();
    match format {
        Format::Tar => {
            let entries = archive_formats::tar::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?;
            Ok((
                ContentKind::Archive,
                entries
                    .into_iter()
                    .map(|entry| DecodedItem {
                        payload: matches!(
                            entry.header.file_type,
                            TarFileType::Regular | TarFileType::GnuSparse
                        )
                        .then_some(entry.data.clone()),
                        summary: EntrySummary {
                            path: entry.header.name,
                            kind: tar_kind(entry.header.file_type),
                            size: Some(entry.header.size),
                            compressed_size: None,
                            mtime: Some(entry.header.mtime),
                            mode: Some(entry.header.mode),
                            extra: Vec::new(),
                        },
                    })
                    .collect(),
            ))
        }
        Format::Cpio => {
            let entries = archive_formats::cpio::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?;
            Ok((
                ContentKind::Archive,
                entries
                    .into_iter()
                    .map(|entry| {
                        let payload = (!entry.header.is_directory()).then_some(entry.data.clone());
                        DecodedItem {
                            payload,
                            summary: EntrySummary {
                                path: entry.name,
                                kind: cpio_kind(&entry.header),
                                size: Some(u64::from(entry.header.filesize)),
                                compressed_size: None,
                                mtime: Some(i64::from(entry.header.mtime)),
                                mode: Some(entry.header.mode),
                                extra: if entry.header.is_crc {
                                    vec!["newcrc checksum".to_owned()]
                                } else {
                                    Vec::new()
                                },
                            },
                        }
                    })
                    .collect(),
            ))
        }
        Format::Ar => {
            let entries = archive_formats::ar::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?;
            Ok((
                ContentKind::Archive,
                entries
                    .into_iter()
                    .map(|entry| DecodedItem {
                        payload: Some(entry.data.clone()),
                        summary: EntrySummary {
                            path: entry.name,
                            kind: "file".to_owned(),
                            size: Some(entry.header.size),
                            compressed_size: None,
                            mtime: Some(entry.header.mtime as i64),
                            mode: Some(entry.header.mode),
                            extra: Vec::new(),
                        },
                    })
                    .collect(),
            ))
        }
        Format::Deb => {
            let package = archive_formats::deb::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?;
            let version = package.version.clone();
            Ok((
                ContentKind::Archive,
                package
                    .members
                    .into_iter()
                    .map(|member| {
                        let mut extra = vec![
                            format!("deb-version={version}"),
                            format!("deb-member={:?}", member.kind),
                        ];
                        if let Some(compression) = member.compression {
                            extra.push(format!("compression={:?}", compression));
                        }
                        DecodedItem {
                            payload: Some(member.data.clone()),
                            summary: EntrySummary {
                                path: member.name,
                                kind: "file".to_owned(),
                                size: Some(member.header.size),
                                compressed_size: None,
                                mtime: Some(member.header.mtime as i64),
                                mode: Some(member.header.mode),
                                extra,
                            },
                        }
                    })
                    .collect(),
            ))
        }
        Format::Rpm => {
            let package = archive_formats::rpm::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?;
            let name = package.name().transpose().ok().flatten();
            let version = package.version().transpose().ok().flatten();
            let entries = package
                .payload_entries()
                .map_err(|error| CliError::from_archive_error(error, password_provided))?;
            Ok((
                ContentKind::Archive,
                entries
                    .into_iter()
                    .map(|entry| {
                        let mut extra = Vec::new();
                        if let (Some(name), Some(version)) = (&name, &version) {
                            extra.push(format!("rpm={name}-{version}"));
                        }
                        if let Some(fx) = entry.file_index {
                            extra.push(format!("rpm-file-index={fx}"));
                        }
                        DecodedItem {
                            payload: Some(entry.data.clone()),
                            summary: EntrySummary {
                                path: entry.name,
                                kind: "file".to_owned(),
                                size: Some(entry.data.len() as u64),
                                compressed_size: None,
                                mtime: None,
                                mode: None,
                                extra,
                            },
                        }
                    })
                    .collect(),
            ))
        }
        Format::Squashfs => {
            let image = archive_formats::squashfs::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?;
            Ok((
                ContentKind::Archive,
                image
                    .entries
                    .into_iter()
                    .map(|entry| DecodedItem {
                        payload: Some(entry.data.clone()),
                        summary: EntrySummary {
                            path: entry.name,
                            kind: format!("{:?}", entry.kind).to_lowercase(),
                            size: Some(entry.data.len() as u64),
                            compressed_size: None,
                            mtime: Some(entry.mtime as i64),
                            mode: Some(u32::from(entry.mode)),
                            extra: Vec::new(),
                        },
                    })
                    .collect(),
            ))
        }
        Format::Mscab => {
            let entries = archive_formats::mscab::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?;
            Ok((
                ContentKind::Archive,
                entries
                    .into_iter()
                    .map(|entry| DecodedItem {
                        payload: Some(entry.data.clone()),
                        summary: EntrySummary {
                            path: entry.name,
                            kind: "file".to_owned(),
                            size: Some(entry.data.len() as u64),
                            compressed_size: None,
                            mtime: None,
                            mode: None,
                            extra: Vec::new(),
                        },
                    })
                    .collect(),
            ))
        }
        Format::Zim => {
            let entries = archive_formats::zim::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?;
            Ok((
                ContentKind::Archive,
                entries
                    .into_iter()
                    .map(|entry| DecodedItem {
                        payload: Some(entry.data.clone()),
                        summary: EntrySummary {
                            path: entry.name,
                            kind: "file".to_owned(),
                            size: Some(entry.data.len() as u64),
                            compressed_size: None,
                            mtime: None,
                            mode: None,
                            extra: Vec::new(),
                        },
                    })
                    .collect(),
            ))
        }
        Format::Mtree => {
            let entries = archive_formats::mtree::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?;
            Ok((
                ContentKind::Archive,
                entries
                    .into_iter()
                    .map(|entry| {
                        let mut extra = Vec::new();
                        if let Some(mode) = entry.mode {
                            extra.push(format!("mode={mode:o}"));
                        }
                        if let Some(link) = &entry.link {
                            extra.push(format!("link={link}"));
                        }
                        DecodedItem {
                            payload: None,
                            summary: EntrySummary {
                                path: entry.name,
                                kind: format!("{:?}", entry.kind).to_lowercase(),
                                size: entry.size,
                                compressed_size: None,
                                mtime: None,
                                mode: entry.mode,
                                extra,
                            },
                        }
                    })
                    .collect(),
            ))
        }
        Format::Warc => {
            let entries = archive_formats::warc::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?;
            Ok((
                ContentKind::Archive,
                entries
                    .into_iter()
                    .map(|entry| {
                        let mut extra = vec![format!("warc-type={}", entry.record_type)];
                        if let Some(ct) = &entry.content_type {
                            extra.push(format!("content-type={ct}"));
                        }
                        DecodedItem {
                            payload: Some(entry.data.clone()),
                            summary: EntrySummary {
                                path: entry.name,
                                kind: "file".to_owned(),
                                size: Some(entry.data.len() as u64),
                                compressed_size: None,
                                mtime: None,
                                mode: None,
                                extra,
                            },
                        }
                    })
                    .collect(),
            ))
        }
        Format::Zpaq => match archive_formats::zpaq::decode::decode(input) {
            Ok(entries) => Ok((
                ContentKind::Archive,
                entries
                    .into_iter()
                    .map(|entry| DecodedItem {
                        payload: Some(entry.data.clone()),
                        summary: EntrySummary {
                            path: entry
                                .filename_utf8()
                                .map_or_else(|| "<non-utf8>".to_owned(), ToOwned::to_owned),
                            kind: "file".to_owned(),
                            size: Some(entry.data.len() as u64),
                            compressed_size: None,
                            mtime: None,
                            mode: None,
                            extra: entry
                                .comment_utf8()
                                .map(|comment| vec![format!("comment={comment}")])
                                .unwrap_or_default(),
                        },
                    })
                    .collect(),
            )),
            Err(_) => {
                let payload = compress_formats::zpaq::decode::decode(input)
                    .map_err(|error| CliError::from_archive_error(error, password_provided))?;
                Ok((
                    ContentKind::Compression,
                    vec![DecodedItem {
                        summary: single_payload_entry(
                            path,
                            input.len() as u64,
                            payload.len() as u64,
                        ),
                        payload: Some(payload),
                    }],
                ))
            }
        },
        Format::Zip => {
            let entries = if let Some(password) = password {
                archive_formats::zip::decode::decode_with_password(input, password)
            } else {
                archive_formats::zip::decode::decode(input)
            }
            .map_err(|error| CliError::from_archive_error(error, password_provided))?;
            Ok((
                ContentKind::Archive,
                entries
                    .into_iter()
                    .map(|entry| DecodedItem {
                        payload: Some(entry.data.clone()),
                        summary: EntrySummary {
                            path: entry.name,
                            kind: "file".to_owned(),
                            size: Some(entry.header.uncompressed_size),
                            compressed_size: Some(entry.header.compressed_size),
                            mtime: None,
                            mode: None,
                            extra: vec![format!("method={}", entry.header.compression_method)],
                        },
                    })
                    .collect(),
            ))
        }
        Format::SevenZ => {
            let entries = if let Some(password) = password {
                archive_formats::sevenz::decode::decode_with_password(input, password)
            } else {
                archive_formats::sevenz::decode::decode(input)
            }
            .map_err(|error| CliError::from_archive_error(error, password_provided))?;
            Ok((
                ContentKind::Archive,
                entries
                    .into_iter()
                    .map(|entry| DecodedItem {
                        payload: Some(entry.data.clone()),
                        summary: EntrySummary {
                            path: entry.name,
                            kind: "file".to_owned(),
                            size: Some(entry.data.len() as u64),
                            compressed_size: None,
                            mtime: None,
                            mode: entry.attributes,
                            extra: entry
                                .crc32
                                .map(|crc| vec![format!("crc32={crc:#010x}")])
                                .unwrap_or_default(),
                        },
                    })
                    .collect(),
            ))
        }
        Format::Gzip => decode_single_payload(
            path,
            input,
            compress_formats::gzip::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Zstd => decode_single_payload(
            path,
            input,
            compress_formats::zstd::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Bzip2 => decode_single_payload(
            path,
            input,
            compress_formats::bzip2::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Lzip => decode_single_payload(
            path,
            input,
            compress_formats::lzip::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::LzmaAlone => decode_single_payload(
            path,
            input,
            compress_formats::lzma_alone::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Lzw => decode_single_payload(
            path,
            input,
            compress_formats::lzw::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Lz4 => decode_single_payload(
            path,
            input,
            compress_formats::lz4::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Lzo => decode_single_payload(
            path,
            input,
            compress_formats::lzo::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Lrzip => decode_single_payload(
            path,
            input,
            compress_formats::lrzip::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Rzip => decode_single_payload(
            path,
            input,
            compress_formats::rzip::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Zlib => decode_single_payload(
            path,
            input,
            compress_formats::zlib::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Snappy => decode_single_payload(
            path,
            input,
            compress_formats::snappy::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Brotli => decode_single_payload(
            path,
            input,
            compress_formats::brotli::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Deflate => decode_single_payload(
            path,
            input,
            compress_formats::deflate::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Xpress => decode_single_payload(
            path,
            input,
            compress_formats::xca::lz77::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::XpressHuff => decode_single_payload(
            path,
            input,
            compress_formats::xca::huffman::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Lznt1 => decode_single_payload(
            path,
            input,
            compress_formats::xca::lznt1::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Lzf => decode_single_payload(
            path,
            input,
            compress_formats::lzf::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Fastlz => decode_single_payload(
            path,
            input,
            compress_formats::fastlz::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Lzsa => decode_single_payload(
            path,
            input,
            compress_formats::lzsa::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Zx0 => decode_single_payload(
            path,
            input,
            compress_formats::zx0::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Lzxd => decode_single_payload(
            path,
            input,
            compress_formats::lzxd::decode_all(input, 1 << 25, &[], usize::MAX)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Cmpsc => decode_single_payload(
            path,
            input,
            compress_formats::cmpsc::decode(input, usize::MAX)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Lzrw1a => decode_single_payload(
            path,
            input,
            compress_formats::lzrw1a::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Xz => decode_single_payload(
            path,
            input,
            compress_formats::xz::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
    }
}

fn decode_single_payload(
    path: &Path,
    input: &[u8],
    payload: Vec<u8>,
) -> Result<(ContentKind, Vec<DecodedItem>), CliError> {
    Ok((
        ContentKind::Compression,
        vec![DecodedItem {
            summary: single_payload_entry(path, input.len() as u64, payload.len() as u64),
            payload: Some(payload),
        }],
    ))
}

fn flatten_list_items(
    out: &mut Vec<EntrySummary>,
    items: Vec<DecodedItem>,
    password: Option<&str>,
    depth: usize,
    prefix: Option<&str>,
) {
    for item in items {
        let full_path = prefix
            .map(|prefix| format!("{prefix}!/{}", item.summary.path))
            .unwrap_or_else(|| item.summary.path.clone());
        let mut summary = item.summary;
        summary.path = full_path.clone();

        let nested = if depth < MAX_LIST_NESTING {
            item.payload.as_ref().and_then(|payload| {
                crate::detect::detect_format(payload).and_then(|nested_format| {
                    decode_items(Path::new(&full_path), payload, nested_format, password)
                        .ok()
                        .map(|(_, nested_items)| (nested_format, nested_items))
                })
            })
        } else {
            None
        };

        if let Some((nested_format, nested_items)) = nested {
            summary.extra.push(format!("nested-format={nested_format}"));
            out.push(summary);
            flatten_list_items(out, nested_items, password, depth + 1, Some(&full_path));
        } else {
            out.push(summary);
        }
    }
}

fn single_payload_entry(path: &Path, compressed_size: u64, size: u64) -> EntrySummary {
    EntrySummary {
        path: path.file_name().map_or_else(
            || "<stdin>".to_owned(),
            |name| name.to_string_lossy().into_owned(),
        ),
        kind: "file".to_owned(),
        size: Some(size),
        compressed_size: Some(compressed_size),
        mtime: None,
        mode: None,
        extra: Vec::new(),
    }
}

fn tar_kind(file_type: TarFileType) -> String {
    match file_type {
        TarFileType::Regular => "file",
        TarFileType::HardLink => "hardlink",
        TarFileType::SymLink => "symlink",
        TarFileType::CharDevice => "char-device",
        TarFileType::BlockDevice => "block-device",
        TarFileType::Directory => "directory",
        TarFileType::Fifo => "fifo",
        TarFileType::Contiguous => "contiguous",
        TarFileType::PaxHeader => "pax-header",
        TarFileType::PaxGlobalHeader => "pax-global-header",
        TarFileType::GnuLongName => "gnu-long-name",
        TarFileType::GnuLongLink => "gnu-long-link",
        TarFileType::GnuSparse => "gnu-sparse",
        TarFileType::Other(_) => "other",
    }
    .to_owned()
}

fn cpio_kind(header: &CpioHeader) -> String {
    if header.is_directory() {
        "directory".to_owned()
    } else if header.is_symlink() {
        "symlink".to_owned()
    } else {
        "file".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::list_bytes;
    use crate::detect::Format;
    use ::archive::archive::tar::encode::TarEncoder;
    use ::archive::compress::deflate::encode::Level;
    use ::archive::compress::gzip::encode;
    use std::path::Path;

    #[test]
    fn list_bytes_descends_into_gzip_wrapped_tar() {
        let mut tar = TarEncoder::new();
        tar.add_file("dir/hello.txt", b"hello");
        let tar_bytes = tar.finish();
        let gz_bytes = encode::encode(&tar_bytes, Level::Default);

        let report = list_bytes(Path::new("sample.tar.gz"), &gz_bytes, Format::Gzip, None).unwrap();
        let paths: Vec<_> = report.entries.into_iter().map(|entry| entry.path).collect();
        assert!(paths.contains(&"sample.tar.gz".to_owned()));
        assert!(paths.contains(&"sample.tar.gz!/dir/hello.txt".to_owned()));
    }
}
