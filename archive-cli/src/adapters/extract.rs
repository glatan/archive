use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use ::archive::archive as archive_formats;
use ::archive::archive::cpio::decode::CpioEntry;
use ::archive::archive::tar::decode::TarEntry;
use ::archive::archive::tar::header::FileType as TarFileType;
use ::archive::compress as compress_formats;

use crate::detect::Format;
use crate::error::CliError;

pub fn extract_input(
    input_path: &Path,
    input: &[u8],
    format: Format,
    password: Option<&str>,
    out_dir: Option<&Path>,
    selected_paths: &[String],
    overwrite: bool,
) -> Result<(), CliError> {
    let base_dir = resolve_base_dir(out_dir)?;
    fs::create_dir_all(&base_dir)?;
    let password_provided = password.is_some();

    match format {
        Format::Tar => {
            let entries = archive_formats::tar::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?;
            extract_tar_entries(&base_dir, entries, selected_paths, overwrite)
        }
        Format::Cpio => {
            let entries = archive_formats::cpio::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?;
            extract_cpio_entries(&base_dir, entries, selected_paths, overwrite)
        }
        Format::Ar => {
            let entries = archive_formats::ar::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?;
            let requested = RequestedPaths::new(selected_paths);
            for entry in entries {
                if !requested.matches(&entry.name) {
                    continue;
                }
                let path = resolved_archive_path(&base_dir, &entry.name)?;
                write_file(&path, &entry.data, overwrite)?;
                requested.mark_matched(&entry.name);
            }
            requested.finish()
        }
        Format::Deb => {
            let package = archive_formats::deb::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?;
            let entries = package
                .data_entries()
                .map_err(|error| CliError::from_archive_error(error, password_provided))?;
            extract_tar_entries(&base_dir, entries, selected_paths, overwrite)
        }
        Format::Rpm => {
            let entries = archive_formats::rpm::decode::decode(input)
                .and_then(|package| package.payload_entries())
                .map_err(|error| CliError::from_archive_error(error, password_provided))?;
            let requested = RequestedPaths::new(selected_paths);
            for entry in entries {
                if !requested.matches(&entry.name) {
                    continue;
                }
                let path = resolved_archive_path(&base_dir, &entry.name)?;
                write_file(&path, &entry.data, overwrite)?;
                requested.mark_matched(&entry.name);
            }
            requested.finish()
        }
        Format::Squashfs => {
            let entries = archive_formats::squashfs::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?
                .entries;
            let requested = RequestedPaths::new(selected_paths);
            for entry in entries {
                if entry.kind != archive_formats::squashfs::decode::SquashfsKind::File {
                    continue;
                }
                if !requested.matches(&entry.name) {
                    continue;
                }
                let path = resolved_archive_path(&base_dir, &entry.name)?;
                write_file(&path, &entry.data, overwrite)?;
                requested.mark_matched(&entry.name);
            }
            requested.finish()
        }
        Format::Mscab => {
            let entries = archive_formats::mscab::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?;
            let requested = RequestedPaths::new(selected_paths);
            for entry in entries {
                if !requested.matches(&entry.name) {
                    continue;
                }
                let path = resolved_archive_path(&base_dir, &entry.name)?;
                write_file(&path, &entry.data, overwrite)?;
                requested.mark_matched(&entry.name);
            }
            requested.finish()
        }
        Format::Zim => {
            let entries = archive_formats::zim::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?;
            let requested = RequestedPaths::new(selected_paths);
            for entry in entries {
                if !requested.matches(&entry.name) {
                    continue;
                }
                let path = resolved_archive_path(&base_dir, &entry.name)?;
                write_file(&path, &entry.data, overwrite)?;
                requested.mark_matched(&entry.name);
            }
            requested.finish()
        }
        Format::Mtree => Err(CliError::Unsupported(
            "mtree is a manifest format and carries no file content".to_owned(),
        )),
        Format::Xar => {
            let entries = archive_formats::xar::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?;
            let requested = RequestedPaths::new(selected_paths);
            for entry in entries {
                if entry.is_dir {
                    continue;
                }
                if !requested.matches(&entry.name) {
                    continue;
                }
                let path = resolved_archive_path(&base_dir, &entry.name)?;
                write_file(&path, &entry.data, overwrite)?;
                requested.mark_matched(&entry.name);
            }
            requested.finish()
        }
        Format::GitPack => {
            let entries = archive_formats::git_pack::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?;
            let requested = RequestedPaths::new(selected_paths);
            for entry in entries {
                use archive::traits::ArchiveEntry;
                if !requested.matches(entry.name()) {
                    continue;
                }
                let path = resolved_archive_path(&base_dir, entry.name())?;
                write_file(&path, entry.data(), overwrite)?;
                requested.mark_matched(entry.name());
            }
            requested.finish()
        }
        Format::Warc => {
            let entries = archive_formats::warc::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?;
            let requested = RequestedPaths::new(selected_paths);
            for entry in entries {
                if !requested.matches(&entry.name) {
                    continue;
                }
                let path = resolved_archive_path(&base_dir, &entry.name)?;
                write_file(&path, &entry.data, overwrite)?;
                requested.mark_matched(&entry.name);
            }
            requested.finish()
        }
        Format::Lha => {
            let entries = archive_formats::lha::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?;
            let requested = RequestedPaths::new(selected_paths);
            for entry in entries {
                if entry.is_dir || !requested.matches(&entry.name) {
                    continue;
                }
                let path = resolved_archive_path(&base_dir, &entry.name)?;
                write_file(&path, &entry.data, overwrite)?;
                requested.mark_matched(&entry.name);
            }
            requested.finish()
        }
        Format::Arj => {
            let entries = archive_formats::arj::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?;
            let requested = RequestedPaths::new(selected_paths);
            for entry in entries {
                if entry.is_dir || !requested.matches(&entry.name) {
                    continue;
                }
                let path = resolved_archive_path(&base_dir, &entry.name)?;
                write_file(&path, &entry.data, overwrite)?;
                requested.mark_matched(&entry.name);
            }
            requested.finish()
        }
        Format::Arc => {
            let entries = archive_formats::arc::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?;
            let requested = RequestedPaths::new(selected_paths);
            for entry in entries {
                if !requested.matches(&entry.name) {
                    continue;
                }
                let path = resolved_archive_path(&base_dir, &entry.name)?;
                write_file(&path, &entry.data, overwrite)?;
                requested.mark_matched(&entry.name);
            }
            requested.finish()
        }
        Format::Zpaq => match archive_formats::zpaq::decode::decode(input) {
            Ok(entries) => {
                let requested = RequestedPaths::new(selected_paths);
                for entry in entries {
                    let Some(name) = entry.filename_utf8() else {
                        return Err(CliError::Unsupported(
                            "zpaq: extraction currently requires UTF-8 filenames".to_owned(),
                        ));
                    };
                    if !requested.matches(name) {
                        continue;
                    }
                    let path = resolved_archive_path(&base_dir, name)?;
                    write_file(&path, &entry.data, overwrite)?;
                    requested.mark_matched(name);
                }
                requested.finish()
            }
            Err(_) => {
                ensure_no_selected_paths(selected_paths, format)?;
                let payload = compress_formats::zpaq::decode::decode(input)
                    .map_err(|error| CliError::from_archive_error(error, password_provided))?;
                let output_path = derived_single_output_path(input_path, &base_dir);
                write_file(&output_path, &payload, overwrite)
            }
        },
        Format::Zip => {
            let entries = if let Some(password) = password {
                archive_formats::zip::decode::decode_with_password(input, password)
            } else {
                archive_formats::zip::decode::decode(input)
            }
            .map_err(|error| CliError::from_archive_error(error, password_provided))?;
            let requested = RequestedPaths::new(selected_paths);
            for entry in entries {
                if !requested.matches(&entry.name) {
                    continue;
                }
                let path = resolved_archive_path(&base_dir, &entry.name)?;
                write_file(&path, &entry.data, overwrite)?;
                requested.mark_matched(&entry.name);
            }
            requested.finish()
        }
        Format::SevenZ => {
            let entries = if let Some(password) = password {
                archive_formats::sevenz::decode::decode_with_password(input, password)
            } else {
                archive_formats::sevenz::decode::decode(input)
            }
            .map_err(|error| CliError::from_archive_error(error, password_provided))?;
            let requested = RequestedPaths::new(selected_paths);
            for entry in entries {
                if !requested.matches(&entry.name) {
                    continue;
                }
                let path = resolved_archive_path(&base_dir, &entry.name)?;
                write_file(&path, &entry.data, overwrite)?;
                requested.mark_matched(&entry.name);
            }
            requested.finish()
        }
        Format::Gzip => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::gzip::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Zstd => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::zstd::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::ZstdSeekable => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::zstd::seekable::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Bzip2 => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::bzip2::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Lzip => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::lzip::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::LzmaAlone => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::lzma_alone::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Lzw => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::lzw::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Lz4 => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::lz4::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Lzo => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::lzo::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Lrzip => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::lrzip::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Rzip => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::rzip::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Zlib => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::zlib::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Snappy => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::snappy::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Brotli => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::brotli::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Deflate => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::deflate::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Xz => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::xz::decode::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Xpress => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::xca::lz77::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::XpressHuff => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::xca::huffman::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Lznt1 => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::xca::lznt1::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Lzf => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::lzf::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Fastlz => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::fastlz::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Lzrw1 => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::lzrw1::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Lzrw1a => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::lzrw1a::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Lzrw2 => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::lzrw2::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Lzrw3 => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::lzrw3::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Lzrw3a => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::lzrw3a::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Lzsa => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::lzsa::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Zx0 => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::zx0::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Zx1 => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::zx1::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Zx2 => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::zx2::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Zx5 => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::zx5::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Vcdiff => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::vcdiff::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Mppc => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::mppc::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Lzs => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::lzs::decode(input)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Lzxd => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::lzxd::decode_all(input, 1 << 25, &[], usize::MAX)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
        Format::Cmpsc => extract_single_payload(
            input_path,
            &base_dir,
            format,
            selected_paths,
            overwrite,
            compress_formats::cmpsc::decode(input, usize::MAX)
                .map_err(|error| CliError::from_archive_error(error, password_provided))?,
        ),
    }
}

fn extract_tar_entries(
    base_dir: &Path,
    entries: Vec<TarEntry>,
    selected_paths: &[String],
    overwrite: bool,
) -> Result<(), CliError> {
    let requested = RequestedPaths::new(selected_paths);
    for entry in entries {
        if !requested.matches(&entry.header.name) {
            continue;
        }
        let path = resolved_archive_path(base_dir, &entry.header.name)?;
        match entry.header.file_type {
            TarFileType::Regular => write_file(&path, &entry.data, overwrite)?,
            TarFileType::Directory => fs::create_dir_all(&path)?,
            TarFileType::SymLink => {
                return Err(CliError::Unsupported(format!(
                    "tar: symlink extraction is not implemented yet ({})",
                    entry.header.name
                )));
            }
            TarFileType::HardLink => {
                return Err(CliError::Unsupported(format!(
                    "tar: hardlink extraction is not implemented yet ({})",
                    entry.header.name
                )));
            }
            other => {
                return Err(CliError::Unsupported(format!(
                    "tar: unsupported entry kind {:?} for extraction ({})",
                    other, entry.header.name
                )));
            }
        }
        requested.mark_matched(&entry.header.name);
    }
    requested.finish()
}

fn extract_cpio_entries(
    base_dir: &Path,
    entries: Vec<CpioEntry>,
    selected_paths: &[String],
    overwrite: bool,
) -> Result<(), CliError> {
    let requested = RequestedPaths::new(selected_paths);
    for entry in entries {
        if !requested.matches(&entry.name) {
            continue;
        }
        let path = resolved_archive_path(base_dir, &entry.name)?;
        if entry.header.is_directory() {
            fs::create_dir_all(&path)?;
        } else if entry.header.is_symlink() {
            return Err(CliError::Unsupported(format!(
                "cpio: symlink extraction is not implemented yet ({})",
                entry.name
            )));
        } else {
            write_file(&path, &entry.data, overwrite)?;
        }
        requested.mark_matched(&entry.name);
    }
    requested.finish()
}

fn extract_single_payload(
    input_path: &Path,
    base_dir: &Path,
    format: Format,
    selected_paths: &[String],
    overwrite: bool,
    payload: Vec<u8>,
) -> Result<(), CliError> {
    ensure_no_selected_paths(selected_paths, format)?;
    let output_path = derived_single_output_path(input_path, base_dir);
    write_file(&output_path, &payload, overwrite)
}

fn write_file(path: &Path, data: &[u8], overwrite: bool) -> Result<(), CliError> {
    if path.exists() && !overwrite {
        return Err(CliError::Detect(format!(
            "refusing to overwrite existing path {}; pass --overwrite to replace it",
            path.display()
        )));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, data)?;
    Ok(())
}

fn resolve_base_dir(out_dir: Option<&Path>) -> Result<PathBuf, CliError> {
    let base = match out_dir {
        Some(path) => path.to_path_buf(),
        None => std::env::current_dir()?,
    };
    Ok(base)
}

fn resolved_archive_path(base_dir: &Path, archive_path: &str) -> Result<PathBuf, CliError> {
    let relative = sanitize_relative_path(archive_path)?;
    Ok(base_dir.join(relative))
}

fn sanitize_relative_path(path: &str) -> Result<PathBuf, CliError> {
    let candidate = Path::new(path);
    let mut clean = PathBuf::new();
    for component in candidate.components() {
        match component {
            Component::Normal(part) => clean.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(CliError::Detect(format!(
                    "refusing to extract path outside destination root: {path}"
                )));
            }
        }
    }
    if clean.as_os_str().is_empty() {
        return Err(CliError::Detect(format!(
            "refusing to extract empty path: {path}"
        )));
    }
    Ok(clean)
}

fn derived_single_output_path(input_path: &Path, base_dir: &Path) -> PathBuf {
    let file_name = input_path.file_name().map_or_else(
        || "output".to_owned(),
        |name| name.to_string_lossy().into_owned(),
    );
    let derived = match file_name.rsplit_once('.') {
        Some((stem, _)) if !stem.is_empty() => stem.to_owned(),
        _ => format!("{file_name}.out"),
    };
    base_dir.join(derived)
}

fn ensure_no_selected_paths(selected_paths: &[String], format: Format) -> Result<(), CliError> {
    if selected_paths.is_empty() {
        Ok(())
    } else {
        Err(CliError::Unsupported(format!(
            "{format}: path filtering is only available for archive formats"
        )))
    }
}

struct RequestedPaths {
    wanted: BTreeSet<String>,
    matched: std::cell::RefCell<BTreeSet<String>>,
}

impl RequestedPaths {
    fn new(selected_paths: &[String]) -> Self {
        Self {
            wanted: selected_paths.iter().cloned().collect(),
            matched: std::cell::RefCell::new(BTreeSet::new()),
        }
    }

    fn matches(&self, path: &str) -> bool {
        self.wanted.is_empty() || self.wanted.contains(path)
    }

    fn mark_matched(&self, path: &str) {
        if !self.wanted.is_empty() {
            self.matched.borrow_mut().insert(path.to_owned());
        }
    }

    fn finish(&self) -> Result<(), CliError> {
        if self.wanted.is_empty() {
            return Ok(());
        }
        let matched = self.matched.borrow();
        let missing: Vec<_> = self.wanted.difference(&matched).cloned().collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(CliError::Detect(format!(
                "requested paths were not found: {}",
                missing.join(", ")
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{derived_single_output_path, sanitize_relative_path};

    #[test]
    fn sanitize_relative_path_rejects_parent_dir() {
        assert!(sanitize_relative_path("../etc/passwd").is_err());
    }

    #[test]
    fn sanitize_relative_path_allows_nested_relative_path() {
        assert_eq!(
            sanitize_relative_path("dir/sub/file.txt").unwrap(),
            Path::new("dir/sub/file.txt")
        );
    }

    #[test]
    fn derive_single_output_uses_parent_dir_and_strips_extension() {
        assert_eq!(
            derived_single_output_path(Path::new("sample.tar.gz"), Path::new("out")),
            Path::new("out/sample.tar")
        );
    }
}
