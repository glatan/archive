use std::fs;
use std::path::{Component, Path, PathBuf};

use ::archive::archive;

use crate::args::PackCommand;
use crate::detect::ArchiveFormat;
use crate::error::CliError;

pub fn pack_inputs(command: PackCommand) -> Result<(), CliError> {
    if command.input.is_empty() {
        return Err(CliError::Detect(
            "archive pack requires at least one input path".to_owned(),
        ));
    }
    ensure_output_policy(&command.output, command.overwrite)?;

    let entries = collect_entries(&command.input, command.base_dir.as_deref())?;
    let encoded = pack_entries(command.format, &entries, command.password.as_deref())?;
    fs::write(&command.output, encoded)?;
    Ok(())
}

/// Pack already-collected entries with the same dispatch as `archive pack`.
///
/// Tree walking is deliberately outside this function so the benchmark
/// helper can separate library encode time from filesystem I/O.
pub fn pack_entries(
    format: ArchiveFormat,
    entries: &[PackedEntry],
    password: Option<&str>,
) -> Result<Vec<u8>, CliError> {
    match format {
        ArchiveFormat::Tar => pack_tar(entries),
        ArchiveFormat::Cpio => pack_cpio(entries),
        ArchiveFormat::Ar => pack_ar(entries),
        ArchiveFormat::Zpaq => pack_zpaq(entries),
        ArchiveFormat::Zip => pack_zip(entries, password),
        ArchiveFormat::SevenZ => pack_sevenz(entries, password),
        ArchiveFormat::Lha => pack_lha(entries),
        ArchiveFormat::Arj => pack_arj(entries),
        ArchiveFormat::Arc => pack_arc(entries),
        ArchiveFormat::GitPack => pack_git_pack(entries),
        ArchiveFormat::Xar => pack_xar(entries),
    }
}

/// One file or directory collected for archive writing.
#[derive(Debug, Clone)]
pub struct PackedEntry {
    pub archive_path: String,
    pub data: Option<Vec<u8>>,
    pub is_dir: bool,
}

fn pack_tar(entries: &[PackedEntry]) -> Result<Vec<u8>, CliError> {
    let mut encoder = archive::tar::encode::TarEncoder::new();
    for entry in entries {
        if entry.is_dir {
            encoder.add_directory(&ensure_dir_suffix(&entry.archive_path), 0o755);
        } else {
            let data = entry_data(entry)?;
            encoder.add_file(&entry.archive_path, data);
        }
    }
    Ok(encoder.finish())
}

fn pack_cpio(entries: &[PackedEntry]) -> Result<Vec<u8>, CliError> {
    let mut encoder = archive::cpio::encode::CpioEncoder::new();
    for entry in entries {
        if entry.is_dir {
            encoder.add_directory(&entry.archive_path, 0o755);
        } else {
            let data = entry_data(entry)?;
            encoder.add_file(&entry.archive_path, data);
        }
    }
    Ok(encoder.finish())
}

fn pack_ar(entries: &[PackedEntry]) -> Result<Vec<u8>, CliError> {
    let mut encoder = archive::ar::encode::ArEncoder::new();
    for entry in entries {
        if entry.is_dir {
            continue;
        }
        if entry.archive_path.contains('/') {
            return Err(CliError::Unsupported(format!(
                "ar: directory trees are not supported by this CLI writer ({})",
                entry.archive_path
            )));
        }
        encoder.add_file(&entry.archive_path, entry_data(entry)?);
    }
    encoder
        .finish()
        .map_err(|error| CliError::from_archive_error(error, false))
}

fn pack_zpaq(entries: &[PackedEntry]) -> Result<Vec<u8>, CliError> {
    let mut encoder = archive::zpaq::encode::ZpaqEncoder::new(2);
    for entry in entries {
        if entry.is_dir {
            continue;
        }
        encoder.add_file(&entry.archive_path, entry_data(entry)?);
    }
    encoder
        .finish()
        .map_err(|error| CliError::from_archive_error(error, false))
}

fn pack_zip(entries: &[PackedEntry], password: Option<&str>) -> Result<Vec<u8>, CliError> {
    let mut encoder = archive::zip::encode::ZipEncoder::new();
    if let Some(password) = password {
        encoder.set_password(password);
    }
    for entry in entries {
        if entry.is_dir {
            continue;
        }
        encoder.add_file(&entry.archive_path, entry_data(entry)?);
    }
    encoder
        .finish()
        .map_err(|error| CliError::from_archive_error(error, password.is_some()))
}

fn pack_lha(entries: &[PackedEntry]) -> Result<Vec<u8>, CliError> {
    let mut encoder = archive::lha::encode::LhaEncoder::new();
    for entry in entries {
        if entry.is_dir {
            encoder
                .add_dir(&entry.archive_path, 0)
                .map_err(|error| CliError::from_archive_error(error, false))?;
        } else {
            encoder
                .add_file(&entry.archive_path, entry_data(entry)?, 0)
                .map_err(|error| CliError::from_archive_error(error, false))?;
        }
    }
    Ok(encoder.finish())
}

fn pack_git_pack(entries: &[PackedEntry]) -> Result<Vec<u8>, CliError> {
    let mut encoder = archive::git_pack::encode::GitPackEncoder::new();
    for entry in entries {
        if !entry.is_dir {
            encoder.add_object(archive::git_pack::ObjectType::Blob, entry_data(entry)?);
        }
    }
    Ok(encoder.finish())
}

fn pack_xar(entries: &[PackedEntry]) -> Result<Vec<u8>, CliError> {
    let mut encoder = archive::xar::encode::XarEncoder::new();
    for entry in entries {
        if entry.is_dir {
            encoder.add_directory(&entry.archive_path);
        } else {
            encoder.add_file(&entry.archive_path, entry_data(entry)?);
        }
    }
    Ok(encoder.finish())
}

fn pack_arj(entries: &[PackedEntry]) -> Result<Vec<u8>, CliError> {
    let mut encoder = archive::arj::encode::ArjEncoder::new();
    for entry in entries {
        if entry.is_dir {
            encoder
                .add_dir(&entry.archive_path, 0)
                .map_err(|error| CliError::from_archive_error(error, false))?;
        } else {
            encoder
                .add_file(&entry.archive_path, entry_data(entry)?, 0)
                .map_err(|error| CliError::from_archive_error(error, false))?;
        }
    }
    Ok(encoder.finish())
}

fn pack_arc(entries: &[PackedEntry]) -> Result<Vec<u8>, CliError> {
    let mut encoder = archive::arc::encode::ArcEncoder::new();
    for entry in entries {
        if entry.is_dir {
            continue; // ARC has no directory entries.
        }
        encoder
            .add_file(&entry.archive_path, entry_data(entry)?, 0, 0)
            .map_err(|error| CliError::from_archive_error(error, false))?;
    }
    Ok(encoder.finish())
}

fn pack_sevenz(entries: &[PackedEntry], password: Option<&str>) -> Result<Vec<u8>, CliError> {
    let mut encoder = archive::sevenz::encode::SevenZEncoder::new();
    if let Some(password) = password {
        encoder.set_password(password);
        encoder.set_encoded_header(true);
    }
    for entry in entries {
        if entry.is_dir {
            continue;
        }
        encoder.add_file(&entry.archive_path, entry_data(entry)?);
    }
    encoder
        .finish()
        .map_err(|error| CliError::from_archive_error(error, password.is_some()))
}

pub fn collect_entries(
    inputs: &[PathBuf],
    base_dir: Option<&Path>,
) -> Result<Vec<PackedEntry>, CliError> {
    let mut entries = Vec::new();
    for input in inputs {
        let effective_base = match base_dir {
            Some(base_dir) => Some(base_dir),
            None => input.parent(),
        };
        collect_one(input, effective_base, &mut entries)?;
    }
    if entries.iter().all(|entry| entry.is_dir) {
        return Err(CliError::Unsupported(
            "packing only empty directories is not supported by the current CLI writer subset"
                .to_owned(),
        ));
    }
    Ok(entries)
}

fn collect_one(
    input: &Path,
    base_dir: Option<&Path>,
    out: &mut Vec<PackedEntry>,
) -> Result<(), CliError> {
    let metadata = fs::symlink_metadata(input)?;
    if metadata.file_type().is_symlink() {
        return Err(CliError::Unsupported(format!(
            "packing symlink inputs is not implemented yet ({})",
            input.display()
        )));
    }
    let relative = archive_relative_path(input, base_dir)?;
    if metadata.is_dir() {
        out.push(PackedEntry {
            archive_path: relative.clone(),
            data: None,
            is_dir: true,
        });
        let mut children = fs::read_dir(input)?
            .map(|entry| entry.map(|e| e.path()))
            .collect::<Result<Vec<_>, _>>()?;
        children.sort();
        for child in children {
            collect_one(&child, base_dir, out)?;
        }
    } else if metadata.is_file() {
        out.push(PackedEntry {
            archive_path: relative,
            data: Some(fs::read(input)?),
            is_dir: false,
        });
    } else {
        return Err(CliError::Unsupported(format!(
            "unsupported filesystem input kind ({})",
            input.display()
        )));
    }
    Ok(())
}

fn archive_relative_path(input: &Path, base_dir: Option<&Path>) -> Result<String, CliError> {
    let relative = if let Some(base_dir) = base_dir {
        input.strip_prefix(base_dir).map_err(|_| {
            CliError::Detect(format!(
                "input path {} is not under --base-dir {}",
                input.display(),
                base_dir.display()
            ))
        })?
    } else {
        input.file_name().map(Path::new).ok_or_else(|| {
            CliError::Detect(format!(
                "could not derive archive name for {}",
                input.display()
            ))
        })?
    };
    sanitize_archive_path(relative)
}

fn sanitize_archive_path(path: &Path) -> Result<String, CliError> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(CliError::Detect(format!(
                    "refusing to encode unsafe archive path {}",
                    path.display()
                )));
            }
        }
    }
    if parts.is_empty() {
        return Err(CliError::Detect(format!(
            "refusing to encode empty archive path {}",
            path.display()
        )));
    }
    Ok(parts.join("/"))
}

fn ensure_output_policy(path: &Path, overwrite: bool) -> Result<(), CliError> {
    if path.exists() && !overwrite {
        return Err(CliError::Detect(format!(
            "refusing to overwrite existing output {}; pass --overwrite to replace it",
            path.display()
        )));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn entry_data(entry: &PackedEntry) -> Result<&[u8], CliError> {
    entry
        .data
        .as_deref()
        .ok_or_else(|| CliError::Detect(format!("missing file data for {}", entry.archive_path)))
}

fn ensure_dir_suffix(path: &str) -> String {
    if path.ends_with('/') {
        path.to_owned()
    } else {
        format!("{path}/")
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{ensure_dir_suffix, sanitize_archive_path};

    #[test]
    fn sanitize_archive_path_rejects_parent_components() {
        assert!(sanitize_archive_path(Path::new("../bad")).is_err());
    }

    #[test]
    fn sanitize_archive_path_normalizes_separators() {
        assert_eq!(
            sanitize_archive_path(Path::new("dir/sub/file.txt")).unwrap(),
            "dir/sub/file.txt"
        );
    }

    #[test]
    fn ensure_dir_suffix_adds_trailing_slash() {
        assert_eq!(ensure_dir_suffix("dir"), "dir/");
    }
}
