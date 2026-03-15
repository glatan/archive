use std::collections::BTreeMap;
use std::io::{self, Write};

use crate::detect::{ContentKind, Format};
use crate::error::CliError;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct EntrySummary {
    pub path: String,
    pub kind: String,
    pub size: Option<u64>,
    pub compressed_size: Option<u64>,
    pub mtime: Option<i64>,
    pub mode: Option<u32>,
    pub extra: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct InspectReport {
    pub detected_format: Format,
    pub kind: ContentKind,
    pub entry_count: Option<usize>,
    pub warnings: Vec<String>,
    pub notes: Vec<String>,
    pub entries: Vec<EntrySummary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct TestReport {
    pub detected_format: Format,
    pub ok: bool,
    pub verified_checksums: bool,
    pub warnings: Vec<String>,
    pub failure: Option<String>,
}

pub fn print_list(
    report: &InspectReport,
    long: bool,
    tree: bool,
    json: bool,
    use_pager: bool,
) -> Result<(), CliError> {
    if json {
        return print_json(report);
    }

    let mut buf = String::new();
    for warning in &report.warnings {
        buf.push_str(&format!("Warning: {warning}\n"));
    }
    for note in &report.notes {
        buf.push_str(&format!("Note: {note}\n"));
    }
    if tree {
        for line in render_tree(report, long) {
            buf.push_str(&line);
            buf.push('\n');
        }
    } else {
        for entry in &report.entries {
            if long {
                buf.push_str(&format_long_entry(&entry.path, entry));
                buf.push('\n');
                for extra in &entry.extra {
                    buf.push_str(&format!("  extra: {extra}\n"));
                }
            } else {
                buf.push_str(&entry.path);
                buf.push('\n');
            }
        }
    }

    if use_pager {
        crate::pager::write_with_pager(&buf)
    } else {
        let mut stdout = io::stdout().lock();
        stdout.write_all(buf.as_bytes())?;
        Ok(())
    }
}

pub fn print_inspect(report: &InspectReport, json: bool) -> Result<(), CliError> {
    if json {
        return print_json(report);
    }

    let mut stdout = io::stdout().lock();
    writeln!(stdout, "Detected format: {}", report.detected_format)?;
    writeln!(stdout, "Kind: {}", report.kind)?;
    if let Some(entry_count) = report.entry_count {
        writeln!(stdout, "Entries: {entry_count}")?;
    }
    for warning in &report.warnings {
        writeln!(stdout, "Warning: {warning}")?;
    }
    for note in &report.notes {
        writeln!(stdout, "Note: {note}")?;
    }
    for entry in &report.entries {
        writeln!(
            stdout,
            "Entry: {} ({}, size: {}, compressed: {})",
            entry.path,
            entry.kind,
            entry
                .size
                .map_or_else(|| "?".to_owned(), |size| size.to_string()),
            entry
                .compressed_size
                .map_or_else(|| "?".to_owned(), |size| size.to_string())
        )?;
    }
    Ok(())
}

pub fn print_test(report: &TestReport, json: bool) -> Result<(), CliError> {
    if json {
        return print_json(report);
    }

    let mut stdout = io::stdout().lock();
    writeln!(stdout, "Detected format: {}", report.detected_format)?;
    writeln!(
        stdout,
        "Result: {}",
        if report.ok { "ok" } else { "failed" }
    )?;
    writeln!(
        stdout,
        "Checksums verified: {}",
        if report.verified_checksums {
            "yes"
        } else {
            "no"
        }
    )?;
    for warning in &report.warnings {
        writeln!(stdout, "Warning: {warning}")?;
    }
    if let Some(failure) = &report.failure {
        writeln!(stdout, "Failure: {failure}")?;
    }
    Ok(())
}

#[cfg(feature = "json")]
fn print_json<T: serde::Serialize>(value: &T) -> Result<(), CliError> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, value)
        .map_err(|error| CliError::Detect(format!("failed to render JSON output: {error}")))?;
    writeln!(stdout)?;
    Ok(())
}

fn format_long_entry(label: &str, entry: &EntrySummary) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}",
        entry.kind,
        entry
            .size
            .map_or_else(|| "-".to_owned(), |size| size.to_string()),
        entry
            .compressed_size
            .map_or_else(|| "-".to_owned(), |size| size.to_string()),
        entry
            .mode
            .map_or_else(|| "-".to_owned(), |mode| format!("{mode:#o}")),
        entry
            .mtime
            .map_or_else(|| "-".to_owned(), |mtime| mtime.to_string()),
        label
    )
}

fn render_tree(report: &InspectReport, long: bool) -> Vec<String> {
    let tree = build_tree(report);
    let mut lines = Vec::new();
    render_tree_children(&tree.children, "", long, &mut lines);
    lines
}

#[derive(Debug, Default)]
struct TreeNode {
    name: String,
    entry: Option<EntrySummary>,
    children: BTreeMap<String, TreeNode>,
}

fn build_tree(report: &InspectReport) -> TreeNode {
    let mut root = TreeNode::default();
    for entry in &report.entries {
        insert_tree_entry(&mut root, entry.clone());
    }
    root
}

fn insert_tree_entry(root: &mut TreeNode, entry: EntrySummary) {
    let collapsed_path = entry.path.replace("!/", "/");
    let normalized = collapsed_path.trim_end_matches('/');
    if normalized.is_empty() {
        return;
    }

    let path_parts: Vec<_> = normalized.split('/').collect();
    let original_path = entry.path.clone();
    let mut current = root;
    for (index, part) in path_parts.iter().enumerate() {
        current = current
            .children
            .entry((*part).to_owned())
            .or_insert_with(|| TreeNode {
                name: (*part).to_owned(),
                ..TreeNode::default()
            });
        if index + 1 == path_parts.len() {
            current.entry = Some(entry.clone());
        } else if current.entry.is_none() {
            current.entry = Some(EntrySummary {
                path: original_path.clone(),
                kind: "directory".to_owned(),
                size: None,
                compressed_size: None,
                mtime: None,
                mode: None,
                extra: Vec::new(),
            });
        }
    }
}

fn render_tree_children(
    children: &BTreeMap<String, TreeNode>,
    prefix: &str,
    long: bool,
    lines: &mut Vec<String>,
) {
    let total = children.len();
    for (index, child) in children.values().enumerate() {
        let is_last = index + 1 == total;
        let branch = if is_last { "└── " } else { "├── " };
        let child_prefix = if is_last { "    " } else { "│   " };
        let label = child_label(child);
        if long {
            let entry = child.entry.clone().unwrap_or(EntrySummary {
                path: label.clone(),
                kind: if child.children.is_empty() {
                    "file".to_owned()
                } else {
                    "directory".to_owned()
                },
                size: None,
                compressed_size: None,
                mtime: None,
                mode: None,
                extra: Vec::new(),
            });
            lines.push(format_long_entry(
                &format!("{prefix}{branch}{label}"),
                &entry,
            ));
        } else {
            lines.push(format!("{prefix}{branch}{label}"));
        }
        if !child.children.is_empty() {
            render_tree_children(
                &child.children,
                &format!("{prefix}{child_prefix}"),
                long,
                lines,
            );
        }
    }
}

fn child_label(child: &TreeNode) -> String {
    let is_dir = child
        .entry
        .as_ref()
        .map(|entry| entry.kind == "directory")
        .unwrap_or(!child.children.is_empty());
    if is_dir {
        format!("{}/", child.name)
    } else {
        child.name.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::{EntrySummary, InspectReport, render_tree};
    use crate::detect::{ContentKind, Format};

    fn sample_report(entries: Vec<EntrySummary>) -> InspectReport {
        InspectReport {
            detected_format: Format::Tar,
            kind: ContentKind::Archive,
            entry_count: Some(entries.len()),
            warnings: Vec::new(),
            notes: Vec::new(),
            entries,
        }
    }

    #[test]
    fn tree_renders_nested_paths() {
        let lines = render_tree(
            &sample_report(vec![
                EntrySummary {
                    path: "src/sub/file.txt".to_owned(),
                    kind: "file".to_owned(),
                    size: Some(1),
                    compressed_size: None,
                    mtime: None,
                    mode: None,
                    extra: Vec::new(),
                },
                EntrySummary {
                    path: "src/other.txt".to_owned(),
                    kind: "file".to_owned(),
                    size: Some(1),
                    compressed_size: None,
                    mtime: None,
                    mode: None,
                    extra: Vec::new(),
                },
            ]),
            false,
        );
        assert_eq!(
            lines,
            vec![
                "└── src/".to_owned(),
                "    ├── other.txt".to_owned(),
                "    └── sub/".to_owned(),
                "        └── file.txt".to_owned(),
            ]
        );
    }

    #[test]
    fn tree_collapses_nested_container_boundaries() {
        let lines = render_tree(
            &sample_report(vec![
                EntrySummary {
                    path: "sample.tar.gz".to_owned(),
                    kind: "file".to_owned(),
                    size: Some(1),
                    compressed_size: Some(1),
                    mtime: None,
                    mode: None,
                    extra: vec!["nested-format=tar".to_owned()],
                },
                EntrySummary {
                    path: "sample.tar.gz!/dir/hello.txt".to_owned(),
                    kind: "file".to_owned(),
                    size: Some(1),
                    compressed_size: None,
                    mtime: None,
                    mode: None,
                    extra: Vec::new(),
                },
            ]),
            false,
        );
        assert_eq!(
            lines,
            vec![
                "└── sample.tar.gz".to_owned(),
                "    └── dir/".to_owned(),
                "        └── hello.txt".to_owned(),
            ]
        );
    }
}

#[cfg(not(feature = "json"))]
fn print_json<T>(_value: &T) -> Result<(), CliError> {
    Err(CliError::Unsupported(
        "JSON output support is disabled at compile time".to_owned(),
    ))
}
