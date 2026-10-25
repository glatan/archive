//! Data model shared by the benchmark catalog, runner, and report writer.

/// Input size used for the quick and full runs.
#[derive(Debug, Clone, Copy)]
pub struct SizeClass {
    pub quick: usize,
    pub full: usize,
}

pub const FAST: SizeClass = SizeClass {
    quick: 4 * 1024 * 1024,
    full: 64 * 1024 * 1024,
};
pub const MEDIUM: SizeClass = SizeClass {
    quick: 2 * 1024 * 1024,
    full: 32 * 1024 * 1024,
};
pub const SLOW: SizeClass = SizeClass {
    quick: 1024 * 1024,
    full: 8 * 1024 * 1024,
};
pub const TINY: SizeClass = SizeClass {
    quick: 256 * 1024,
    full: 4 * 1024 * 1024,
};
pub const SMALL: SizeClass = SizeClass {
    quick: 64 * 1024,
    full: 512 * 1024,
};
pub const PACKET: SizeClass = SizeClass {
    quick: 8 * 1024,
    full: 8 * 1024,
};
pub const XCA: SizeClass = SizeClass {
    quick: 32 * 1024,
    full: 32 * 1024,
};
pub const ZX: SizeClass = SizeClass {
    quick: 32 * 1024,
    full: 128 * 1024,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Codec,
    Archive,
}

/// How a reference command receives its output path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    /// Write the result to stdout. The runner redirects stdout to a file.
    Stdout,
    /// The output path is passed as a `{output}` argument.
    Arg,
    /// The output path is an extraction directory passed as `{output}`.
    Dir,
    /// The command writes `{output}` itself (typically through a shell script).
    None,
}

#[derive(Debug, Clone, Copy)]
pub struct RefCommand {
    pub program: &'static str,
    /// Arguments with `{input}` and `{output}` placeholders.
    pub args: &'static [&'static str],
    pub output: OutputMode,
}

#[derive(Debug, Clone, Copy)]
pub struct RefSpec {
    pub name: &'static str,
    pub version: &'static str,
    /// Identifier used to prefer `target/bench/refs/bin/<binary_id>`.
    pub binary_id: &'static str,
    /// Human-readable build provenance, including optimization flags when known.
    pub build: &'static str,
    pub encode: Option<RefCommand>,
    pub decode: Option<RefCommand>,
}

#[derive(Debug, Clone, Copy)]
pub struct Case {
    pub id: &'static str,
    pub label: &'static str,
    pub kind: Kind,
    /// Helper/CLI format name. For codecs this is a `CompressionFormat`
    /// value; for archives it is an `ArchiveFormat` or `Format` value.
    pub format: &'static str,
    /// Format name for the user-facing `archive` CLI, when supported.
    pub cli_format: Option<&'static str>,
    pub ours_lib: bool,
    pub ours_cli: bool,
    /// Use the helper's raw library dispatch instead of the CLI dispatch.
    pub raw: bool,
    pub encode: bool,
    pub decode: bool,
    pub level: Option<u8>,
    pub backend: Option<&'static str>,
    pub reference: Option<RefSpec>,
    /// Optional checked-in fixture for read-only formats.
    pub fixture: Option<&'static str>,
    /// Why no reference is available, or other scope note.
    pub note: Option<&'static str>,
    pub size: SizeClass,
}

impl Case {
    pub fn compared(&self) -> bool {
        self.reference.is_some()
    }

    pub fn status(&self) -> &'static str {
        match (self.compared(), self.encode, self.decode) {
            (true, true, true) => "measured",
            (true, false, true) => "decode-only",
            (true, true, false) => "encode-only",
            (false, _, _) if !self.ours_lib && !self.ours_cli => "unavailable",
            (false, _, _) => "ours-only",
            (true, false, false) => "reference-only",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Measurement {
    pub samples_ns: Vec<u64>,
    pub output_len: usize,
    pub hash: u64,
}

impl Measurement {
    pub fn median_ns(&self) -> u64 {
        median(&self.samples_ns)
    }
}

#[derive(Debug, Clone, Default)]
pub struct OpResult {
    pub ours_lib: Option<Measurement>,
    pub ours_cli: Option<Measurement>,
    pub reference: Option<Measurement>,
    /// Reference decoder run on this implementation's encoded stream.
    pub reference_on_ours: Option<Measurement>,
    /// True when both directions of the cross-decode check matched.
    pub cross_decode_ok: Option<bool>,
    pub note: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CaseResult {
    pub case: Case,
    pub corpus: String,
    pub input_len: usize,
    pub encode: Option<OpResult>,
    pub decode: Option<OpResult>,
    pub error: Option<String>,
    /// Runtime status: measured, ours-only, or unavailable.
    pub status: String,
}

fn median(values: &[u64]) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    sorted[sorted.len() / 2]
}
