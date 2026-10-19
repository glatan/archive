//! Byte layout for `fuzz_host::exec`.
//!
//! The wasm guest asks the native host to run a Unix command. The host keeps
//! process groups and `ulimit`, then returns this buffer through guest memory.
//!
//! ```text
//! u32 status       0 = finished, 1 = spawn/timeout failure
//! i32 code         exit code, or -1 when the process was signaled
//! u32 stdout_len
//! u32 stderr_len
//! u32 display_len  UTF-8 `ExitStatus` display (`exit status: N`, `signal: 15 (SIGTERM)`, ...)
//! [stdout bytes][stderr bytes][display bytes]
//! ```
//!
//! On status 1, stderr holds the error string and the display is empty.
//! A signaled process is status 0 with code -1, so the guest can tell it
//! from a normal exit. The display is the same string Unix `ExitStatus`
//! produces, including `signal: 11 (SIGSEGV) (core dumped)` when the process dumped core.

pub const STATUS_FINISHED: u32 = 0;
#[cfg(not(target_arch = "wasm32"))]
#[allow(dead_code)]
pub const STATUS_FAILED: u32 = 1;
pub const HEADER_LEN: usize = 20;

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
pub struct ExecBody {
    pub finished: bool,
    pub code: i32,
    pub status_display: String,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[cfg(not(target_arch = "wasm32"))]
#[allow(dead_code)]
pub fn pack(
    finished: bool,
    code: i32,
    status_display: &str,
    stdout: &[u8],
    stderr: &[u8],
) -> Vec<u8> {
    if let Some(bytes) = pack_checked(finished, code, status_display.as_bytes(), stdout, stderr) {
        return bytes;
    }
    pack_checked(false, -1, b"", &[], b"host exec reply exceeds 4GiB")
        .expect("failure reply fits in the header")
}

#[cfg(not(target_arch = "wasm32"))]
fn pack_checked(
    finished: bool,
    code: i32,
    status_display: &[u8],
    stdout: &[u8],
    stderr: &[u8],
) -> Option<Vec<u8>> {
    let status = if finished {
        STATUS_FINISHED
    } else {
        STATUS_FAILED
    };
    let stdout_len = u32::try_from(stdout.len()).ok()?;
    let stderr_len = u32::try_from(stderr.len()).ok()?;
    let display_len = u32::try_from(status_display.len()).ok()?;
    let mut out =
        Vec::with_capacity(HEADER_LEN + stdout.len() + stderr.len() + status_display.len());
    out.extend_from_slice(&status.to_le_bytes());
    out.extend_from_slice(&code.to_le_bytes());
    out.extend_from_slice(&stdout_len.to_le_bytes());
    out.extend_from_slice(&stderr_len.to_le_bytes());
    out.extend_from_slice(&display_len.to_le_bytes());
    out.extend_from_slice(stdout);
    out.extend_from_slice(stderr);
    out.extend_from_slice(status_display);
    Some(out)
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
pub fn unpack(buf: &[u8]) -> Result<ExecBody, String> {
    if buf.len() < HEADER_LEN {
        return Err("host exec reply is shorter than the header".to_string());
    }
    let status = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    let code = i32::from_le_bytes(buf[4..8].try_into().unwrap());
    let stdout_len = u32::from_le_bytes(buf[8..12].try_into().unwrap()) as usize;
    let stderr_len = u32::from_le_bytes(buf[12..16].try_into().unwrap()) as usize;
    let display_len = u32::from_le_bytes(buf[16..20].try_into().unwrap()) as usize;
    let rest = &buf[HEADER_LEN..];
    let body_len = stdout_len
        .saturating_add(stderr_len)
        .saturating_add(display_len);
    if rest.len() < body_len {
        return Err("host exec reply truncated the command output".to_string());
    }
    let stdout_end = stdout_len;
    let stderr_end = stdout_end + stderr_len;
    let display_end = stderr_end + display_len;
    let status_display = std::str::from_utf8(&rest[stderr_end..display_end])
        .map_err(|_| "host exec status is not utf-8".to_string())?
        .to_string();
    Ok(ExecBody {
        finished: status == STATUS_FINISHED,
        code,
        status_display,
        stdout: rest[..stdout_end].to_vec(),
        stderr: rest[stdout_end..stderr_end].to_vec(),
    })
}

/// One `fuzz_host::exec` call. The host compares this on a retry so a short
/// guest buffer does not run the command again.
#[cfg_attr(not(feature = "wasm-host"), allow(dead_code))]
#[derive(Clone, PartialEq, Eq)]
pub struct ExecRequest {
    pub cmd: String,
    pub args_blob: String,
    pub dir_blob: String,
    pub stdin: Option<Vec<u8>>,
    pub timeout_ms: i32,
}

#[cfg_attr(not(feature = "wasm-host"), allow(dead_code))]
pub struct PendingExec {
    pub request: ExecRequest,
    pub reply: Vec<u8>,
}

/// Return the reply saved for `request`, if the previous call could not copy
/// it into the guest. A different request leaves the saved reply in place.
#[cfg_attr(not(feature = "wasm-host"), allow(dead_code))]
pub fn take_pending(pending: &mut Option<PendingExec>, request: &ExecRequest) -> Option<Vec<u8>> {
    if pending
        .as_ref()
        .is_some_and(|item| &item.request == request)
    {
        pending.take().map(|item| item.reply)
    } else {
        None
    }
}

/// Remember `reply` when `out_cap` cannot hold it. A copied reply drops any
/// saved one. `copied == false` with a large enough cap is a write failure
/// and leaves `pending` unchanged.
#[cfg_attr(not(feature = "wasm-host"), allow(dead_code))]
pub fn store_pending(
    pending: &mut Option<PendingExec>,
    request: ExecRequest,
    reply: Vec<u8>,
    out_cap: i32,
    copied: bool,
) {
    if copied {
        *pending = None;
        return;
    }
    let too_small = out_cap < 0 || reply.len() > usize::try_from(out_cap).unwrap_or(0);
    if too_small {
        *pending = Some(PendingExec { request, reply });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_roundtrips_finished_output() {
        let packed = pack(true, 0, "exit status: 0", b"out", b"err");
        let body = unpack(&packed).unwrap();
        assert!(body.finished);
        assert_eq!(body.code, 0);
        assert_eq!(body.status_display, "exit status: 0");
        assert_eq!(body.stdout, b"out");
        assert_eq!(body.stderr, b"err");
    }

    #[test]
    fn pack_roundtrips_signal_status() {
        let packed = pack(
            true,
            -1,
            "signal: 11 (SIGSEGV) (core dumped)",
            b"",
            b"killed",
        );
        let body = unpack(&packed).unwrap();
        assert!(body.finished);
        assert_eq!(body.code, -1);
        assert_eq!(body.status_display, "signal: 11 (SIGSEGV) (core dumped)");
        assert_eq!(body.stderr, b"killed");
    }

    #[test]
    fn pack_roundtrips_failure_message() {
        let packed = pack(false, -1, "", &[], b"gzip timed out after 30s");
        let body = unpack(&packed).unwrap();
        assert!(!body.finished);
        assert_eq!(body.status_display, "");
        assert_eq!(body.stderr, b"gzip timed out after 30s");
    }

    #[test]
    fn short_buffer_reuses_the_saved_reply() {
        let request = sample_request();
        let mut pending = None;
        let first = b"0123456789".to_vec();
        assert!(take_pending(&mut pending, &request).is_none());
        store_pending(&mut pending, request.clone(), first.clone(), 4, false);
        assert_eq!(take_pending(&mut pending, &request), Some(first.clone()));
        assert!(pending.is_none());
        store_pending(&mut pending, request.clone(), first.clone(), 4, false);
        let other = ExecRequest {
            cmd: "xz".to_string(),
            ..request.clone()
        };
        assert!(take_pending(&mut pending, &other).is_none());
        assert!(pending.is_some());
        store_pending(&mut pending, request, first, 10, true);
        assert!(pending.is_none());
    }

    fn sample_request() -> ExecRequest {
        ExecRequest {
            cmd: "gzip".to_string(),
            args_blob: "-c".to_string(),
            dir_blob: String::new(),
            stdin: Some(vec![1, 2, 3]),
            timeout_ms: 30_000,
        }
    }
}
