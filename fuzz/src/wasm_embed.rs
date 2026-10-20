//! Native host that runs `archive-fuzz.wasm`.
//!
//! The guest is `wasm32-wasip1-threads` with simd128 and `-C panic=unwind`.
//! WASI cannot exec a host binary or put it in a process group, so
//! `fuzz_host::exec` lands here and reuses the Unix `ulimit` / process-group
//! path. Unwind is enabled so `catch_unwind` records a library panic as a
//! failure instead of aborting the process.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use wasmtime::{Caller, Config, Engine, Linker, Module, SharedMemory, Store};
use wasmtime_wasi::p1::WasiP1Ctx;
use wasmtime_wasi::{I32Exit, WasiCtxBuilder};
use wasmtime_wasi_threads::WasiThreadsCtx;

use crate::external;

const DEFAULT_MODULE: &str = "/usr/local/lib/archive-fuzz.wasm";

struct State {
    wasi: WasiP1Ctx,
    make_wasi: Arc<dyn Fn() -> WasiP1Ctx + Send + Sync>,
    threads: Arc<OnceLock<WasiThreadsCtx<State>>>,
    /// Reply that did not fit in the guest buffer. Retries of the same
    /// request copy it instead of running the command again. Child threads
    /// start with this empty.
    pending_exec: Option<crate::host_proto::PendingExec>,
}

impl Clone for State {
    fn clone(&self) -> Self {
        Self {
            wasi: (self.make_wasi)(),
            make_wasi: Arc::clone(&self.make_wasi),
            threads: Arc::clone(&self.threads),
            pending_exec: None,
        }
    }
}

pub fn run() -> Result<(), wasmtime::Error> {
    let module_path = std::env::var("ARCHIVE_FUZZ_WASM")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_MODULE));
    let root = std::env::var("ARCHIVE_FUZZ_ROOT").unwrap_or_else(|_| "/workspace".to_string());
    let mut args = vec!["archive-fuzz".to_string()];
    args.extend(std::env::args().skip(1));

    let mut config = Config::new();
    config.wasm_simd(true);
    config.wasm_threads(true);
    config.wasm_bulk_memory(true);
    config.shared_memory(true);
    // The guest is built with `-C panic=unwind`. Overflow and other library
    // panics must be catchable by `catch_unwind`, matching the native targets.
    // The default wasm panic strategy aborts the process on the first panic.
    config.wasm_exceptions(true);
    // Exception objects live on the GC heap. An unset GC reservation copies
    // the 2GiB linear-memory reservation, and that second mapping does not
    // fit in fuzz-wasm's 4GiB address-space cap.
    config.gc_heap_reservation(1 << 20);
    config.gc_heap_guard_size(64 * 1024);
    config.gc_heap_reservation_for_growth(1 << 20);
    // The default reservation is 4GiB plus a guard, and `ulimit -v` counts
    // that mapping. The guest maximum is 2GiB. `fuzz-wasm` raises this
    // process to 4GiB so the 2GiB reservation has a contiguous hole. The
    // other fuzz processes stay at 2GiB.
    config.memory_reservation(2_147_483_648);
    let engine = Engine::new(&config)?;
    let module = Module::from_file(&engine, &module_path)?;

    let threads = Arc::new(OnceLock::new());
    let make_wasi: Arc<dyn Fn() -> WasiP1Ctx + Send + Sync> =
        Arc::new(make_wasi_factory(args, root));
    let state = State {
        wasi: make_wasi(),
        make_wasi: Arc::clone(&make_wasi),
        threads: Arc::clone(&threads),
        pending_exec: None,
    };

    let mut linker = Linker::<State>::new(&engine);
    wasmtime_wasi::p1::add_to_linker_sync(&mut linker, |state: &mut State| &mut state.wasi)?;
    linker.func_wrap("fuzz_host", "exec", host_exec)?;

    let mut store = Store::new(&engine, state);
    wasmtime_wasi_threads::add_to_linker(&mut linker, &store, &module, |state| {
        state
            .threads
            .get()
            .expect("wasi threads context is installed before _start")
    })?;

    let linker = Arc::new(linker);
    let ctx = WasiThreadsCtx::new(module.clone(), Arc::clone(&linker), false)?;
    store
        .data_mut()
        .threads
        .set(ctx)
        .map_err(|_| wasmtime::Error::msg("wasi threads context was set twice"))?;

    let instance = linker.instantiate(&mut store, &module)?;
    let start = instance.get_typed_func::<(), ()>(&mut store, "_start")?;
    match start.call(&mut store, ()) {
        Ok(()) => Ok(()),
        Err(err) => match err.downcast_ref::<I32Exit>() {
            Some(exit) => std::process::exit(exit.0),
            None => Err(err),
        },
    }
}

fn make_wasi_factory(args: Vec<String>, root: String) -> impl Fn() -> WasiP1Ctx + Send + Sync {
    move || {
        let mut environment = vec![("TMPDIR".to_string(), "/tmp".to_string())];
        environment.extend(std::env::vars().filter(|(key, _)| key != "TMPDIR"));
        let mut builder = WasiCtxBuilder::new();
        builder
            .inherit_stdout()
            .inherit_stderr()
            .envs(&environment)
            .args(&args)
            .allow_blocking_current_thread(true)
            .initial_cwd(".");
        preopen(&mut builder, &root, ".");
        preopen(&mut builder, "/tmp", "/tmp");
        builder.build_p1()
    }
}

fn preopen(builder: &mut WasiCtxBuilder, host: &str, guest: &str) {
    builder
        .preopened_dir(
            host,
            guest,
            wasmtime_wasi::DirPerms::all(),
            wasmtime_wasi::FilePerms::all(),
        )
        .unwrap_or_else(|err| panic!("preopen {host} as {guest}: {err}"));
}

#[allow(clippy::too_many_arguments)]
fn host_exec(
    mut caller: Caller<'_, State>,
    cmd_ptr: i32,
    cmd_len: i32,
    args_ptr: i32,
    args_len: i32,
    dir_ptr: i32,
    dir_len: i32,
    stdin_ptr: i32,
    stdin_len: i32,
    stdin_null: i32,
    timeout_ms: i32,
    out_ptr: i32,
    out_cap: i32,
) -> i32 {
    let request = match read_exec_request(
        &mut caller,
        cmd_ptr,
        cmd_len,
        args_ptr,
        args_len,
        dir_ptr,
        dir_len,
        stdin_ptr,
        stdin_len,
        stdin_null,
        timeout_ms,
    ) {
        Ok(request) => request,
        Err(err) => {
            let reply = crate::host_proto::pack(false, -1, "", &[], err.as_bytes());
            return write_reply(&mut caller, out_ptr, out_cap, &reply);
        }
    };
    let reply = if let Some(reply) =
        crate::host_proto::take_pending(&mut caller.data_mut().pending_exec, &request)
    {
        reply
    } else {
        run_packed(&request)
    };
    let code = write_reply(&mut caller, out_ptr, out_cap, &reply);
    let copied = code >= 0 && out_cap >= 0 && reply.len() <= usize::try_from(out_cap).unwrap_or(0);
    crate::host_proto::store_pending(
        &mut caller.data_mut().pending_exec,
        request,
        reply,
        out_cap,
        copied,
    );
    code
}

#[allow(clippy::too_many_arguments)]
fn read_exec_request(
    caller: &mut Caller<'_, State>,
    cmd_ptr: i32,
    cmd_len: i32,
    args_ptr: i32,
    args_len: i32,
    dir_ptr: i32,
    dir_len: i32,
    stdin_ptr: i32,
    stdin_len: i32,
    stdin_null: i32,
    timeout_ms: i32,
) -> Result<crate::host_proto::ExecRequest, String> {
    let cmd = read_string(caller, cmd_ptr, cmd_len)?;
    let args_blob = read_string(caller, args_ptr, args_len)?;
    let dir_blob = read_string(caller, dir_ptr, dir_len)?;
    let stdin = if stdin_null != 0 {
        None
    } else {
        Some(read_bytes(caller, stdin_ptr, stdin_len)?)
    };
    Ok(crate::host_proto::ExecRequest {
        cmd,
        args_blob,
        dir_blob,
        stdin,
        timeout_ms,
    })
}

fn run_packed(request: &crate::host_proto::ExecRequest) -> Vec<u8> {
    let args: Vec<&str> = if request.args_blob.is_empty() {
        Vec::new()
    } else {
        request.args_blob.split('\0').collect()
    };
    let dir = if request.dir_blob.is_empty() {
        None
    } else {
        Some(Path::new(&request.dir_blob))
    };
    let timeout = Duration::from_millis(request.timeout_ms.max(0) as u64);
    external::execute_tool_packed(&request.cmd, &args, dir, request.stdin.as_deref(), timeout)
}

fn write_reply(caller: &mut Caller<'_, State>, out_ptr: i32, out_cap: i32, reply: &[u8]) -> i32 {
    // A length that does not fit in i32 cannot be reported as "grow and
    // retry". Returning the saturated max would look like a full write.
    let Ok(need) = i32::try_from(reply.len()) else {
        return -1;
    };
    if out_cap < 0 || reply.len() > out_cap as usize {
        return need;
    }
    let Some(memory) = guest_memory(caller) else {
        return -1;
    };
    let start = out_ptr as u32 as usize;
    let data = memory.data();
    let Some(end) = start.checked_add(reply.len()) else {
        return -1;
    };
    if end > data.len() {
        return -1;
    }
    for (slot, byte) in data[start..end].iter().zip(reply) {
        unsafe {
            *slot.get() = *byte;
        }
    }
    need
}

fn read_string(caller: &mut Caller<'_, State>, ptr: i32, len: i32) -> Result<String, String> {
    let bytes = read_bytes(caller, ptr, len)?;
    String::from_utf8(bytes).map_err(|_| "host exec argument is not utf-8".to_string())
}

fn guest_memory(caller: &mut Caller<'_, State>) -> Option<SharedMemory> {
    caller
        .get_export("memory")
        .and_then(|item| item.into_shared_memory())
}

fn read_bytes(caller: &mut Caller<'_, State>, ptr: i32, len: i32) -> Result<Vec<u8>, String> {
    if len < 0 {
        return Err("host exec length is negative".to_string());
    }
    if len == 0 {
        return Ok(Vec::new());
    }
    let memory =
        guest_memory(caller).ok_or_else(|| "wasm module has no memory export".to_string())?;
    let start = ptr as u32 as usize;
    let data = memory.data();
    let end = start
        .checked_add(len as usize)
        .filter(|end| *end <= data.len())
        .ok_or_else(|| "host exec pointer is outside wasm memory".to_string())?;
    let mut buf = vec![0u8; len as usize];
    for (slot, byte) in data[start..end].iter().zip(buf.iter_mut()) {
        *byte = unsafe { *slot.get() };
    }
    Ok(buf)
}
