//! Host process for the wasm32 simd128 fuzz guest.
//!
//! The Unix external-tool path lives in `external`. This binary does not run
//! the harness itself, so the rest of that module is unused here.
#![allow(dead_code)]

mod algorithms;
mod external;
mod host_proto;
mod wasm_embed;

fn main() {
    if let Err(err) = wasm_embed::run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
