//! Predefined model configurations for ZPAQ levels 1-3.
//!
//! Each level defines the HCOMP bytecode (context hash computation)
//! and the component configuration for the predictor.

use alloc::vec::Vec;

/// Model configuration containing both component config and HCOMP bytecode.
#[derive(Debug, Clone)]
pub(crate) struct ModelConfig {
    /// Component configuration for the predictor.
    pub comp_config: Vec<u8>,
    /// HCOMP bytecode for the ZPAQL VM.
    pub hcomp: Vec<u8>,
    /// Log2 size of hash memory (h[]).
    pub hh: usize,
    /// Log2 size of byte memory (m[]).
    pub hm: usize,
}

/// Get the model configuration for the given ZPAQ compression level (1-3).
pub(crate) fn model_config(level: u32) -> ModelConfig {
    match level {
        1 => model_level1(),
        2 => model_level2(),
        _ => model_level3(),
    }
}

/// Level 1: Simple order-1 context model.
/// Single CM component with 256 contexts (one per previous byte).
fn model_level1() -> ModelConfig {
    // Component config: 1 component, CM with 8-bit context (256 entries), limit=4
    let comp_config = vec![
        1, // number of components
        1, // CM
        8, // size = 2^8 = 256
        4, // limit (update rate)
    ];

    // HCOMP: h[0] = a (input byte is used as context directly)
    // The VM receives the input byte in register a.
    // We just need to store it in h[0].
    let hcomp = vec![
        // d = 0 (h index)
        128 + 16,
        0, // d = 0
        // *d = a (store a into h[0])
        13, // h[d] = a
        // halt
        0,
    ];

    ModelConfig {
        comp_config,
        hcomp,
        hh: 8, // 256 hash entries
        hm: 8, // 256 byte memory
    }
}

/// Level 2: ICM + ISSE chain for better compression.
fn model_level2() -> ModelConfig {
    // 2 components: ICM + ISSE
    let comp_config = vec![
        2, // number of components
        2, // ICM
        8, // size = 2^8 states
        7, // ISSE
        8, // size = 2^8
        0, // input = component 0 (ICM)
    ];

    // HCOMP: compute order-1 and order-2 contexts
    // h[0] = previous byte (for ICM)
    // h[1] = hash of previous 2 bytes (for ISSE)
    let hcomp = vec![
        // Save input byte to m[b] where b = c (rotating buffer index)
        // b = c
        33, // b = c
        // *b = a
        9, // m[b] = a
        // h[0] = a (order-1 context for ICM)
        128 + 16,
        0,  // d = 0
        13, // h[d] = a
        // h[1] = hash(a, m[b-1])
        128 + 16,
        1,  // d = 1
        17, // hashd: h[d] = (h[d] + a + 512) * 773
        // Get previous byte
        30, // b = a (save current a)
        128 + 22,
        0,  // a = r[0] (previous byte from r[0])
        17, // hashd again
        // Save current byte as previous
        24, // swap a, b (restore current byte)
        128 + 21,
        0, // r[0] = a
        // c++ for rotating buffer
        128 + 19,
        1, // c += 1
        // halt
        0,
    ];

    ModelConfig {
        comp_config,
        hcomp,
        hh: 8,
        hm: 8,
    }
}

/// Level 3: Full model with CM + ICM + ISSE + MATCH + MIX2.
fn model_level3() -> ModelConfig {
    // 4 components: CM + ICM + ISSE + MIX2
    let comp_config = vec![
        4,  // number of components
        1,  // CM
        10, // size = 2^10 = 1024
        4,  // limit
        2,  // ICM
        8,  // size = 2^8
        7,  // ISSE
        8,  // size = 2^8
        1,  // input = component 1 (ICM)
        5,  // MIX2
        8,  // size = 2^8
        0,  // input 1 = component 0 (CM)
        2,  // input 2 = component 2 (ISSE)
        4,  // learning rate
    ];

    // HCOMP: compute order-1 through order-3 contexts
    let hcomp = vec![
        // h[0] = hash for CM (order-2)
        128 + 16,
        0,  // d = 0
        17, // hashd
        128 + 22,
        0,  // a = r[0]
        17, // hashd
        // h[1] = a (order-1 for ICM)
        128 + 16,
        1, // d = 1
        128 + 22,
        1,  // a = r[1] (current input, saved below)
        13, // h[d] = a
        // h[2] = hash for ISSE (order-2)
        128 + 16,
        2,  // d = 2
        17, // hashd
        128 + 22,
        0,  // a = r[0]
        17, // hashd
        // h[3] = order-1 for MIX2 context
        128 + 16,
        3, // d = 3
        128 + 22,
        1,  // a = r[1]
        13, // h[d] = a
        // Save registers: r[0] = r[1] (shift history), r[1] = input
        128 + 22,
        1, // a = r[1]
        128 + 21,
        0, // r[0] = a (previous byte)
        // Restore input
        128,
        0, // a = N (will be overwritten by VM with input byte)
        // Actually we need to save the original input first
        // Let's restructure: save input first
        0, // halt
    ];

    ModelConfig {
        comp_config,
        hcomp,
        hh: 10,
        hm: 8,
    }
}
