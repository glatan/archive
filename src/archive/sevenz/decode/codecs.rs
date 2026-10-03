//! Codec execution for 7z folder decoding.

use alloc::vec;
use alloc::vec::Vec;

use super::super::bcj2;
use crate::compress::bcj;
use crate::compress::delta;
use crate::compress::lzma::{LzmaProperties, lzma_decode_with_props_and_size};
use crate::compress::lzma2;
use crate::compress::ppmd;
use crate::error::Error;
use crate::util::aes256::Aes256;
use crate::util::sha256::Sha256;

use super::graph::{
    InputSource, NormalizedFolderGraph, is_encryption_method, normalize_folder_graph,
    validate_execution_order,
};
use super::parse::{Coder, Folder};
use super::{
    METHOD_7Z_AES, METHOD_BCJ_ARM, METHOD_BCJ_ARM64, METHOD_BCJ_ARMTHUMB, METHOD_BCJ_IA64,
    METHOD_BCJ_POWERPC, METHOD_BCJ_RISCV, METHOD_BCJ_SPARC, METHOD_BCJ_X86, METHOD_BCJ2_X86,
    METHOD_BROTLI, METHOD_BZIP2, METHOD_COPY, METHOD_DEFLATE, METHOD_DEFLATE64, METHOD_DELTA,
    METHOD_LZMA, METHOD_LZMA2, METHOD_PPMD, METHOD_ZSTD,
};

pub(super) fn decode_folder(
    folder: &Folder,
    packed: &[&[u8]],
    password: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    if packed.len() != folder.packed_streams.len() {
        return Err(Error::UnexpectedEof);
    }
    let graph = normalize_folder_graph(folder)?;
    let requested_outputs = graph
        .output_consumers
        .iter()
        .enumerate()
        .filter_map(|(index, consumers)| consumers.is_empty().then_some(index as u64))
        .collect::<Vec<_>>();
    if requested_outputs != graph.final_outputs {
        return Err(Error::InvalidData("7z: inconsistent final output graph"));
    }
    validate_execution_order(folder, &graph)?;
    let mut outputs: Vec<Option<Vec<u8>>> = vec![None; graph.total_outputs];
    let mut active_coders = vec![false; folder.coders.len()];
    let mut unpacked = Vec::new();
    for &final_output in &graph.final_outputs {
        let stream = resolve_folder_output(
            folder,
            packed,
            password,
            &graph,
            &mut outputs,
            &mut active_coders,
            final_output as usize,
        )?;
        unpacked.extend_from_slice(&stream);
    }
    Ok(unpacked)
}

fn resolve_folder_output(
    folder: &Folder,
    packed: &[&[u8]],
    password: Option<&[u8]>,
    graph: &NormalizedFolderGraph,
    outputs: &mut [Option<Vec<u8>>],
    active_coders: &mut [bool],
    output_index: usize,
) -> Result<Vec<u8>, Error> {
    let Some(output) = outputs.get(output_index) else {
        return Err(Error::InvalidData("7z: folder output out of range"));
    };
    if let Some(data) = output {
        return Ok(data.clone());
    }

    let coder_index = *graph
        .output_owners
        .get(output_index)
        .ok_or(Error::InvalidData("7z: folder output out of range"))?;
    decode_folder_coder(
        folder,
        packed,
        password,
        graph,
        outputs,
        active_coders,
        coder_index,
    )?;
    outputs
        .get(output_index)
        .and_then(|slot| slot.as_ref())
        .cloned()
        .ok_or(Error::InvalidData("7z: missing final output stream"))
}

fn decode_folder_coder(
    folder: &Folder,
    packed: &[&[u8]],
    password: Option<&[u8]>,
    graph: &NormalizedFolderGraph,
    outputs: &mut [Option<Vec<u8>>],
    active_coders: &mut [bool],
    coder_index: usize,
) -> Result<(), Error> {
    let coder = folder
        .coders
        .get(coder_index)
        .ok_or(Error::InvalidData("7z: coder index out of range"))?;
    let output_start = coder.output_index as usize;
    let output_end = output_start
        .checked_add(coder.num_out_streams as usize)
        .ok_or(Error::InvalidData("7z: coder output range overflow"))?;
    if output_end > outputs.len() {
        return Err(Error::InvalidData("7z: coder output out of range"));
    }
    if outputs[output_start..output_end]
        .iter()
        .all(|slot| slot.is_some())
    {
        return Ok(());
    }
    if active_coders
        .get(coder_index)
        .copied()
        .ok_or(Error::InvalidData("7z: coder index out of range"))?
    {
        return Err(Error::Unsupported("7z: unsupported folder graph"));
    }
    active_coders[coder_index] = true;

    let result = (|| {
        let mut inputs = Vec::with_capacity(coder.num_in_streams as usize);
        for input_offset in 0..coder.num_in_streams {
            let input_index = coder.input_index + input_offset;
            match graph
                .input_sources
                .get(input_index as usize)
                .ok_or(Error::InvalidData("7z: folder input out of range"))?
            {
                InputSource::Packed(packed_slot) => {
                    let Some(data) = packed.get(*packed_slot) else {
                        return Err(Error::InvalidData("7z: packed stream index out of range"));
                    };
                    inputs.push((*data).to_vec());
                }
                InputSource::Output(output_index) => {
                    inputs.push(resolve_folder_output(
                        folder,
                        packed,
                        password,
                        graph,
                        outputs,
                        active_coders,
                        *output_index as usize,
                    )?);
                }
            }
        }

        let expected_sizes = folder
            .unpack_sizes
            .get(output_start..output_end)
            .ok_or(Error::InvalidData("7z: missing coder unpack size"))?
            .iter()
            .map(|&size| size as usize)
            .collect::<Vec<_>>();
        let decoded_outputs = decode_coder(coder, &inputs, &expected_sizes, password)?;
        if decoded_outputs.len() != expected_sizes.len() {
            return Err(Error::InvalidData(
                "7z: coder produced unexpected output count",
            ));
        }
        for (slot, decoded) in outputs[output_start..output_end]
            .iter_mut()
            .zip(decoded_outputs)
        {
            *slot = Some(decoded);
        }
        Ok(())
    })();

    active_coders[coder_index] = false;
    result
}

pub(super) fn decode_coder(
    coder: &Coder,
    inputs: &[Vec<u8>],
    expected_sizes: &[usize],
    password: Option<&[u8]>,
) -> Result<Vec<Vec<u8>>, Error> {
    if expected_sizes.len() != coder.num_out_streams as usize {
        return Err(Error::InvalidData("7z: missing coder unpack size"));
    }

    if coder.method_id == METHOD_BCJ2_X86 {
        if inputs.len() != 4 || expected_sizes.len() != 1 {
            return Err(Error::Unsupported(
                "7z: non-BCJ2 multi-input coder methods are not supported",
            ));
        }
        let output = bcj2::decode(
            &inputs[0],
            &inputs[1],
            &inputs[2],
            &inputs[3],
            expected_sizes[0],
        )?;
        if output.len() != expected_sizes[0] {
            return Err(Error::SizeMismatch {
                expected: expected_sizes[0] as u32,
                actual: output.len() as u32,
            });
        }
        return Ok(vec![output]);
    }

    if expected_sizes.len() != 1 {
        return Err(Error::Unsupported(
            "7z: multi-output coder methods are not supported",
        ));
    }
    let expected_size = expected_sizes[0];

    let output = if coder.method_id == METHOD_COPY {
        if inputs.len() != 1 {
            return Err(Error::Unsupported(
                "7z: non-BCJ2 multi-input coder methods are not supported",
            ));
        }
        inputs[0].clone()
    } else if coder.method_id == METHOD_7Z_AES {
        if inputs.len() != 1 {
            return Err(Error::Unsupported(
                "7z: non-BCJ2 multi-input coder methods are not supported",
            ));
        }
        decode_7z_aes(&inputs[0], &coder.properties, expected_size, password)?
    } else if coder.method_id == METHOD_LZMA2 {
        if inputs.len() != 1 {
            return Err(Error::Unsupported(
                "7z: non-BCJ2 multi-input coder methods are not supported",
            ));
        }
        let dict_size = decode_lzma2_dict_size(&coder.properties)?;
        lzma2::lzma2_decode(&inputs[0], dict_size)?
    } else if coder.method_id == METHOD_LZMA {
        if inputs.len() != 1 {
            return Err(Error::Unsupported(
                "7z: non-BCJ2 multi-input coder methods are not supported",
            ));
        }
        let (props, dict_size) = decode_lzma_props(&coder.properties)?;
        lzma_decode_with_props_and_size(&inputs[0], dict_size, props, expected_size)?.0
    } else if coder.method_id == METHOD_PPMD {
        if inputs.len() != 1 {
            return Err(Error::Unsupported(
                "7z: non-BCJ2 multi-input coder methods are not supported",
            ));
        }
        let props = ppmd::Ppmd7Properties::from_sevenz_properties(&coder.properties)?;
        ppmd::decode(&inputs[0], props, expected_size)?
    } else if coder.method_id == METHOD_BCJ_X86 {
        if inputs.len() != 1 {
            return Err(Error::Unsupported(
                "7z: non-BCJ2 multi-input coder methods are not supported",
            ));
        }
        bcj::x86_decode(&inputs[0], 0)
    } else if coder.method_id == METHOD_BCJ_POWERPC {
        if inputs.len() != 1 {
            return Err(Error::Unsupported(
                "7z: non-BCJ2 multi-input coder methods are not supported",
            ));
        }
        bcj::powerpc_decode(&inputs[0], 0)
    } else if coder.method_id == METHOD_BCJ_IA64 {
        if inputs.len() != 1 {
            return Err(Error::Unsupported(
                "7z: non-BCJ2 multi-input coder methods are not supported",
            ));
        }
        bcj::ia64_decode(&inputs[0], 0)
    } else if coder.method_id == METHOD_BCJ_ARM {
        if inputs.len() != 1 {
            return Err(Error::Unsupported(
                "7z: non-BCJ2 multi-input coder methods are not supported",
            ));
        }
        bcj::arm_decode(&inputs[0], 0)
    } else if coder.method_id == METHOD_BCJ_ARMTHUMB {
        if inputs.len() != 1 {
            return Err(Error::Unsupported(
                "7z: non-BCJ2 multi-input coder methods are not supported",
            ));
        }
        bcj::armthumb_decode(&inputs[0], 0)
    } else if coder.method_id == METHOD_BCJ_SPARC {
        if inputs.len() != 1 {
            return Err(Error::Unsupported(
                "7z: non-BCJ2 multi-input coder methods are not supported",
            ));
        }
        bcj::sparc_decode(&inputs[0], 0)
    } else if coder.method_id == METHOD_BCJ_ARM64 {
        if inputs.len() != 1 {
            return Err(Error::Unsupported(
                "7z: non-BCJ2 multi-input coder methods are not supported",
            ));
        }
        bcj::arm64_decode(&inputs[0], 0)
    } else if coder.method_id == METHOD_BCJ_RISCV {
        if inputs.len() != 1 {
            return Err(Error::Unsupported(
                "7z: non-BCJ2 multi-input coder methods are not supported",
            ));
        }
        bcj::riscv_decode(&inputs[0], 0)
    } else if coder.method_id == METHOD_DELTA {
        if inputs.len() != 1 {
            return Err(Error::Unsupported(
                "7z: non-BCJ2 multi-input coder methods are not supported",
            ));
        }
        let distance = decode_delta_distance(&coder.properties)?;
        delta::decode(&inputs[0], distance)?
    } else if coder.method_id == METHOD_DEFLATE {
        if inputs.len() != 1 {
            return Err(Error::Unsupported(
                "7z: non-BCJ2 multi-input coder methods are not supported",
            ));
        }
        crate::compress::deflate::decode::decode(&inputs[0])?
    } else if coder.method_id == METHOD_DEFLATE64 {
        if inputs.len() != 1 {
            return Err(Error::Unsupported(
                "7z: non-BCJ2 multi-input coder methods are not supported",
            ));
        }
        crate::compress::deflate64::decode::decode(&inputs[0])?
    } else if coder.method_id == METHOD_BZIP2 {
        if inputs.len() != 1 {
            return Err(Error::Unsupported(
                "7z: non-BCJ2 multi-input coder methods are not supported",
            ));
        }
        crate::compress::bzip2::decode::decode(&inputs[0])?
    } else if coder.method_id == METHOD_ZSTD {
        if inputs.len() != 1 {
            return Err(Error::Unsupported(
                "7z: non-BCJ2 multi-input coder methods are not supported",
            ));
        }
        #[cfg(feature = "zstd")]
        {
            crate::compress::zstd::decode::decode(&inputs[0])?
        }
        #[cfg(not(feature = "zstd"))]
        {
            return Err(Error::Unsupported("7z: zstd feature not enabled"));
        }
    } else if coder.method_id == METHOD_BROTLI {
        if inputs.len() != 1 {
            return Err(Error::Unsupported(
                "7z: non-BCJ2 multi-input coder methods are not supported",
            ));
        }
        #[cfg(feature = "brotli")]
        {
            crate::compress::brotli::decode::decode(&inputs[0])?
        }
        #[cfg(not(feature = "brotli"))]
        {
            return Err(Error::Unsupported("7z: brotli feature not enabled"));
        }
    } else if is_encryption_method(&coder.method_id) {
        return Err(Error::Unsupported("7z: unsupported encryption method"));
    } else {
        return Err(Error::Unsupported("7z: unsupported coder method"));
    };

    if output.len() != expected_size {
        return Err(Error::SizeMismatch {
            expected: expected_size as u32,
            actual: output.len() as u32,
        });
    }
    Ok(vec![output])
}

pub(super) fn decode_7z_aes(
    input: &[u8],
    properties: &[u8],
    expected_size: usize,
    password: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    let password = password.ok_or(Error::Unsupported(
        "7z: encrypted archive requires a password",
    ))?;
    let props = parse_7z_aes_properties(properties)?;
    let key = derive_7z_aes_key(password, &props)?;
    let cipher = Aes256::new(&key);
    cipher.decrypt_cbc_truncated(input, &props.iv, expected_size)
}

#[derive(Debug, Clone)]
pub(crate) struct SevenZAesProperties {
    pub(super) num_cycles_power: u8,
    pub(super) salt: Vec<u8>,
    pub(crate) iv: [u8; 16],
}

pub(crate) fn parse_7z_aes_properties(properties: &[u8]) -> Result<SevenZAesProperties, Error> {
    if properties.is_empty() {
        return Ok(SevenZAesProperties {
            num_cycles_power: 0,
            salt: Vec::new(),
            iv: [0; 16],
        });
    }

    let first = properties[0];
    let num_cycles_power = first & 0x3F;
    if num_cycles_power > 24 && num_cycles_power != 0x3F {
        return Err(Error::Unsupported(
            "7z: unsupported AES key derivation cost",
        ));
    }
    if (first & 0xC0) == 0 {
        if properties.len() != 1 {
            return Err(Error::InvalidData("7z: invalid AES properties"));
        }
        return Ok(SevenZAesProperties {
            num_cycles_power,
            salt: Vec::new(),
            iv: [0; 16],
        });
    }
    if properties.len() < 2 {
        return Err(Error::InvalidData("7z: truncated AES properties"));
    }

    let second = properties[1];
    let salt_size = usize::from((first >> 7) & 1) + usize::from(second >> 4);
    let iv_size = usize::from((first >> 6) & 1) + usize::from(second & 0x0F);
    let expected_len = 2 + salt_size + iv_size;
    if properties.len() != expected_len || salt_size > 16 || iv_size > 16 {
        return Err(Error::InvalidData("7z: invalid AES properties"));
    }

    let mut iv = [0u8; 16];
    let salt = properties[2..2 + salt_size].to_vec();
    iv[..iv_size].copy_from_slice(&properties[2 + salt_size..expected_len]);

    Ok(SevenZAesProperties {
        num_cycles_power,
        salt,
        iv,
    })
}

pub(crate) fn derive_7z_aes_key(
    password: &[u8],
    properties: &SevenZAesProperties,
) -> Result<[u8; 32], Error> {
    if properties.num_cycles_power == 0x3F {
        let mut key = [0u8; 32];
        let mut pos = 0usize;
        for &byte in &properties.salt {
            if pos == key.len() {
                return Ok(key);
            }
            key[pos] = byte;
            pos += 1;
        }
        for &byte in password {
            if pos == key.len() {
                return Ok(key);
            }
            key[pos] = byte;
            pos += 1;
        }
        return Ok(key);
    }

    let rounds = 1u32 << properties.num_cycles_power;
    let mut hasher = Sha256::new();
    for counter in 0..rounds {
        hasher.update(&properties.salt);
        hasher.update(password);
        hasher.update(&(counter as u64).to_le_bytes());
    }
    Ok(hasher.finish())
}

pub(crate) fn encode_password_utf16le(password: &str) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(password.len() * 2);
    for unit in password.encode_utf16() {
        encoded.extend_from_slice(&unit.to_le_bytes());
    }
    encoded
}

fn decode_lzma_props(properties: &[u8]) -> Result<(LzmaProperties, u32), Error> {
    if properties.len() != 5 {
        return Err(Error::InvalidData("7z: LZMA properties must be 5 bytes"));
    }
    let props = LzmaProperties::from_props_byte(properties[0])?;
    let dict_size =
        u32::from_le_bytes([properties[1], properties[2], properties[3], properties[4]]);
    Ok((props, dict_size.max(1)))
}

fn decode_lzma2_dict_size(properties: &[u8]) -> Result<u32, Error> {
    if properties.len() != 1 {
        return Err(Error::InvalidData("7z: LZMA2 properties must be 1 byte"));
    }
    let prop = properties[0];
    if prop > 40 {
        return Err(Error::InvalidData("7z: invalid LZMA2 dictionary property"));
    }
    if prop == 40 {
        return Ok(u32::MAX);
    }
    let base = 2u32 | u32::from(prop & 1);
    let shift = u32::from(prop / 2) + 11;
    Ok(base << shift)
}

fn decode_delta_distance(properties: &[u8]) -> Result<usize, Error> {
    if properties.len() != 1 {
        return Err(Error::InvalidData("7z: Delta properties must be 1 byte"));
    }
    Ok(properties[0] as usize + 1)
}
