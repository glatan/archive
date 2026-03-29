//! Folder DAG normalization and validation for 7z decode.

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

use super::METHOD_7Z_AES;
use super::parse::Folder;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InputSource {
    Packed(usize),
    Output(u64),
}

#[derive(Debug, Clone)]
pub(super) struct NormalizedFolderGraph {
    pub(super) total_outputs: usize,
    pub(super) input_sources: Vec<InputSource>,
    pub(super) output_owners: Vec<usize>,
    pub(super) output_consumers: Vec<Vec<u64>>,
    pub(super) final_outputs: Vec<u64>,
    pub(super) execution_order: Vec<usize>,
}

pub(super) fn normalize_folder_graph(folder: &Folder) -> Result<NormalizedFolderGraph, Error> {
    let total_inputs = folder.total_in_streams()? as usize;
    let total_outputs = folder.total_out_streams()? as usize;
    let mut input_sources = vec![None; total_inputs];
    let mut output_owners = vec![None; total_outputs];
    let mut output_consumers = vec![Vec::new(); total_outputs];

    for (coder_index, coder) in folder.coders.iter().enumerate() {
        let output_start = coder.output_index as usize;
        let output_end = output_start
            .checked_add(coder.num_out_streams as usize)
            .ok_or(Error::InvalidData("7z: coder output range overflow"))?;
        if output_end > total_outputs {
            return Err(Error::InvalidData("7z: coder output out of range"));
        }
        for owner in &mut output_owners[output_start..output_end] {
            if owner.is_some() {
                return Err(Error::InvalidData("7z: duplicate coder output ownership"));
            }
            *owner = Some(coder_index);
        }
    }

    for bind_pair in &folder.bind_pairs {
        let input_index = bind_pair.in_index as usize;
        if input_index >= total_inputs {
            return Err(Error::InvalidData("7z: bind pair input out of range"));
        }
        if bind_pair.out_index as usize >= total_outputs {
            return Err(Error::InvalidData("7z: bind pair output out of range"));
        }
        if input_sources[input_index].is_some() {
            return Err(Error::InvalidData("7z: duplicate folder input binding"));
        }
        input_sources[input_index] = Some(InputSource::Output(bind_pair.out_index));
        output_consumers[bind_pair.out_index as usize].push(bind_pair.in_index);
    }

    for (packed_slot, &packed_index) in folder.packed_streams.iter().enumerate() {
        let input_index = packed_index as usize;
        if input_index >= total_inputs {
            return Err(Error::InvalidData("7z: packed stream index out of range"));
        }
        if input_sources[input_index].is_some() {
            return Err(Error::InvalidData("7z: duplicate folder input binding"));
        }
        input_sources[input_index] = Some(InputSource::Packed(packed_slot));
    }

    let input_sources = input_sources
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or(Error::Unsupported("7z: unsupported folder graph"))?;
    let output_owners = output_owners
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or(Error::InvalidData("7z: missing coder output ownership"))?;
    let final_outputs = find_final_output_indices(folder)?;

    let mut produced_outputs = vec![false; total_outputs];
    let mut scheduled = vec![false; folder.coders.len()];
    let mut execution_order = Vec::with_capacity(folder.coders.len());

    while execution_order.len() < folder.coders.len() {
        let mut progress = false;
        for (coder_index, coder) in folder.coders.iter().enumerate() {
            if scheduled[coder_index] {
                continue;
            }
            let ready = (0..coder.num_in_streams).all(|input_offset| {
                let input_index = (coder.input_index + input_offset) as usize;
                matches!(input_sources[input_index], InputSource::Packed(_))
                    || matches!(
                        input_sources[input_index],
                        InputSource::Output(output_index) if produced_outputs[output_index as usize]
                    )
            });
            if !ready {
                continue;
            }
            let output_start = coder.output_index as usize;
            let output_end = output_start
                .checked_add(coder.num_out_streams as usize)
                .ok_or(Error::InvalidData("7z: coder output range overflow"))?;
            if output_end > total_outputs {
                return Err(Error::InvalidData("7z: coder output out of range"));
            }
            for produced in &mut produced_outputs[output_start..output_end] {
                *produced = true;
            }
            scheduled[coder_index] = true;
            execution_order.push(coder_index);
            progress = true;
        }

        if !progress {
            return Err(Error::Unsupported("7z: unsupported folder graph"));
        }
    }

    Ok(NormalizedFolderGraph {
        total_outputs,
        input_sources,
        output_owners,
        output_consumers,
        final_outputs,
        execution_order,
    })
}

pub(super) fn validate_execution_order(
    folder: &Folder,
    graph: &NormalizedFolderGraph,
) -> Result<(), Error> {
    let mut produced_outputs = vec![false; graph.total_outputs];
    for &coder_index in &graph.execution_order {
        let coder = folder
            .coders
            .get(coder_index)
            .ok_or(Error::InvalidData("7z: coder index out of range"))?;
        for input_offset in 0..coder.num_in_streams {
            let input_index = (coder.input_index + input_offset) as usize;
            match graph
                .input_sources
                .get(input_index)
                .ok_or(Error::InvalidData("7z: folder input out of range"))?
            {
                InputSource::Packed(_) => {}
                InputSource::Output(output_index) => {
                    if !produced_outputs
                        .get(*output_index as usize)
                        .copied()
                        .unwrap_or(false)
                    {
                        return Err(Error::InvalidData("7z: invalid execution order"));
                    }
                }
            }
        }
        let output_start = coder.output_index as usize;
        let output_end = output_start
            .checked_add(coder.num_out_streams as usize)
            .ok_or(Error::InvalidData("7z: coder output range overflow"))?;
        if output_end > produced_outputs.len() {
            return Err(Error::InvalidData("7z: coder output out of range"));
        }
        for produced in &mut produced_outputs[output_start..output_end] {
            *produced = true;
        }
    }
    Ok(())
}

pub(super) fn folder_uses_encryption(folder: &Folder) -> bool {
    folder
        .coders
        .iter()
        .any(|coder| is_encryption_method(&coder.method_id))
}

pub(super) fn is_encryption_method(method_id: &[u8]) -> bool {
    method_id == METHOD_7Z_AES || method_id.first() == Some(&0x06)
}

pub(super) fn find_final_output_indices(folder: &Folder) -> Result<Vec<u64>, Error> {
    let total_outputs = folder.total_out_streams()? as usize;
    let mut bound = vec![false; total_outputs];
    for bind_pair in &folder.bind_pairs {
        let index = bind_pair.out_index as usize;
        if index >= bound.len() {
            return Err(Error::InvalidData("7z: bind pair output out of range"));
        }
        bound[index] = true;
    }
    let final_outputs = bound
        .iter()
        .enumerate()
        .filter_map(|(index, is_bound)| (!is_bound).then_some(index as u64))
        .collect::<Vec<_>>();
    if final_outputs.is_empty() {
        return Err(Error::InvalidData("7z: missing final output stream"));
    }
    Ok(final_outputs)
}

pub(super) fn folder_total_final_unpack_size(folder: &Folder) -> Result<u64, Error> {
    let mut total_size = 0u64;
    for output_index in find_final_output_indices(folder)? {
        let unpack_size = *folder
            .unpack_sizes
            .get(output_index as usize)
            .ok_or(Error::InvalidData("7z: missing final unpack size"))?;
        total_size = total_size
            .checked_add(unpack_size)
            .ok_or(Error::InvalidData("7z: final unpack size overflow"))?;
    }
    Ok(total_size)
}
