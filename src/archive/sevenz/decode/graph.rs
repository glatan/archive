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
    let total_inputs = usize::try_from(folder.total_in_streams()?)
        .map_err(|_| Error::InvalidData("7z: count exceeds decode limit"))?;
    let total_outputs = usize::try_from(folder.total_out_streams()?)
        .map_err(|_| Error::InvalidData("7z: count exceeds decode limit"))?;
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
        let input_index = usize::try_from(bind_pair.in_index)
            .map_err(|_| Error::InvalidData("7z: bind pair input out of range"))?;
        let output_index = usize::try_from(bind_pair.out_index)
            .map_err(|_| Error::InvalidData("7z: bind pair output out of range"))?;
        if input_index >= total_inputs {
            return Err(Error::InvalidData("7z: bind pair input out of range"));
        }
        if output_index >= total_outputs {
            return Err(Error::InvalidData("7z: bind pair output out of range"));
        }
        if input_sources[input_index].is_some() {
            return Err(Error::InvalidData("7z: duplicate folder input binding"));
        }
        input_sources[input_index] = Some(InputSource::Output(bind_pair.out_index));
        output_consumers[output_index].push(bind_pair.in_index);
    }

    for (packed_slot, &packed_index) in folder.packed_streams.iter().enumerate() {
        let input_index = usize::try_from(packed_index)
            .map_err(|_| Error::InvalidData("7z: packed stream index out of range"))?;
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
    let total_outputs = usize::try_from(folder.total_out_streams()?)
        .map_err(|_| Error::InvalidData("7z: count exceeds decode limit"))?;
    let mut bound = vec![false; total_outputs];
    for bind_pair in &folder.bind_pairs {
        let index = usize::try_from(bind_pair.out_index)
            .map_err(|_| Error::InvalidData("7z: bind pair output out of range"))?;
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

#[cfg(test)]
mod tests {
    use super::super::parse::{BindPair, Coder};
    use super::*;

    fn coder(
        method: u8,
        num_in_streams: u64,
        num_out_streams: u64,
        input_index: u64,
        output_index: u64,
    ) -> Coder {
        Coder {
            method_id: alloc::vec![method],
            properties: Vec::new(),
            num_in_streams,
            num_out_streams,
            input_index,
            output_index,
        }
    }

    fn folder(
        coders: Vec<Coder>,
        bind_pairs: Vec<BindPair>,
        packed_streams: Vec<u64>,
        unpack_sizes: Vec<u64>,
    ) -> Folder {
        Folder {
            coders,
            bind_pairs,
            packed_streams,
            unpack_sizes,
            crc32: None,
        }
    }

    #[test]
    fn normalizes_single_coder_folder() {
        let folder = folder(
            alloc::vec![coder(0, 1, 1, 0, 0)],
            Vec::new(),
            alloc::vec![0],
            alloc::vec![4],
        );
        let graph = normalize_folder_graph(&folder).unwrap();

        assert_eq!(graph.total_outputs, 1);
        assert!(matches!(graph.input_sources[0], InputSource::Packed(0)));
        assert_eq!(graph.output_owners, alloc::vec![0]);
        assert_eq!(graph.final_outputs, alloc::vec![0]);
        assert_eq!(graph.execution_order, alloc::vec![0]);
        assert!(validate_execution_order(&folder, &graph).is_ok());
    }

    #[test]
    fn rejects_duplicate_ownership_and_unbound_inputs() {
        let duplicate = folder(
            alloc::vec![coder(0, 1, 1, 0, 0), coder(0, 1, 1, 1, 0)],
            Vec::new(),
            alloc::vec![0, 1],
            alloc::vec![1, 1],
        );
        assert!(matches!(
            normalize_folder_graph(&duplicate),
            Err(Error::InvalidData("7z: duplicate coder output ownership"))
        ));

        let unbound = folder(
            alloc::vec![coder(0, 1, 1, 0, 0)],
            Vec::new(),
            Vec::new(),
            alloc::vec![1],
        );
        assert!(matches!(
            normalize_folder_graph(&unbound),
            Err(Error::Unsupported("7z: unsupported folder graph"))
        ));
    }

    #[test]
    fn rejects_missing_final_output() {
        let folder = folder(
            alloc::vec![coder(0, 1, 2, 0, 0)],
            alloc::vec![
                BindPair {
                    in_index: 0,
                    out_index: 0,
                },
                BindPair {
                    in_index: 0,
                    out_index: 1,
                },
            ],
            alloc::vec![0],
            alloc::vec![1, 1],
        );
        assert!(matches!(
            find_final_output_indices(&folder),
            Err(Error::InvalidData("7z: missing final output stream"))
        ));
    }

    #[test]
    fn validates_execution_order() {
        let folder = folder(
            alloc::vec![coder(0, 1, 1, 0, 0), coder(0, 1, 1, 1, 1)],
            alloc::vec![BindPair {
                in_index: 1,
                out_index: 0,
            }],
            alloc::vec![0],
            alloc::vec![1, 1],
        );
        let mut graph = normalize_folder_graph(&folder).unwrap();
        assert_eq!(graph.execution_order, alloc::vec![0, 1]);
        assert!(validate_execution_order(&folder, &graph).is_ok());

        graph.execution_order = alloc::vec![1, 0];
        assert!(matches!(
            validate_execution_order(&folder, &graph),
            Err(Error::InvalidData("7z: invalid execution order"))
        ));
    }

    #[test]
    fn detects_encryption_methods() {
        assert!(is_encryption_method(METHOD_7Z_AES));
        assert!(is_encryption_method(&[0x06, 0xF1, 0x07, 0x01]));
        assert!(!is_encryption_method(&[0x03, 0x01, 0x01]));
    }
}
