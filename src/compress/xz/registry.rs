use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::error::Error;

/// Smallest filter ID reserved for application-defined xz filters.
pub const MIN_CUSTOM_FILTER_ID: u64 = 0x0C;

/// Application-defined codec for a custom xz filter ID.
///
/// Implement this trait to teach the registry-aware encode/decode APIs how to
/// handle a non-standard filter. The crate's built-in filters (LZMA2, BCJ,
/// Delta) are handled internally and do not go through this trait.
pub trait FilterCodec {
    /// The xz filter ID this codec handles.
    fn filter_id(&self) -> u64;

    /// Transform `input` during compression, given the filter's property bytes.
    fn encode(&self, input: &[u8], properties: &[u8]) -> Result<Vec<u8>, Error>;

    /// Reverse the transformation during decompression.
    fn decode(&self, input: &[u8], properties: &[u8]) -> Result<Vec<u8>, Error>;
}

/// Registry of application-defined [`FilterCodec`] implementations.
///
/// Pass an instance to [`super::encode::encode_with_filters_and_registry`] or
/// [`super::decode::decode_with_registry`] to handle custom filter IDs that
/// the crate does not support natively.
#[derive(Default)]
pub struct FilterRegistry {
    codecs: BTreeMap<u64, Box<dyn FilterCodec>>,
}

impl FilterRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a custom [`FilterCodec`].
    ///
    /// Returns an error if a codec with the same filter ID is already registered.
    pub fn register(&mut self, codec: Box<dyn FilterCodec>) -> Result<(), Error> {
        let filter_id = codec.filter_id();
        if self.codecs.insert(filter_id, codec).is_some() {
            return Err(Error::InvalidData(
                "xz: duplicate custom filter registration",
            ));
        }
        Ok(())
    }

    /// Register an identity codec for an application-defined custom filter ID.
    ///
    /// This is useful when a caller wants an xz stream carrying a known custom
    /// filter ID to roundtrip through the registry-aware encode/decode APIs
    /// without transforming the payload. Standard built-in filter IDs remain
    /// reserved for the crate's dedicated implementations.
    pub fn register_passthrough(&mut self, filter_id: u64) -> Result<(), Error> {
        if filter_id < MIN_CUSTOM_FILTER_ID || filter_id == 0x21 {
            return Err(Error::InvalidData(
                "xz: passthrough registration requires an application-defined custom filter ID",
            ));
        }
        self.register(Box::new(PassthroughCodec(filter_id)))
    }

    /// Look up a registered codec by filter ID.
    pub fn get(&self, filter_id: u64) -> Option<&dyn FilterCodec> {
        self.codecs.get(&filter_id).map(Box::as_ref)
    }
}

struct PassthroughCodec(u64);

impl FilterCodec for PassthroughCodec {
    fn filter_id(&self) -> u64 {
        self.0
    }

    fn encode(&self, input: &[u8], _properties: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(input.to_vec())
    }

    fn decode(&self, input: &[u8], _properties: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(input.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_registry_register_and_get() {
        let mut registry = FilterRegistry::new();
        registry
            .register(Box::new(PassthroughCodec(0x1234)))
            .unwrap();
        assert!(registry.get(0x1234).is_some());
        assert!(registry.get(0x9999).is_none());
    }

    #[test]
    fn test_filter_registry_register_passthrough() {
        let mut registry = FilterRegistry::new();
        registry.register_passthrough(0x1234).unwrap();
        let codec = registry.get(0x1234).unwrap();
        assert_eq!(codec.encode(b"abc", &[1, 2, 3]).unwrap(), b"abc");
        assert_eq!(codec.decode(b"xyz", &[4, 5]).unwrap(), b"xyz");
    }

    #[test]
    fn test_filter_registry_register_passthrough_rejects_builtin_ids() {
        let mut registry = FilterRegistry::new();
        assert!(matches!(
            registry.register_passthrough(0x03),
            Err(Error::InvalidData(
                "xz: passthrough registration requires an application-defined custom filter ID"
            ))
        ));
        assert!(matches!(
            registry.register_passthrough(0x21),
            Err(Error::InvalidData(
                "xz: passthrough registration requires an application-defined custom filter ID"
            ))
        ));
    }
}
