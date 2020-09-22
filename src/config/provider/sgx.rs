//! Configuration for SGX signer

use crate::chain;
use serde::Deserialize;
use std::path::PathBuf;

/// SGX signer configuration
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct SgxConfig {
    /// Chain this signing key is authorized to be used from
    pub chain_id: chain::Id,
    /// Path to a *.sgxs + *.sig signatory enclave app files
    pub sgxs_path: PathBuf,
    /// Path to the sealed key
    pub sealed_key_path: PathBuf,
}
