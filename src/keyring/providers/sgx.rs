//! SGX signer

use crate::{
    chain,
    config::provider::sgx::SgxConfig,
    error::{Error, ErrorKind::*},
    keyring::{ed25519::Signer, SigningProvider},
    prelude::*,
};
use signatory_sgx::SignatorySgxSigner;
use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};
use tendermint::TendermintKey;

/// CreateSGX signer object from the given configuration
pub fn init(chain_registry: &mut chain::Registry, sgx_configs: &[SgxConfig]) -> Result<(), Error> {
    if sgx_configs.is_empty() {
        return Ok(());
    }

    if sgx_configs.len() != 1 {
        fail!(
            ConfigError,
            "expected one [providers.sgx] in config, found: {}",
            sgx_configs.len()
        );
    }

    let provider = SignatorySgxSigner::launch_enclave_app(&sgx_configs[0].sgxs_path)
        .map_err(|_| Error::from(SigningError))?;
    if sgx_configs[0].sealed_key_path.exists() {
        let input_path = &sgx_configs[0].sealed_key_path;
        let mut file = std::fs::File::open(input_path).map_err(|e| {
            format_err!(
                ConfigError,
                "couldn't open `{}`: {}",
                input_path.display(),
                e
            )
        })?;
        let sealed_data = bincode::deserialize_from(&mut file).map_err(|e| {
            format_err!(
                ConfigError,
                "couldn't read from `{}`: {}",
                input_path.display(),
                e
            )
        })?;
        let _public = provider
            .import(sealed_data)
            .map_err(|e| format_err!(ConfigError, "can't import key: {}", e))?;
    } else {
        let sealed_data = provider
            .keygen()
            .map_err(|e| format_err!(ConfigError, "can't generate key: {}", e))?;
        let output_path = &sgx_configs[0].sealed_key_path;
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(output_path)
            .map_err(|e| {
                format_err!(
                    ConfigError,
                    "couldn't open `{}`: {}",
                    output_path.display(),
                    e
                )
            })?;
        bincode::serialize_into(&mut file, &sealed_data).unwrap_or_else(|e| {
            status_err!("couldn't write to `{}`: {}", output_path.display(), e);
            std::process::exit(1);
        });
    }
    let public_key = ed25519_dalek::PublicKey::from_bytes(
        &provider.public_key().map_err(|_| Error::from(InvalidKey))?,
    )
    .map_err(|_| Error::from(InvalidKey))?;

    // TODO(tarcieri): support for adding account keys into keyrings
    let consensus_pubkey = TendermintKey::ConsensusKey(public_key.into());

    let signer = Signer::new(SigningProvider::Sgx, consensus_pubkey, Box::new(provider));
    chain_registry.add_consensus_key(&sgx_configs[0].chain_id, signer)?;

    Ok(())
}
