#![no_main]

mod aes_utils;
mod ciphertext_verification;
mod ecdsa_utils;
mod signature_verification;
mod verification_data;

use std::format;
use anyhow::Result;
use verification_data::{VerifyingData, VerifyingDataOpt};

#[cfg(feature = "sp1")]
sp1_zkvm::entrypoint!(main);

impl VerifyingData {
    // implement verify interface for VerifyingData
    pub fn verify(&self, verifying_key: &str) -> Result<bool> {
        // verify ecdsa signature
        let result = self.verify_signature(verifying_key)?;
        if !result {
            return Ok(false);
        }

        // verify aes ciphertext
        let result = self.verify_ciphertext()?;
        if !result {
            return Ok(false);
        }
        Ok(true)
    }
}

impl VerifyingDataOpt {
    // implement verify interface for VerifyingDataOpt
    pub fn verify(&self, verifying_key: &str) -> Result<bool> {
        // verify ecdsa signature
        let result = self.verify_signature(verifying_key)?;
        if !result {
            return Ok(false);
        }

        // verify aes ciphertext
        let result = self.verify_ciphertext()?;
        if !result {
            return Ok(false);
        }
        Ok(true)
    }
}

// verify partial http response
fn partial_verification(verifying_key: &str, verifying_data: &VerifyingDataOpt) {
    verifying_data.verify(verifying_key).unwrap();
}

// load verifying data
fn get_verifying_data(json_content: String) -> VerifyingDataOpt {
    let verifying_data: VerifyingDataOpt = serde_json::from_str(&json_content).unwrap();
    verifying_data
}

pub fn main() {
    #[cfg(feature = "sp1")]
    let verifying_key: String = sp1_zkvm::io::read();
    #[cfg(feature = "sp1")]
    let verifying_raw_data: String = sp1_zkvm::io::read();

    let verifying_data = get_verifying_data(verifying_raw_data);

    partial_verification(&verifying_key, &verifying_data);
}