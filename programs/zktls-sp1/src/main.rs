#![no_main]

use verification_data::{VerifyingData, VerifyingDataOpt};

#[cfg(feature = "sp1")]
sp1_zkvm::entrypoint!(main);


pub fn main() {
    #[cfg(feature = "sp1")]
    let verifying_key: String = sp1_zkvm::io::read();
    #[cfg(feature = "sp1")]
    let verifying_data: VerifyingDataOpt = sp1_zkvm::io::read();

    verifying_data.verify(&verifying_key).is_ok();

    #[cfg(feature = "sp1")]
    sp1_zkvm::io::commit(&verifying_key);
}