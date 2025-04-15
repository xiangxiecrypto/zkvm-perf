#![no_main]

use zktls_att_verification::verification_data::VerifyingDataOpt;

#[cfg(feature = "sp1")]
sp1_zkvm::entrypoint!(main);


pub fn main() {
    let verifying_key: String = sp1_zkvm::io::read();
    let verifying_data: VerifyingDataOpt = sp1_zkvm::io::read();

    let _ = verifying_data.verify(&verifying_key).is_ok();

    sp1_zkvm::io::commit(&verifying_key);
    sp1_zkvm::io::commit(&verifying_data.get_records());
}