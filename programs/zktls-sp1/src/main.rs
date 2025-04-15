#![no_main]

use zktls_att_verification::verification_data::VerifyingDataOpt;

#[cfg(feature = "sp1")]
sp1_zkvm::entrypoint!(main);

// load verifying data
fn get_verifying_data(json_content: String) -> VerifyingDataOpt {
    let verifying_data: VerifyingDataOpt = serde_json::from_str(&json_content).unwrap();
    verifying_data
}

pub fn main() {
    let verifying_key: String = sp1_zkvm::io::read();
    let verifying_raw_data: String = sp1_zkvm::io::read();
    let verifying_data = get_verifying_data(verifying_raw_data);

    let _ = verifying_data.verify(&verifying_key).is_ok();

    //sp1_zkvm::io::commit(&verifying_key);
    //sp1_zkvm::io::commit(&verifying_data.get_records());
}