// This code is borrowed from RISC Zero's benchmarks.
//
// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![no_main]

use sha3::{Digest as _, Keccak256};

sp1_zkvm::entrypoint!(main);

fn main() {
    let data: Vec<u8> = sp1_zkvm::io::read();
    let hash = keccak(&data);
    sp1_zkvm::io::commit(&hash)
}

#[inline]
pub fn keccak(data: impl AsRef<[u8]>) -> [u8; 32] {
    Keccak256::digest(data).into()
}