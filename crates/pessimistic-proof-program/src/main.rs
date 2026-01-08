#![no_main]

use pessimistic_proof_core::{
    generate_pessimistic_proof, multi_batch_header::MultiBatchHeader, NetworkState,
    PessimisticProofOutput,
};
use rkyv::{api::low::from_bytes, rancor::Error as RkyvError};

sp1_zkvm::entrypoint!(main);
pub fn main() {
    let initial_state_bytes = sp1_zkvm::io::read_vec();
    let batch_header_bytes = sp1_zkvm::io::read_vec();

    let initial_state =
        from_bytes::<NetworkState, RkyvError>(&initial_state_bytes).expect("state rkyv");
    let batch_header =
        from_bytes::<MultiBatchHeader, RkyvError>(&batch_header_bytes).expect("header rkyv");

    let (outputs, _targets) = generate_pessimistic_proof(initial_state, &batch_header).unwrap();

    let pp_inputs = outputs.rkyv_to_bytes().unwrap();

    sp1_zkvm::io::commit_slice(&pp_inputs);
}
