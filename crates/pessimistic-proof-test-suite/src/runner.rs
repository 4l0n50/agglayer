pub use pessimistic_proof::PessimisticProofOutput;
use pessimistic_proof::{
    keccak::{Hasher, Keccak256Hasher},
    NetworkState,
};
pub use sp1_sdk::{ExecutionReport, SP1Proof};
use sp1_sdk::{SP1ProofWithPublicValues, SP1PublicValues, SP1Stdin, SP1VerifyingKey};

use crate::PESSIMISTIC_PROOF_ELF;

pub type KeccakHasher = Keccak256Hasher;
pub type Digest = <KeccakHasher as Hasher>::Digest;
pub type MultiBatchHeader = pessimistic_proof::multi_batch_header::MultiBatchHeader<KeccakHasher>;

pub struct ProofOutput {}

/// A convenient interface to run the pessimistic proof ELF bytecode.
pub struct Runner {
    client: sp1_sdk::EnvProver,
}

impl Default for Runner {
    fn default() -> Self {
        Self::new()
    }
}

impl Runner {
    /// Create a new pessimistic proof client.
    pub fn new() -> Self {
        Self::from_client(sp1_sdk::ProverClient::from_env())
    }

    /// Create a new pessimistic proof client from a custom generic client.
    pub fn from_client(client: sp1_sdk::EnvProver) -> Self {
        Self { client }
    }

    /// Convert inputs to stdin.
    pub fn prepare_stdin(state: &NetworkState, batch_header: &MultiBatchHeader) -> SP1Stdin {
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(
            &rkyv::to_bytes::<rkyv::rancor::Error>(state)
                .expect("Failed to serialize NetworkState"),
        );
        stdin.write_slice(
            &rkyv::to_bytes::<rkyv::rancor::Error>(batch_header)
                .expect("Failed to serialize MultiBatchHeader"),
        );
        stdin
    }

    /// Extract outputs from the committed public values.
    pub fn extract_output(public_vals: SP1PublicValues) -> PessimisticProofOutput {
        PessimisticProofOutput::bincode_codec()
            .deserialize(public_vals.as_slice())
            .expect("deser")
    }

    /// Execute the ELF with given inputs.
    pub fn execute(
        &self,
        state: &NetworkState,
        batch_header: &MultiBatchHeader,
    ) -> anyhow::Result<(PessimisticProofOutput, ExecutionReport)> {
        let stdin = Self::prepare_stdin(state, batch_header);
        let (public_vals, report) = self.client.execute(PESSIMISTIC_PROOF_ELF, &stdin).run()?;

        let output = Self::extract_output(public_vals);

        Ok((output, report))
    }

    pub fn get_vkey(&self) -> SP1VerifyingKey {
        let (_pk, vk) = self.client.setup(PESSIMISTIC_PROOF_ELF);
        vk
    }

    /// Generate one plonk proof.
    pub fn generate_plonk_proof(
        &self,
        state: &NetworkState,
        batch_header: &MultiBatchHeader,
    ) -> anyhow::Result<(
        SP1ProofWithPublicValues,
        SP1VerifyingKey,
        PessimisticProofOutput,
    )> {
        let stdin = Self::prepare_stdin(state, batch_header);
        let (pk, vk) = self.client.setup(PESSIMISTIC_PROOF_ELF);

        let proof = self.client.prove(&pk, &stdin).plonk().run()?;
        let output = Self::extract_output(proof.public_values.clone());

        Ok((proof, vk, output))
    }
}
