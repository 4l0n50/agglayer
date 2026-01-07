#![allow(clippy::too_many_arguments)]
use std::collections::BTreeMap;

use agglayer_primitives::{Digest, U256};
use serde::{Deserialize, Serialize};
use unified_bridge::{
    BridgeExit, ImportedBridgeExit, ImportedBridgeExitCommitmentValues, NetworkId, TokenInfo,
};

use crate::{
    adapters::{
        BalanceProofValueAdapter, BridgeExitAdapter, DigestAdapter,
        ImportedBridgeExitWithNullifierPathAdapter, NetworkIdAdapter, TokenInfoAdapter,
    },
    aggchain_data::AggchainData,
    local_balance_tree::LocalBalancePath,
    nullifier_tree::NullifierPath,
};

/// Represents the chain state transition for the pessimistic proof.
#[derive(
    Clone, Debug, Serialize, Deserialize, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub struct MultiBatchHeader {
    /// Network that emitted this [`MultiBatchHeader`].
    #[rkyv(with = NetworkIdAdapter)]
    pub origin_network: NetworkId,
    /// Current certificate height of the L2 chain.
    pub height: u64,
    /// Previous pessimistic root.
    #[rkyv(with = DigestAdapter)]
    pub prev_pessimistic_root: Digest,
    /// List of bridge exits created in this batch.
    #[rkyv(with = rkyv::with::Map<BridgeExitAdapter>)]
    pub bridge_exits: Vec<BridgeExit>,
    /// List of imported bridge exits claimed in this batch.
    #[rkyv(with = rkyv::with::Map<ImportedBridgeExitWithNullifierPathAdapter>)]
    pub imported_bridge_exits: Vec<(ImportedBridgeExit, NullifierPath)>,
    /// L1 info root used to import bridge exits.
    #[rkyv(with = DigestAdapter)]
    pub l1_info_root: Digest,
    /// Token balances of the origin network before processing bridge events,
    /// with Merkle proofs of these balances in the local balance tree.
    #[rkyv(with = rkyv::with::MapKV<TokenInfoAdapter, BalanceProofValueAdapter>)]
    pub balances_proofs: BTreeMap<TokenInfo, (U256, LocalBalancePath)>,
    /// Aggchain data which include either multisig, aggchain proof, or both.
    pub aggchain_data: AggchainData,
    /// Certificate id used as nonce to compute the commitment.
    #[rkyv(with = DigestAdapter)]
    pub certificate_id: Digest,
}

impl MultiBatchHeader {
    /// Returns the commitment on the imported bridge exits.
    pub fn commit_imported_bridge_exits(&self) -> ImportedBridgeExitCommitmentValues {
        ImportedBridgeExitCommitmentValues {
            claims: self
                .imported_bridge_exits
                .iter()
                .map(|(exit, _)| exit.to_indexed_exit_hash())
                .collect(),
        }
    }
}
