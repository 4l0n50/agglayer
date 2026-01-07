use agglayer_primitives::{Address, Digest, Signature};
use agglayer_tries::proof::{SmtMerkleProof, SmtNonInclusionProof};
use alloy_primitives::U256;
use rkyv::{
    rancor::Fallible,
    ser::{Allocator, Writer},
    with::{ArchiveWith, DeserializeWith, SerializeWith},
    Archive, Place,
};
use unified_bridge::{
    BridgeExit, Claim, ClaimFromMainnet, ClaimFromRollup, GlobalIndex, ImportedBridgeExit,
    L1InfoTreeLeaf, L1InfoTreeLeafInner, LETMerkleProof, LeafType, LocalExitTree, MerkleProof,
    NetworkId, TokenInfo,
};

use crate::{
    local_balance_tree::{LocalBalancePath, LOCAL_BALANCE_TREE_DEPTH},
    nullifier_tree::NullifierPath,
};

/// rkyv adapter that archives `Digest` as bytes.
pub struct DigestAdapter;

impl ArchiveWith<Digest> for DigestAdapter {
    type Archived = <[u8; 32] as Archive>::Archived;
    type Resolver = <[u8; 32] as Archive>::Resolver;

    fn resolve_with(field: &Digest, resolver: Self::Resolver, out: Place<Self::Archived>) {
        let bytes: [u8; 32] = field.0;
        bytes.resolve(resolver, out);
    }
}

impl<S: Fallible> SerializeWith<Digest, S> for DigestAdapter {
    fn serialize_with(field: &Digest, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        let bytes: [u8; 32] = field.0;
        <[u8; 32] as rkyv::Serialize<S>>::serialize(&bytes, serializer)
    }
}

impl<D: Fallible> DeserializeWith<<[u8; 32] as Archive>::Archived, Digest, D> for DigestAdapter {
    fn deserialize_with(
        archived: &<[u8; 32] as Archive>::Archived,
        deserializer: &mut D,
    ) -> Result<Digest, D::Error> {
        // rkyv-style: deserialize from the archived bytes
        let bytes: [u8; 32] =
            <[u8; 32] as rkyv::Deserialize<[u8; 32], D>>::deserialize(archived, deserializer)?;
        Ok(Digest(bytes))
    }
}

/// rkyv adapter that archives `LocalExitTree<N>` as `(u32, [[u8; 32]; N])`.
pub struct LocalExitTreeAdapter<const N: usize>;

impl<const N: usize> ArchiveWith<LocalExitTree<N>> for LocalExitTreeAdapter<N> {
    type Archived = <(u32, [[u8; 32]; N]) as Archive>::Archived;
    type Resolver = <(u32, [[u8; 32]; N]) as Archive>::Resolver;

    fn resolve_with(
        field: &LocalExitTree<N>,
        resolver: Self::Resolver,
        out: Place<Self::Archived>,
    ) {
        let frontier_bytes: [[u8; 32]; N] = core::array::from_fn(|i| field.frontier[i].0);
        let repr: (u32, [[u8; 32]; N]) = (field.leaf_count, frontier_bytes);
        repr.resolve(resolver, out);
    }
}

impl<const N: usize, S> SerializeWith<LocalExitTree<N>, S> for LocalExitTreeAdapter<N>
where
    S: Fallible + Writer + ?Sized,
{
    fn serialize_with(
        field: &LocalExitTree<N>,
        serializer: &mut S,
    ) -> Result<Self::Resolver, S::Error> {
        let frontier_bytes: [[u8; 32]; N] = core::array::from_fn(|i| field.frontier[i].0);
        let repr: (u32, [[u8; 32]; N]) = (field.leaf_count, frontier_bytes);

        <(u32, [[u8; 32]; N]) as rkyv::Serialize<S>>::serialize(&repr, serializer)
    }
}

type ExitRepr<const N: usize> = (u32, [[u8; 32]; N]);
type ArchivedExitRepr<const N: usize> = <ExitRepr<N> as Archive>::Archived;

impl<const N: usize, D> rkyv::with::DeserializeWith<ArchivedExitRepr<N>, LocalExitTree<N>, D>
    for LocalExitTreeAdapter<N>
where
    D: Fallible + ?Sized,
{
    fn deserialize_with(
        archived: &ArchivedExitRepr<N>,
        deserializer: &mut D,
    ) -> Result<LocalExitTree<N>, D::Error> {
        let (leaf_count, frontier_bytes): ExitRepr<N> =
            <ArchivedExitRepr<N> as rkyv::Deserialize<ExitRepr<N>, D>>::deserialize(
                archived,
                deserializer,
            )?;

        let frontier: [Digest; N] = core::array::from_fn(|i| Digest(frontier_bytes[i]));

        Ok(LocalExitTree {
            leaf_count,
            frontier,
        })
    }
}

/// rkyv adapter that archives `Address` as `[u8; 20]`.
pub struct AddressAdapter;

impl ArchiveWith<Address> for AddressAdapter {
    type Archived = <[u8; 20] as Archive>::Archived;
    type Resolver = <[u8; 20] as Archive>::Resolver;

    fn resolve_with(field: &Address, resolver: Self::Resolver, out: Place<Self::Archived>) {
        // because you already have `Into<[u8; 20]>` via derive_more
        let bytes: [u8; 20] = (*field).into();
        bytes.resolve(resolver, out);
    }
}

impl<S> SerializeWith<Address, S> for AddressAdapter
where
    S: Fallible + Writer + ?Sized,
{
    fn serialize_with(field: &Address, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        let bytes: [u8; 20] = (*field).into();
        <[u8; 20] as rkyv::Serialize<S>>::serialize(&bytes, serializer)
    }
}

impl<D> DeserializeWith<<[u8; 20] as Archive>::Archived, Address, D> for AddressAdapter
where
    D: Fallible + ?Sized,
{
    fn deserialize_with(
        archived: &<[u8; 20] as Archive>::Archived,
        deserializer: &mut D,
    ) -> Result<Address, D::Error> {
        let bytes: [u8; 20] = <<[u8; 20] as Archive>::Archived as rkyv::Deserialize<
            [u8; 20],
            D,
        >>::deserialize(archived, deserializer)?;
        Ok(Address::from(bytes)) // you already derived From<[u8; 20]>
    }
}

/// rkyv adapter that archives `Signature` as `[parity (1) | r (32) | s (32)]`.
pub struct SignatureAdapter;

impl ArchiveWith<Signature> for SignatureAdapter {
    type Archived = <[u8; 65] as Archive>::Archived;
    type Resolver = <[u8; 65] as Archive>::Resolver;

    fn resolve_with(field: &Signature, resolver: Self::Resolver, out: Place<Self::Archived>) {
        let bytes: [u8; 65] = signature_to_bytes(*field);
        bytes.resolve(resolver, out);
    }
}

impl<S: Fallible> SerializeWith<Signature, S> for SignatureAdapter {
    fn serialize_with(field: &Signature, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        let bytes: [u8; 65] = signature_to_bytes(*field);
        <[u8; 65] as rkyv::Serialize<S>>::serialize(&bytes, serializer)
    }
}

impl<D: Fallible> DeserializeWith<<[u8; 65] as Archive>::Archived, Signature, D>
    for SignatureAdapter
{
    fn deserialize_with(
        archived: &<[u8; 65] as Archive>::Archived,
        deserializer: &mut D,
    ) -> Result<Signature, D::Error> {
        let bytes: [u8; 65] =
            <[u8; 65] as rkyv::Deserialize<[u8; 65], D>>::deserialize(archived, deserializer)?;
        Ok(signature_from_bytes(bytes))
    }
}

/// Encode as `[parity (1) | r (32) | s (32)]`.
#[inline]
fn signature_to_bytes(sig: Signature) -> [u8; 65] {
    // These are the only two lines you must adapt to your alloy API:
    let parity: u8 = if sig.v() { 1 } else { 0 };
    let r_bytes: [u8; 32] = sig.r().to_be_bytes(); // or to_be_bytes::<32>(), etc.
    let s_bytes: [u8; 32] = sig.s().to_be_bytes();

    let mut out = [0u8; 65];
    out[0] = parity;
    out[1..33].copy_from_slice(&r_bytes);
    out[33..65].copy_from_slice(&s_bytes);
    out
}

/// Decode from `[parity (1) | r (32) | s (32)]`.
#[inline]
fn signature_from_bytes(bytes: [u8; 65]) -> Signature {
    let parity = bytes[0] != 0;

    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&bytes[1..33]);

    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&bytes[33..65]);

    // These constructors depend on your alloy types:
    let r = U256::from_be_bytes(r_bytes);
    let s = U256::from_be_bytes(s_bytes);

    Signature::new(r, s, parity)
}

/// rkyv adapter that archives `Option<Signature>` as `Option<[u8; 65]>`.
pub struct OptionSignatureAdapter;

impl ArchiveWith<Option<Signature>> for OptionSignatureAdapter {
    type Archived = <Option<[u8; 65]> as Archive>::Archived;
    type Resolver = <Option<[u8; 65]> as Archive>::Resolver;

    fn resolve_with(
        field: &Option<Signature>,
        resolver: Self::Resolver,
        out: Place<Self::Archived>,
    ) {
        let repr: Option<[u8; 65]> = field.map(signature_to_bytes);
        repr.resolve(resolver, out);
    }
}

impl<S: Fallible> SerializeWith<Option<Signature>, S> for OptionSignatureAdapter {
    fn serialize_with(
        field: &Option<Signature>,
        serializer: &mut S,
    ) -> Result<Self::Resolver, S::Error> {
        let repr: Option<[u8; 65]> = field.map(signature_to_bytes);
        <Option<[u8; 65]> as rkyv::Serialize<S>>::serialize(&repr, serializer)
    }
}

impl<D: Fallible> DeserializeWith<<Option<[u8; 65]> as Archive>::Archived, Option<Signature>, D>
    for OptionSignatureAdapter
{
    fn deserialize_with(
        archived: &<Option<[u8; 65]> as Archive>::Archived,
        deserializer: &mut D,
    ) -> Result<Option<Signature>, D::Error> {
        type Repr = Option<[u8; 65]>;
        type ArchivedRepr = <Repr as Archive>::Archived;

        let repr: Repr =
            <ArchivedRepr as rkyv::Deserialize<Repr, D>>::deserialize(archived, deserializer)?;

        Ok(repr.map(signature_from_bytes))
    }
}

/// rkyv adapter that archives `NetworkId` as `u32`.
pub struct NetworkIdAdapter;

impl ArchiveWith<NetworkId> for NetworkIdAdapter {
    type Archived = <u32 as Archive>::Archived;
    type Resolver = <u32 as Archive>::Resolver;

    fn resolve_with(field: &NetworkId, resolver: Self::Resolver, out: Place<Self::Archived>) {
        let v: u32 = field.to_u32();
        v.resolve(resolver, out);
    }
}

impl<S: Fallible> SerializeWith<NetworkId, S> for NetworkIdAdapter {
    fn serialize_with(field: &NetworkId, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        let v: u32 = field.to_u32();
        <u32 as rkyv::Serialize<S>>::serialize(&v, serializer)
    }
}

impl<D: Fallible> DeserializeWith<<u32 as Archive>::Archived, NetworkId, D> for NetworkIdAdapter {
    fn deserialize_with(
        archived: &<u32 as Archive>::Archived,
        deserializer: &mut D,
    ) -> Result<NetworkId, D::Error> {
        let v: u32 = <<u32 as Archive>::Archived as rkyv::Deserialize<u32, D>>::deserialize(
            archived,
            deserializer,
        )?;
        Ok(NetworkId::new(v))
    }
}

/// rkyv adapter that archives `TokenInfo` as `(u32, [u8; 20])`.
pub struct TokenInfoAdapter;

impl ArchiveWith<TokenInfo> for TokenInfoAdapter {
    type Archived = <(u32, [u8; 20]) as Archive>::Archived;
    type Resolver = <(u32, [u8; 20]) as Archive>::Resolver;

    fn resolve_with(field: &TokenInfo, resolver: Self::Resolver, out: Place<Self::Archived>) {
        let net: u32 = field.origin_network.to_u32();
        let addr: [u8; 20] = field.origin_token_address.into();
        let repr: (u32, [u8; 20]) = (net, addr);
        repr.resolve(resolver, out);
    }
}

impl<S: Fallible> SerializeWith<TokenInfo, S> for TokenInfoAdapter {
    fn serialize_with(field: &TokenInfo, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        let net: u32 = field.origin_network.to_u32();
        let addr: [u8; 20] = field.origin_token_address.into();
        let repr: (u32, [u8; 20]) = (net, addr);

        <(u32, [u8; 20]) as rkyv::Serialize<S>>::serialize(&repr, serializer)
    }
}

impl<D: Fallible> DeserializeWith<<(u32, [u8; 20]) as Archive>::Archived, TokenInfo, D>
    for TokenInfoAdapter
{
    fn deserialize_with(
        archived: &<(u32, [u8; 20]) as Archive>::Archived,
        deserializer: &mut D,
    ) -> Result<TokenInfo, D::Error> {
        type Repr = (u32, [u8; 20]);
        type ArchivedRepr = <Repr as Archive>::Archived;

        let (net, addr): Repr =
            <ArchivedRepr as rkyv::Deserialize<Repr, D>>::deserialize(archived, deserializer)?;

        Ok(TokenInfo {
            origin_network: NetworkId::new(net),
            origin_token_address: Address::from(addr),
        })
    }
}

/// rkyv adapter that archives `(U256, LocalBalancePath)` as
/// `([u8; 32], [[u8; 32]; LOCAL_BALANCE_TREE_DEPTH])`.
pub struct BalanceProofValueAdapter;

impl ArchiveWith<(U256, LocalBalancePath)> for BalanceProofValueAdapter {
    type Archived = <([u8; 32], [[u8; 32]; LOCAL_BALANCE_TREE_DEPTH]) as Archive>::Archived;
    type Resolver = <([u8; 32], [[u8; 32]; LOCAL_BALANCE_TREE_DEPTH]) as Archive>::Resolver;

    fn resolve_with(
        field: &(U256, LocalBalancePath),
        resolver: Self::Resolver,
        out: Place<Self::Archived>,
    ) {
        let (bal, proof) = field;

        // TODO: replace with your U256 -> [u8; 32] BE conversion
        let bal_bytes: [u8; 32] = bal.to_be_bytes();

        let sibs: [[u8; 32]; LOCAL_BALANCE_TREE_DEPTH] =
            core::array::from_fn(|i| proof.siblings[i].0);

        (bal_bytes, sibs).resolve(resolver, out);
    }
}

impl<S: Fallible> SerializeWith<(U256, LocalBalancePath), S> for BalanceProofValueAdapter {
    fn serialize_with(
        field: &(U256, LocalBalancePath),
        serializer: &mut S,
    ) -> Result<Self::Resolver, S::Error> {
        let (bal, proof) = field;

        // TODO: replace with your U256 -> [u8; 32] BE conversion
        let bal_bytes: [u8; 32] = bal.to_be_bytes();

        let sibs: [[u8; 32]; LOCAL_BALANCE_TREE_DEPTH] =
            core::array::from_fn(|i| proof.siblings[i].0);

        <([u8; 32], [[u8; 32]; LOCAL_BALANCE_TREE_DEPTH]) as rkyv::Serialize<S>>::serialize(
            &(bal_bytes, sibs),
            serializer,
        )
    }
}

impl<D: Fallible>
    DeserializeWith<
        <([u8; 32], [[u8; 32]; LOCAL_BALANCE_TREE_DEPTH]) as Archive>::Archived,
        (U256, LocalBalancePath),
        D,
    > for BalanceProofValueAdapter
{
    fn deserialize_with(
        archived: &<([u8; 32], [[u8; 32]; LOCAL_BALANCE_TREE_DEPTH]) as Archive>::Archived,
        deserializer: &mut D,
    ) -> Result<(U256, LocalBalancePath), D::Error> {
        type Repr = ([u8; 32], [[u8; 32]; LOCAL_BALANCE_TREE_DEPTH]);
        type ArchivedRepr = <Repr as Archive>::Archived;

        let (bal_bytes, sibs): Repr =
            <ArchivedRepr as rkyv::Deserialize<Repr, D>>::deserialize(archived, deserializer)?;

        // TODO: replace with your [u8; 32] BE -> U256 conversion
        let bal: U256 = U256::from_be_bytes(bal_bytes);

        let proof: LocalBalancePath = SmtMerkleProof {
            siblings: core::array::from_fn(|i| Digest(sibs[i])),
        };

        Ok((bal, proof))
    }
}

/// Archived representation of `BridgeExit`.
type BridgeExitRepr = (
    u8,               // leaf_type
    (u32, [u8; 20]),  // TokenInfo
    u32,              // dest_network
    [u8; 20],         // dest_address
    [u8; 32],         // amount
    Option<[u8; 32]>, // metadata
);

#[inline]
fn leaf_type_to_u8(t: LeafType) -> u8 {
    match t {
        LeafType::Transfer => 0,
        LeafType::Message => 1,
    }
}

#[inline]
fn leaf_type_from_u8(v: u8) -> LeafType {
    match v {
        0 => LeafType::Transfer,
        1 => LeafType::Message,
        _ => LeafType::Transfer, // or handle error if you prefer
    }
}

/// rkyv adapter that archives `BridgeExit` via a primitive/byte tuple.
pub struct BridgeExitAdapter;

impl ArchiveWith<BridgeExit> for BridgeExitAdapter {
    type Archived = <BridgeExitRepr as Archive>::Archived;
    type Resolver = <BridgeExitRepr as Archive>::Resolver;

    fn resolve_with(field: &BridgeExit, resolver: Self::Resolver, out: Place<Self::Archived>) {
        let repr: BridgeExitRepr = bridge_exit_to_repr(field);
        repr.resolve(resolver, out);
    }
}

impl<S: Fallible> SerializeWith<BridgeExit, S> for BridgeExitAdapter {
    fn serialize_with(field: &BridgeExit, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        let repr: BridgeExitRepr = bridge_exit_to_repr(field);
        <BridgeExitRepr as rkyv::Serialize<S>>::serialize(&repr, serializer)
    }
}

impl<D: Fallible> DeserializeWith<<BridgeExitRepr as Archive>::Archived, BridgeExit, D>
    for BridgeExitAdapter
{
    fn deserialize_with(
        archived: &<BridgeExitRepr as Archive>::Archived,
        deserializer: &mut D,
    ) -> Result<BridgeExit, D::Error> {
        type ArchivedRepr = <BridgeExitRepr as Archive>::Archived;

        let repr: BridgeExitRepr =
            <ArchivedRepr as rkyv::Deserialize<BridgeExitRepr, D>>::deserialize(
                archived,
                deserializer,
            )?;

        Ok(bridge_exit_from_repr(repr))
    }
}

#[inline]
fn bridge_exit_to_repr(be: &BridgeExit) -> BridgeExitRepr {
    let token_info_repr: (u32, [u8; 20]) = (
        be.token_info.origin_network.to_u32(),
        be.token_info.origin_token_address.into(),
    );

    let dest_network: u32 = be.dest_network.to_u32();
    let dest_address: [u8; 20] = be.dest_address.into();
    let amount: [u8; 32] = be.amount.to_be_bytes();
    let metadata: Option<[u8; 32]> = be.metadata.map(|d| d.0);

    (
        leaf_type_to_u8(be.leaf_type),
        token_info_repr,
        dest_network,
        dest_address,
        amount,
        metadata,
    )
}

#[inline]
fn bridge_exit_from_repr(repr: BridgeExitRepr) -> BridgeExit {
    let (leaf_u8, (origin_net, origin_addr), dest_net, dest_addr, amount_bytes, metadata) = repr;

    let amount: U256 = U256::from_be_bytes(amount_bytes);

    BridgeExit {
        leaf_type: leaf_type_from_u8(leaf_u8),
        token_info: TokenInfo {
            origin_network: NetworkId::new(origin_net),
            origin_token_address: Address::from(origin_addr),
        },
        dest_network: NetworkId::new(dest_net),
        dest_address: Address::from(dest_addr),
        amount,
        metadata: metadata.map(Digest),
    }
}

/// rkyv representation of `MerkleProof` as (siblings, root).
type MerkleProofRepr = ([[u8; 32]; 32], [u8; 32]);

/// rkyv representation of `L1InfoTreeLeaf`.
type L1LeafRepr = (u32, [u8; 32], [u8; 32], ([u8; 32], [u8; 32], u64));

/// rkyv representation of `GlobalIndex` as (network_id_u32, leaf_index).
type GlobalIndexRepr = (u32, u32); // (network_id_u32, leaf_index)

/// rkyv representation of `ClaimFromMainnet`.
type ClaimFromMainnetRepr = (MerkleProofRepr, MerkleProofRepr, L1LeafRepr);

/// rkyv representation of `ClaimFromRollup`.
type ClaimFromRollupRepr = (
    MerkleProofRepr,
    MerkleProofRepr,
    MerkleProofRepr,
    L1LeafRepr,
);

/// rkyv tagged representation of `Claim` (0 = mainnet, 1 = rollup).
type ClaimRepr = (u8, ClaimFromMainnetRepr, ClaimFromRollupRepr);

#[inline]
fn merkle_proof_to_repr(p: &MerkleProof) -> MerkleProofRepr {
    (core::array::from_fn(|i| p.proof.siblings[i].0), p.root.0)
}

#[inline]
fn l1_leaf_to_repr(l: &L1InfoTreeLeaf) -> L1LeafRepr {
    (
        l.l1_info_tree_index,
        l.rer.0,
        l.mer.0,
        (
            l.inner.global_exit_root.0,
            l.inner.block_hash.0,
            l.inner.timestamp,
        ),
    )
}

#[inline]
fn claim_to_repr(c: &Claim) -> ClaimRepr {
    // default fillers (ignored depending on tag)
    let zero_mp: MerkleProofRepr = ([[0u8; 32]; 32], [0u8; 32]);
    let zero_leaf: L1LeafRepr = (0, [0u8; 32], [0u8; 32], ([0u8; 32], [0u8; 32], 0));

    match c {
        Claim::Mainnet(b) => {
            let cm = &**b;
            (
                0,
                (
                    merkle_proof_to_repr(&cm.proof_leaf_mer),
                    merkle_proof_to_repr(&cm.proof_ger_l1root),
                    l1_leaf_to_repr(&cm.l1_leaf),
                ),
                (zero_mp, zero_mp, zero_mp, zero_leaf),
            )
        }
        Claim::Rollup(b) => {
            let cr = &**b;
            (
                1,
                (zero_mp, zero_mp, zero_leaf),
                (
                    merkle_proof_to_repr(&cr.proof_leaf_ler),
                    merkle_proof_to_repr(&cr.proof_ler_rer),
                    merkle_proof_to_repr(&cr.proof_ger_l1root),
                    l1_leaf_to_repr(&cr.l1_leaf),
                ),
            )
        }
    }
}

#[inline]
fn merkle_proof_from_repr((proof, root): MerkleProofRepr) -> MerkleProof {
    MerkleProof {
        proof: LETMerkleProof {
            siblings: core::array::from_fn(|i| Digest(proof[i])),
        },
        root: Digest(root),
    }
}

#[inline]
fn l1_leaf_from_repr((idx, rer, mer, (ger, bh, ts)): L1LeafRepr) -> L1InfoTreeLeaf {
    L1InfoTreeLeaf {
        l1_info_tree_index: idx,
        rer: Digest(rer),
        mer: Digest(mer),
        inner: L1InfoTreeLeafInner {
            global_exit_root: Digest(ger),
            block_hash: Digest(bh),
            timestamp: ts,
        },
    }
}

#[inline]
fn claim_from_repr((tag, mainnet, rollup): ClaimRepr) -> Claim {
    match tag {
        0 => {
            let (p_leaf_mer, p_ger_l1, leaf) = mainnet;
            Claim::Mainnet(Box::new(ClaimFromMainnet {
                proof_leaf_mer: merkle_proof_from_repr(p_leaf_mer),
                proof_ger_l1root: merkle_proof_from_repr(p_ger_l1),
                l1_leaf: l1_leaf_from_repr(leaf),
            }))
        }
        _ => {
            let (p_leaf_ler, p_ler_rer, p_ger_l1, leaf) = rollup;
            Claim::Rollup(Box::new(ClaimFromRollup {
                proof_leaf_ler: merkle_proof_from_repr(p_leaf_ler),
                proof_ler_rer: merkle_proof_from_repr(p_ler_rer),
                proof_ger_l1root: merkle_proof_from_repr(p_ger_l1),
                l1_leaf: l1_leaf_from_repr(leaf),
            }))
        }
    }
}

/// rkyv representation of `ImportedBridgeExit`.
type ImportedBridgeExitRepr = (BridgeExitRepr, ClaimRepr, GlobalIndexRepr);

/// rkyv representation of `(ImportedBridgeExit, NullifierPath)`.
type ImportedElemRepr = (ImportedBridgeExitRepr, Vec<[u8; 32]>);

/// rkyv adapter that archives `(ImportedBridgeExit, NullifierPath)` as bytes.
pub struct ImportedBridgeExitWithNullifierPathAdapter;

impl ArchiveWith<(ImportedBridgeExit, NullifierPath)>
    for ImportedBridgeExitWithNullifierPathAdapter
{
    type Archived = <ImportedElemRepr as Archive>::Archived;
    type Resolver = <ImportedElemRepr as Archive>::Resolver;

    fn resolve_with(
        field: &(ImportedBridgeExit, NullifierPath),
        resolver: Self::Resolver,
        out: Place<Self::Archived>,
    ) {
        let (ibe, path) = field;
        let network_u32: u32 = if ibe.global_index.is_mainnet() {
            NetworkId::ETH_L1.to_u32()
        } else {
            ibe.global_index
                .rollup_index()
                .expect("non-mainnet must have rollup index")
                .to_u32()
        };
        let gi_repr: GlobalIndexRepr = (network_u32, ibe.global_index.leaf_index());
        let ibe_repr = (
            bridge_exit_to_repr(&ibe.bridge_exit),
            claim_to_repr(&ibe.claim_data),
            gi_repr,
        );
        let path_bytes: Vec<[u8; 32]> = path.siblings.iter().map(|d| d.0).collect();

        (ibe_repr, path_bytes).resolve(resolver, out);
    }
}

impl<S: Fallible + Allocator + Writer> SerializeWith<(ImportedBridgeExit, NullifierPath), S>
    for ImportedBridgeExitWithNullifierPathAdapter
{
    fn serialize_with(
        field: &(ImportedBridgeExit, NullifierPath),
        serializer: &mut S,
    ) -> Result<Self::Resolver, S::Error> {
        let (ibe, path) = field;
        let network_u32: u32 = if ibe.global_index.is_mainnet() {
            NetworkId::ETH_L1.to_u32()
        } else {
            ibe.global_index
                .rollup_index()
                .expect("non-mainnet must have rollup index")
                .to_u32()
        };
        let gi_repr: GlobalIndexRepr = (network_u32, ibe.global_index.leaf_index());
        let ibe_repr = (
            bridge_exit_to_repr(&ibe.bridge_exit),
            claim_to_repr(&ibe.claim_data),
            gi_repr,
        );
        let path_bytes: Vec<[u8; 32]> = path.siblings.iter().map(|d| d.0).collect();

        <ImportedElemRepr as rkyv::Serialize<S>>::serialize(&(ibe_repr, path_bytes), serializer)
    }
}

impl<D>
    DeserializeWith<<ImportedElemRepr as Archive>::Archived, (ImportedBridgeExit, NullifierPath), D>
    for ImportedBridgeExitWithNullifierPathAdapter
where
    D: Fallible + ?Sized,
    D::Error: rkyv::rancor::Source,
{
    fn deserialize_with(
        archived: &<ImportedElemRepr as Archive>::Archived,
        deserializer: &mut D,
    ) -> Result<(ImportedBridgeExit, NullifierPath), D::Error> {
        type ArchivedRepr = <ImportedElemRepr as Archive>::Archived;

        let (ibe_repr, path_bytes): ImportedElemRepr =
            <ArchivedRepr as rkyv::Deserialize<ImportedElemRepr, D>>::deserialize(
                archived,
                deserializer,
            )?;

        let ibe = ImportedBridgeExit {
            bridge_exit: bridge_exit_from_repr(ibe_repr.0),
            claim_data: claim_from_repr(ibe_repr.1),
            global_index: GlobalIndex::new(NetworkId::new((ibe_repr.2).0), (ibe_repr.2).1),
        };

        let path = SmtNonInclusionProof {
            siblings: path_bytes.into_iter().map(Digest).collect(),
        };

        Ok((ibe, path))
    }
}

#[cfg(test)]
mod tests {

    use std::collections::BTreeMap;

    use rkyv::{api::low::from_bytes, rancor::Error, to_bytes};

    use super::*;
    use crate::{
        aggchain_data::AggchainData, local_balance_tree::LocalBalanceTree,
        multi_batch_header::MultiBatchHeader, nullifier_tree::NullifierTree, NetworkState,
    };

    #[test]
    fn test_network_state_zero_copy_roundtrip() -> Result<(), Error> {
        let state = NetworkState {
            exit_tree: LocalExitTree::from_parts(42, [[1u8; 32].into(); 32]),
            balance_tree: LocalBalanceTree {
                root: [0xAAu8; 32].into(),
            },
            nullifier_tree: NullifierTree {
                root: [0xBBu8; 32].into(),
            },
        };

        let state_bytes = to_bytes::<Error>(&state)?;
        let deserialized_state = from_bytes::<NetworkState, Error>(&state_bytes)?;

        assert_eq!(state_bytes.len(), std::mem::size_of::<NetworkState>());

        assert_eq!(
            state.exit_tree.leaf_count,
            deserialized_state.exit_tree.leaf_count
        );
        assert_eq!(
            state.balance_tree.root,
            deserialized_state.balance_tree.root
        );
        assert_eq!(
            state.nullifier_tree.root,
            deserialized_state.nullifier_tree.root
        );
        Ok(())
    }

    #[test]
    fn test_network_state_zero_copy_invalid_input() -> Result<(), Error> {
        let state = NetworkState {
            exit_tree: LocalExitTree::new(),
            balance_tree: LocalBalanceTree {
                root: [1u8; 32].into(),
            },
            nullifier_tree: NullifierTree {
                root: [2u8; 32].into(),
            },
        };

        let bytes = to_bytes::<Error>(&state)?;

        // sanity: we expect exactly the archived size
        assert_eq!(bytes.len(), core::mem::size_of::<NetworkState>());

        // Test unaligned data
        let unaligned = &bytes[1..];
        assert!(from_bytes::<NetworkState, Error>(unaligned).is_err());

        // Test wrong size (too small)
        let too_small = &bytes[..bytes.len() - 1];
        assert!(from_bytes::<NetworkState, Error>(too_small).is_err());

        // Test empty data
        assert!(from_bytes::<NetworkState, Error>(&[]).is_err());

        Ok(())
    }

    /// Deep comparison function to check for lossy conversions
    /// This function compares all fields including nested structures
    /// Uses Eq where available, manual comparison where needed
    fn deep_equals(original: &MultiBatchHeader, reconstructed: &MultiBatchHeader) -> bool {
        // Compare basic fields (all have Eq)
        if original.origin_network != reconstructed.origin_network
            || original.height != reconstructed.height
            || original.prev_pessimistic_root != reconstructed.prev_pessimistic_root
            || original.bridge_exits != reconstructed.bridge_exits
            || original.l1_info_root != reconstructed.l1_info_root
            || original.aggchain_data != reconstructed.aggchain_data
            || original.certificate_id != reconstructed.certificate_id
        {
            return false;
        }

        // Compare imported_bridge_exits (most fields have Eq, only nullifier paths need
        // manual comparison)
        if original.imported_bridge_exits.len() != reconstructed.imported_bridge_exits.len() {
            return false;
        }
        for (orig, rec) in original
            .imported_bridge_exits
            .iter()
            .zip(reconstructed.imported_bridge_exits.iter())
        {
            // Compare ImportedBridgeExit (has Eq)
            if orig.0 != rec.0 {
                return false;
            }
            // Compare nullifier paths manually (SmtNonInclusionProof doesn't have Eq)
            if orig.1.siblings != rec.1.siblings {
                return false;
            }
        }

        // Compare balances_proofs (most fields have Eq, only merkle paths need manual
        // comparison)
        if original.balances_proofs.len() != reconstructed.balances_proofs.len() {
            return false;
        }
        for (orig, rec) in original
            .balances_proofs
            .iter()
            .zip(reconstructed.balances_proofs.iter())
        {
            // Compare TokenInfo and U256 (both have Eq)
            if orig.0 != rec.0 || orig.1 .0 != rec.1 .0 {
                return false;
            }
            // Compare merkle paths manually (SmtMerkleProof doesn't have Eq)
            if orig.1 .1.siblings != rec.1 .1.siblings {
                return false;
            }
        }

        true
    }

    /// Test helper to create a sample BridgeExit
    fn create_sample_bridge_exit() -> BridgeExit {
        BridgeExit {
            leaf_type: LeafType::Message,
            token_info: TokenInfo {
                origin_network: NetworkId::new(1),
                origin_token_address: Address::from([1u8; 20]),
            },
            dest_network: NetworkId::new(2),
            dest_address: Address::from([2u8; 20]),
            amount: U256::from(1000u64),
            metadata: Some(Digest([3u8; 32])),
        }
    }

    /// Test helper to create a sample ImportedBridgeExit
    fn create_sample_imported_bridge_exit() -> ImportedBridgeExit {
        ImportedBridgeExit {
            bridge_exit: create_sample_bridge_exit(),
            claim_data: Claim::Mainnet(Box::new(ClaimFromMainnet {
                proof_leaf_mer: MerkleProof {
                    proof: LETMerkleProof {
                        siblings: [Digest([4u8; 32]); 32],
                    },
                    root: Digest([5u8; 32]),
                },
                proof_ger_l1root: MerkleProof {
                    proof: LETMerkleProof {
                        siblings: [Digest([6u8; 32]); 32],
                    },
                    root: Digest([7u8; 32]),
                },
                l1_leaf: L1InfoTreeLeaf {
                    l1_info_tree_index: 42,
                    rer: Digest([8u8; 32]),
                    mer: Digest([9u8; 32]),
                    inner: L1InfoTreeLeafInner {
                        block_hash: Digest([10u8; 32]),
                        timestamp: 1234567890,
                        global_exit_root: Digest([11u8; 32]),
                    },
                },
            })),
            global_index: GlobalIndex::new(NetworkId::new(3), 123),
        }
    }

    /// Test helper to create a sample ImportedBridgeExit with Rollup claim
    fn create_sample_imported_bridge_exit_rollup() -> ImportedBridgeExit {
        ImportedBridgeExit {
            bridge_exit: create_sample_bridge_exit(),
            claim_data: Claim::Rollup(Box::new(ClaimFromRollup {
                proof_leaf_ler: MerkleProof {
                    proof: LETMerkleProof {
                        siblings: [Digest([12u8; 32]); 32],
                    },
                    root: Digest([13u8; 32]),
                },
                proof_ler_rer: MerkleProof {
                    proof: LETMerkleProof {
                        siblings: [Digest([14u8; 32]); 32],
                    },
                    root: Digest([15u8; 32]),
                },
                proof_ger_l1root: MerkleProof {
                    proof: LETMerkleProof {
                        siblings: [Digest([16u8; 32]); 32],
                    },
                    root: Digest([17u8; 32]),
                },
                l1_leaf: L1InfoTreeLeaf {
                    l1_info_tree_index: 43,
                    rer: Digest([18u8; 32]),
                    mer: Digest([19u8; 32]),
                    inner: L1InfoTreeLeafInner {
                        block_hash: Digest([20u8; 32]),
                        timestamp: 1234567891,
                        global_exit_root: Digest([21u8; 32]),
                    },
                },
            })),
            global_index: GlobalIndex::new(NetworkId::new(4), 124),
        }
    }

    /// Test helper to create a sample TokenInfo
    fn create_sample_token_info() -> TokenInfo {
        TokenInfo {
            origin_network: NetworkId::new(4),
            origin_token_address: Address::from([12u8; 20]),
        }
    }

    pub type BalanceMerkleProof = SmtMerkleProof<192>;

    /// Test helper to create a sample BalanceMerkleProof
    fn create_sample_balance_merkle_proof() -> BalanceMerkleProof {
        BalanceMerkleProof {
            siblings: [Digest([13u8; 32]); 192],
        }
    }

    pub type NullifierNonInclusionProof = SmtNonInclusionProof<64>;

    /// Test helper to create a sample NullifierNonInclusionProof
    fn create_sample_nullifier_non_inclusion_proof() -> NullifierNonInclusionProof {
        NullifierNonInclusionProof {
            siblings: vec![Digest([14u8; 32]); 64],
        }
    }

    /// Test helper to create a sample NullifierNonInclusionProof with fewer
    /// siblings
    fn create_sample_nullifier_non_inclusion_proof_partial() -> NullifierNonInclusionProof {
        NullifierNonInclusionProof {
            siblings: vec![Digest([15u8; 32]); 32], // Only 32 siblings instead of 64
        }
    }

    /// Test helper to create a sample MultiBatchHeader
    fn create_sample_multi_batch_header() -> MultiBatchHeader {
        MultiBatchHeader {
            origin_network: NetworkId::new(5),
            height: 1000,
            prev_pessimistic_root: Digest([15u8; 32]),
            bridge_exits: vec![create_sample_bridge_exit()],
            imported_bridge_exits: vec![(
                create_sample_imported_bridge_exit(),
                create_sample_nullifier_non_inclusion_proof(),
            )],
            l1_info_root: Digest([16u8; 32]),
            balances_proofs: vec![(
                create_sample_token_info(),
                (U256::from(5000u64), create_sample_balance_merkle_proof()),
            )],
            aggchain_data: AggchainData::LegacyEcdsa {
                signer: Address::from([17u8; 20]),
                signature: Signature::new(U256::from(18u64), U256::from(19u64), true),
            },
            certificate_id: Digest([20u8; 32]),
        }
    }

    /// Test helper to create a sample MultiBatchHeader with Generic aggchain
    /// proof
    fn create_sample_multi_batch_header_generic() -> MultiBatchHeader {
        MultiBatchHeader {
            origin_network: NetworkId::new(6),
            height: 2000,
            prev_pessimistic_root: Digest([20u8; 32]),
            bridge_exits: vec![create_sample_bridge_exit()],
            imported_bridge_exits: vec![(
                create_sample_imported_bridge_exit(),
                create_sample_nullifier_non_inclusion_proof(),
            )],
            l1_info_root: Digest([21u8; 32]),
            balances_proofs: BTreeMap::from([(
                create_sample_token_info(),
                (U256::from(7000u64), create_sample_balance_merkle_proof()),
            )]),
            aggchain_data: AggchainData::AggchainProofOnly(crate::aggchain_data::AggchainProof {
                aggchain_params: Digest([22u8; 32]),
                aggchain_vkey: [23u32, 24u32, 25u32, 26u32, 27u32, 28u32, 29u32, 30u32],
            }),
            certificate_id: Digest([21u8; 32]),
        }
    }

    /// Test helper to create a sample MultiBatchHeader with Rollup claims
    fn create_sample_multi_batch_header_rollup() -> MultiBatchHeader {
        MultiBatchHeader {
            origin_network: NetworkId::new(7),
            height: 3000,
            prev_pessimistic_root: Digest([30u8; 32]),
            bridge_exits: vec![create_sample_bridge_exit()],
            imported_bridge_exits: vec![(
                create_sample_imported_bridge_exit_rollup(),
                create_sample_nullifier_non_inclusion_proof(),
            )],
            l1_info_root: Digest([31u8; 32]),
            balances_proofs: vec![(
                create_sample_token_info(),
                (U256::from(8000u64), create_sample_balance_merkle_proof()),
            )],
            aggchain_data: AggchainData::LegacyEcdsa {
                signer: Address::from([32u8; 20]),
                signature: Signature::new(U256::from(33u64), U256::from(34u64), false),
            },
            certificate_id: Digest([31u8; 32]),
        }
    }

    /// Test helper to create a sample MultiBatchHeader with mixed claims
    fn create_sample_multi_batch_header_mixed() -> MultiBatchHeader {
        MultiBatchHeader {
            origin_network: NetworkId::new(8),
            height: 4000,
            prev_pessimistic_root: Digest([40u8; 32]),
            bridge_exits: vec![create_sample_bridge_exit()],
            imported_bridge_exits: vec![
                (
                    create_sample_imported_bridge_exit(),
                    create_sample_nullifier_non_inclusion_proof(),
                ),
                (
                    create_sample_imported_bridge_exit_rollup(),
                    create_sample_nullifier_non_inclusion_proof(),
                ),
            ],
            l1_info_root: Digest([41u8; 32]),
            balances_proofs: vec![(
                create_sample_token_info(),
                (U256::from(9000u64), create_sample_balance_merkle_proof()),
            )],
            aggchain_data: AggchainData::AggchainProofOnly(crate::aggchain_data::AggchainProof {
                aggchain_params: Digest([42u8; 32]),
                aggchain_vkey: [43u32, 44u32, 45u32, 46u32, 47u32, 48u32, 49u32, 50u32],
            }),
            certificate_id: Digest([41u8; 32]),
        }
    }
}
