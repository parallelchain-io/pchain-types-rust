/*
    Copyright © 2023, ParallelChain Lab 
    Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
*/

//! The data structures that are used for verifying a Merkle tree.

use crate::{crypto, Serializable, Deserializable, PublicAddress};

/// MerkleProof defines fields required in proving leaves hashes given a root hash and other related information
/// The fields are compatible to function `verify` used in [rs_merkle].
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct MerkleProof {
    /// Merkle root hash required in the proof
    pub root_hash: crypto::Sha256Hash,
    /// Number of Leaves in the Merkle Tree
    pub total_leaves_count: u64,
    /// Vector of u32 integers. Integer li\[i\] represents the i-th leave to prove in the Trie
    pub leaf_indices: Vec<u32>,
    /// Vector of sha256 hashes
    pub leaf_hashes: Vec<crypto::Sha256Hash>,
    /// Bytes used for verification
    pub proof: Vec<u8>,
}

/// StorageHash is the root hash of account's Storage Trie. 
pub type StorageHash = crypto::Sha256Hash;
/// StateProofItem contains ItemType-value pair to verify with StateProof.
pub type StateProofItem = (StateProofItemType, Vec<u8>);
/// Type of account state item that can request the StateProof
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub enum StateProofItemType {
    Nonce,
    Balance,
    Code,
    CbiVersion,
    Storage(StorageHash, Vec<u8>),
}

/// StateProofs is compatible to functions in crate [trie-db](https://docs.rs/trie-db/latest/trie_db/).
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct StateProof {
    /// Merkle root hash required in the proof
    pub root_hash: crypto::Sha256Hash,
    /// Account address that the items belong to.
    pub address: PublicAddress,
    /// Items are key-value pairs to verify with root hash and proof. 
    pub item: StateProofItem,
    /// Proof is sequence of some nodes in trie traversed in pre-order traversal order.
    pub proof: Vec<Vec<u8>>
}

impl Serializable for MerkleProof {}
impl Deserializable for MerkleProof {}
impl Serializable for StateProof {}
impl Deserializable for StateProof {}
