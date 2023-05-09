/*
    Copyright © 2023, ParallelChain Lab 
    Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
*/

//! block defines block-related protocol types

use crate::{crypto, PublicAddress, Transaction, Receipt, Serializable, Deserializable};

/// A data structure that describes and authorizes the execution of a batch of transactions (state transitions) on the blockchain.
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize, Clone)]
pub struct Block {
    /// Block header
    pub header : BlockHeader,
    /// A dynamically sized list of Transactions
    pub transactions : Vec<Transaction>,
    /// A dynamically sized list of Receipts. If a Block contains a Transaction,
    /// it must also contain its Receipt. Receipts appear in the order of their Transactions.
    pub receipts : Vec<Receipt>,
}

/// Block header defines meta information of a block, including evidence for verifying validity of the block.
#[derive(Clone, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct BlockHeader {
    /// Block hash of this block
    pub hash: crypto::Sha256Hash,
    /// The number of Justify-links between this Block and the Genesis Block. 0 for the Genesis Block
    pub height: u64, 
    /// A QuorumCertificate that points to the Block’s parent
    pub justify: hotstuff_rs::types::QuorumCertificate,
    /// The SHA256 Hash over content inside the block header
    pub data_hash: hotstuff_rs::types::CryptoHash,
    /// A number unique to a particular ParallelChain Mainnet-based blockchain. This
    /// prevents, for example, Blocks from one chain from being published in another chain as evidence
    /// of malfeasance.
    pub chain_id: hotstuff_rs::types::ChainID,
    /// The Public Address of the Validator that is the Leader of the View this Block was proposed in
    pub proposer: PublicAddress,
    /// A Unix timestamp
    pub timestamp: u32,
    /// The (inclusive) minimum number of Grays that a Transaction included in this Block must pay for every Gas used.
    pub base_fee: u64,
    /// The total gas used for producing the block.
    pub gas_used: u64,
    /// Transactions Hash, the Binary Merkle Tree root hash over the Block’s Transactions
    pub txs_hash: crypto::Sha256Hash,
    /// Receipts Hash, the Binary Merkle Tree root hash over the Block’s Receipts
    pub receipts_hash: crypto::Sha256Hash,
    /// State Hash, the SHA256 root hash of the blockchain’s World State Merkle Patricia 
    /// Trie (MPT) after executing all of this Block’s Transactions
    pub state_hash: crypto::Sha256Hash,
    /// Log Bloom, the 256-byte Block-level Bloom Filter union of all the Bloom Filters of each Log topic from the Block’s Receipts
    pub log_bloom: crypto::BloomFilter,
}

impl Serializable for Block {}
impl Deserializable for Block {}
impl Serializable for BlockHeader {}
impl Deserializable for BlockHeader {}