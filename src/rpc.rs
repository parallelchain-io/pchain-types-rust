/*
    Copyright © 2023, ParallelChain Lab 
    Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
*/

//! RPC requests and responses, and the additional types included in them.

use std::collections::{HashSet, HashMap};
use borsh::{BorshSerialize, BorshDeserialize};
use hotstuff_rs::types::{CryptoHash, BlockHeight};
use crate::serialization::{Serializable, Deserializable};
use crate::cryptography::PublicAddress;
use crate::blockchain::{Block, BlockHeader, Transaction, Receipt, CommandReceipt};

/* Transaction RPCs */

/// Submit a transaction to the mempool.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct SubmitTransactionRequest {
    pub transaction: Transaction
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct SubmitTransactionResponse {
    pub error: Option<SubmitTransactionError>,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub enum SubmitTransactionError {
    UnacceptableNonce,
    MempoolFull,
    Other,
}

/// Get a transaction and optionally its receipt.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct TransactionRequest {    
    pub transaction_hash: CryptoHash,
    pub include_receipt: bool,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct TransactionResponse {
    pub transaction: Option<Transaction>,
    pub receipt: Option<Receipt>,
    pub block_hash: Option<CryptoHash>,
    pub position: Option<u32>,
}

/// Find out where a transaction is in the blockchain.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct TransactionPositionRequest {
    pub transaction_hash: CryptoHash,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct TransactionPositionResponse {
    pub transaction_hash: Option<CryptoHash>,
    pub block_hash: Option<CryptoHash>,
    pub position: Option<u32>,
}

/// Get a transaction's receipt.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct ReceiptRequest {    
    pub transaction_hash: CryptoHash,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct ReceiptResponse {
    pub transaction_hash: CryptoHash,
    pub receipt: Option<Receipt>,
    pub block_hash: Option<CryptoHash>,
    pub position: Option<u32>,
}

/* Block RPCs */

/// Get a block by its block hash.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct BlockRequest {
    pub block_hash: CryptoHash
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct BlockResponse {
    pub block: Option<Block>,
}

/// Get a block header by its block hash.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct BlockHeaderRequest {
    pub block_hash: CryptoHash
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct BlockHeaderResponse {
    pub block_header: Option<BlockHeader>,
}

/// Get the height of the block with a given block hash.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct BlockHeightByHashRequest {
    pub block_hash: CryptoHash,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct BlockHeightByHashResponse {
    pub block_hash: CryptoHash,
    pub block_height: Option<BlockHeight>,
}

/// Get the hash of a block at a given height.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct BlockHashByHeightRequest {
    pub block_height: BlockHeight,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct BlockHashByHeightResponse {
    pub block_height: BlockHeight,
    pub block_hash: Option<CryptoHash>,
}

/// Return the hash of the highest committed block.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct HighestCommittedBlockResponse {
    pub block_hash: Option<CryptoHash>
}

/* State RPCs */

/// Get the state of a set of accounts (optionally including their contract code), and/or a set of storage tuples.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct StateRequest {
    pub accounts: HashSet<PublicAddress>,
    pub include_contract: bool,
    pub storage_keys: HashMap<PublicAddress, HashSet<Vec<u8>>>,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct StateResponse {
    pub accounts: HashMap<PublicAddress, Account>,
    pub storage_tuples: HashMap<PublicAddress, HashMap<Vec<u8>, Vec<u8>>>,
    pub block_hash: CryptoHash,
}

/// Get the previous, current, and next validator sets, optionally including the stakes delegated to them.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct ValidatorSetsRequest {
    pub include_prev: bool,
    pub include_prev_delegators: bool,
    pub include_curr: bool,
    pub include_curr_delegators: bool,
    pub include_next: bool,
    pub include_next_delegators: bool,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct ValidatorSetsResponse {
    // The inner Option is None if we are at Epoch 0.
    pub previous_validator_set: Option<Option<ValidatorSet>>,
    pub current_validator_set: Option<ValidatorSet>,
    pub next_validator_set: Option<ValidatorSet>,
    pub block_hash: CryptoHash,
}

/// Get a set of pools.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct PoolsRequest {
    pub operators: HashSet<Operator>,
    pub include_stakes: bool,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct PoolsResponse {
    pub pools: HashMap<Operator, Option<Pool>>,
    pub block_hash: CryptoHash,
}

/// Get a set of stakes.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct StakesRequest {
    pub stakes: HashSet<(Operator, Owner)>,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct StakesResponse {
    pub stakes: HashMap<(Operator, Owner), Option<Stake>>,
    pub block_hash: CryptoHash,
}

/// Get a set of deposits.

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct DepositsRequest {
    pub stakes: HashSet<(Operator, Owner)>,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct DepositsResponse {
    pub deposits: HashMap<(Operator, Owner), Option<Deposit>>,
    pub block_hash: CryptoHash,
}

/// Call a method in a contract in a read-only way.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct ViewRequest {
    pub target: PublicAddress,
    pub method: Vec<u8>,
    pub arguments: Option<Vec<Vec<u8>>>
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct ViewResponse {
    pub receipt: CommandReceipt
}

/* Account-related types */

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub enum Account {
    WithContract(AccountWithContract),
    WithoutContract(AccountWithoutContract)
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct AccountWithContract {
    pub nonce: u64,
    pub balance: u64,
    pub contract: Option<Vec<u8>>,
    pub cbi_version: Option<u32>,
    pub storage_hash: Option<CryptoHash>,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct AccountWithoutContract {
    pub nonce: u64,
    pub balance: u64,
    pub cbi_version: Option<u32>,
    pub storage_hash: Option<CryptoHash>,
}

/* DPoS-related types */

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub enum ValidatorSet {
    WithDelegators(Vec<PoolWithDelegators>),
    WithoutDelegators(Vec<PoolWithoutDelegators>),
}

pub type Operator = PublicAddress;
pub type Owner = PublicAddress;

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]

pub struct PoolWithDelegators {
    pub operator: PublicAddress,
    pub power: u64,
    pub commission_rate: u8, 
    pub operator_stake: Option<Stake>,
    pub delegated_stakes: Vec<Stake>,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct PoolWithoutDelegators {
    pub operator: PublicAddress,
    pub power: u64,
    pub commission_rate: u8, 
    pub operator_stake: Option<Stake>,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct Deposit {
    pub owner: PublicAddress,
    pub balance: u64,
    pub auto_stake_rewards: bool,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct Stake {
    pub owner: PublicAddress,
    pub power: u64, 
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub enum Pool {
    WithStakes(PoolWithDelegators),
    WithoutStakes(PoolWithoutDelegators),
}

macro_rules! define_serde {
    ($($t:ty),*) => {
        $(
            impl Serializable for $t {}
            impl Deserializable for $t {}
        )*
    }
}

define_serde!(
    SubmitTransactionRequest, SubmitTransactionResponse,
    TransactionRequest, TransactionResponse,
    TransactionPositionRequest, TransactionPositionResponse,
    ReceiptRequest, ReceiptResponse,
    BlockRequest, BlockResponse,
    BlockHeaderRequest, BlockHeaderResponse,
    BlockHeightByHashRequest, BlockHeightByHashResponse,
    BlockHashByHeightRequest, BlockHashByHeightResponse,
    HighestCommittedBlockResponse,
    StateRequest, StateResponse,
    ValidatorSetsRequest, ValidatorSetsResponse,
    PoolsRequest, PoolsResponse,
    StakesRequest, StakesResponse,
    DepositsRequest, DepositsResponse,
    ViewRequest, ViewResponse
);
