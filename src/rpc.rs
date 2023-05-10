/*
    Copyright © 2023, ParallelChain Lab 
    Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
*/

//! The request-response structures for RPC.

use std::collections::{HashSet, HashMap};

use hotstuff_rs::types::{CryptoHash, BlockHeight};
use crate::{Transaction, Serializable, Block, BlockHeader, Receipt, PublicAddress, Stake, Deserializable, CommandReceipt};

/* Transaction RPCs */

/// Submit a transaction to the mempool.
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SubmitTransactionRequest {
    pub transaction: Transaction
}

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize, Debug)]
pub struct SubmitTransactionResponse {
    pub error: Option<SubmitTransactionError>,
}

#[derive(Debug, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub enum SubmitTransactionError {
    UnacceptableNonce,
    MempoolFull,
    Other,
}

/// Get a transaction and optionally its receipt.
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct TransactionRequest {    
    pub transaction_hash: CryptoHash,
    pub include_receipt: bool,
}

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize, Debug)]
pub struct TransactionResponse {
    pub transaction: Option<Transaction>,
    pub receipt: Option<Receipt>,
    pub block_hash: Option<CryptoHash>,
    pub position: Option<u32>,
}

/// Find out where a transaction is in the blockchain.
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct TransactionPositionRequest {
    pub transaction_hash: CryptoHash,
}

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize, Debug)]
pub struct TransactionPositionResponse {
    pub transaction_hash: Option<CryptoHash>,
    pub block_hash: Option<CryptoHash>,
    pub position: Option<u32>,
}

/// Get a transaction's receipt.
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct ReceiptRequest {    
    pub transaction_hash: CryptoHash,
}

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize, Debug)]
pub struct ReceiptResponse {
    pub transaction_hash: CryptoHash,
    pub receipt: Option<Receipt>,
    pub block_hash: Option<CryptoHash>,
    pub position: Option<u32>,
}

/* Block RPCs */

/// Get a block by its block hash.
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct BlockRequest {
    pub block_hash: CryptoHash
}

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct BlockResponse {
    pub block: Option<Block>,
}

/// Get a block header by its block hash.
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct BlockHeaderRequest {
    pub block_hash: CryptoHash
}

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct BlockHeaderResponse {
    pub block_header: Option<BlockHeader>,
}

/// Get the height of the block with a given block hash.
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct BlockHeightByHashRequest {
    pub block_hash: CryptoHash,
}

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize, Debug)]
pub struct BlockHeightByHashResponse {
    pub block_hash: CryptoHash,
    pub block_height: Option<BlockHeight>,
}

/// Get the hash of a block at a given height.
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct BlockHashByHeightRequest {
    pub block_height: BlockHeight,
}

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize, Debug)]
pub struct BlockHashByHeightResponse {
    pub block_height: BlockHeight,
    pub block_hash: Option<CryptoHash>,
}

/// Return the hash of the highest committed block.
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize, Debug)]
pub struct HighestCommittedBlockResponse {
    pub block_hash: Option<CryptoHash>
}

/* State RPCs */

/// Get the state of a set of accounts (optionally including their contract code), and/or a set of storage tuples.
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct StateRequest {
    pub accounts: HashSet<PublicAddress>,
    pub include_contract: bool,
    pub storage_keys: HashMap<PublicAddress, HashSet<Vec<u8>>>,
}

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize, Debug)]
pub struct StateResponse {
    pub accounts: HashMap<PublicAddress, Account>,
    pub storage_tuples: HashMap<PublicAddress, HashMap<Vec<u8>, Vec<u8>>>,
    pub block_hash: CryptoHash,
}

/// Get the previous, current, and next validator sets, optionally including the stakes delegated to them.
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct ValidatorSetsRequest {
    pub include_prev: bool,
    pub include_prev_delegators: bool,
    pub include_curr: bool,
    pub include_curr_delegators: bool,
    pub include_next: bool,
    pub include_next_delegators: bool,
}

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize, Debug)]
pub struct ValidatorSetsResponse {
    // The inner Option is None if we are at Epoch 0.
    pub previous_validator_set: Option<Option<ValidatorSet>>,
    pub current_validator_set: Option<ValidatorSet>,
    pub next_validator_set: Option<ValidatorSet>,
    pub block_hash: CryptoHash,
}

/// Get a set of pools.
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct PoolsRequest {
    pub operators: HashSet<Operator>,
    pub include_stakes: bool,
}

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize, Debug)]
pub struct PoolsResponse {
    pub pools: HashMap<Operator, Option<Pool>>,
    pub block_hash: CryptoHash,
}

/// Get a set of stakes.
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct StakesRequest {
    pub stakes: HashSet<(Operator, Owner)>,
}

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize, Debug)]
pub struct StakesResponse {
    pub stakes: HashMap<(Operator, Owner), Option<Stake>>,
    pub block_hash: CryptoHash,
}

/// Get a set of deposits.
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct DepositsRequest {
    pub stakes: HashSet<(Operator, Owner)>,
}

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize, Debug)]
pub struct DepositsResponse {
    pub deposits: HashMap<(Operator, Owner), Option<Deposit>>,
    pub block_hash: CryptoHash,
}

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize, Debug)]
pub struct Deposit {
    pub owner: PublicAddress,
    pub balance: u64,
    pub auto_stake_rewards: bool,
}

/* Account-related types */

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize, Debug)]
pub enum Account {
    WithContract(AccountWithContract),
    WithoutContract(AccountWithoutContract)
}

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize, Debug)]
pub struct AccountWithContract {
    pub nonce: u64,
    pub balance: u64,
    pub contract: Option<Vec<u8>>,
    pub cbi_version: Option<u32>,
    pub storage_hash: Option<CryptoHash>,
}

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize, Debug)]
pub struct AccountWithoutContract {
    pub nonce: u64,
    pub balance: u64,
    pub cbi_version: Option<u32>,
    pub storage_hash: Option<CryptoHash>,
}

/// Call a method in a contract in a read-only way.
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct ViewRequest {
    pub target: PublicAddress,
    pub method: Vec<u8>,
    pub arguments: Option<Vec<Vec<u8>>>
}

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize, Debug)]
pub struct ViewResponse {
    pub receipt: CommandReceipt
}

/* Staking-related types */

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize, Debug)]
pub enum ValidatorSet {
    WithDelegators(Vec<PoolWithDelegators>),
    WithoutDelegators(Vec<PoolWithoutDelegators>),
}

pub type Operator = PublicAddress;
pub type Owner = PublicAddress;

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize, Debug)]
pub struct PoolWithDelegators {
    pub operator: PublicAddress,
    pub power: u64,
    pub commission_rate: u8, 
    pub operator_stake: Option<Stake>,
    pub delegated_stakes: Vec<Stake>,
}

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize, Debug)]
pub struct PoolWithoutDelegators {
    pub operator: PublicAddress,
    pub power: u64,
    pub commission_rate: u8, 
    pub operator_stake: Option<Stake>,
}

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize, Debug)]
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

/// Stake represents the voting power of an account. It could be a delegated stakes or operation's own state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct Stake {
    /// Address of the owner of the stake
    pub owner: PublicAddress,
    /// Power of the stake
    pub power: u64
}

impl Serializable for Stake {}
impl Deserializable for Stake {}

/// Deposit is the locked balance of an account for a particular pool. 
/// It determines the limit of voting power (see [Stake]) that the owner can delegate. 
#[derive(Debug, Clone, Copy, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct Deposit {
    /// Balance of this deposit
    pub balance: u64,
    /// Flag to indicate whether the received reward in epoch transaction should be automatically
    /// staked to the pool
    pub auto_stake_rewards: bool,
}

impl Serializable for Deposit {}
impl Deserializable for Deposit {}

/// Pool is the place that stake owners can stake to.
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct Pool {
    /// Address of the pool's operator
    pub operator: PublicAddress,
    /// Commission rate (in unit of percentage) is the portion that 
    /// the owners of its delegated stakes should pay from the reward in an epoch transaction.
    pub commission_rate: u8,
    /// Pool's power that determines the eligibility to be one of the validator
    pub power: u64,
    /// Operator's own stake
    pub operator_stake: Option<Stake>
}

impl Serializable for Pool {}
impl Deserializable for Pool {}
