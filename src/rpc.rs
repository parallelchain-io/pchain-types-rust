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
use crate::blockchain::{BlockV1, BlockHeaderV1, CommandReceiptV1, TransactionV2, CommandReceiptV2, BlockV2, ReceiptV2, TransactionV1, ReceiptV1, BlockHeaderV2};

/* Transaction RPCs */

/// Submit a transaction to the mempool.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct SubmitTransactionRequestV1 {
    pub transaction: TransactionV1
}

/// Submit a transaction to the mempool.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct SubmitTransactionRequestV2 {
    pub transaction: TransactionV1OrV2
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct SubmitTransactionResponseV1 {
    pub error: Option<SubmitTransactionErrorV1>,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct SubmitTransactionResponseV2 {
    pub error: Option<SubmitTransactionErrorV2>,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub enum SubmitTransactionErrorV1 {
    UnacceptableNonce,
    MempoolFull,
    Other,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub enum SubmitTransactionErrorV2 {
    NonceLTCommitted,
    BaseFeePerGasTooLow,
    MempoolIsFull,
    Other,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct SubscribeToTransactionEventsRequest {
    pub filter: Option<TransactionEventsFilter>,
}

/// Get a transaction and optionally its receipt.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct TransactionRequest {    
    pub transaction_hash: CryptoHash,
    pub include_receipt: bool,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct TransactionResponseV1 {
    pub transaction: Option<TransactionV1>,
    pub receipt: Option<ReceiptV1>,
    pub block_hash: Option<CryptoHash>,
    pub position: Option<u32>,
}

/// In version 2, the response includes transactions and receipts in different versions, which means it
/// is possible to get the receipts in older version,
/// The pairing of transaction and receipt remains the same - the receipt is in same version with
/// the verion of the corresponding transaction.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct TransactionResponseV2 {
    pub transaction: Option<TransactionV1ToV2>,
    pub receipt: Option<ReceiptV1ToV2>,
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
pub struct ReceiptResponseV1 {
    pub transaction_hash: CryptoHash,
    pub receipt: Option<ReceiptV1>,
    pub block_hash: Option<CryptoHash>,
    pub position: Option<u32>,
}

/// In version 2, the response includes receipts in different versions, which means it
/// is possible to get the receipts in older version.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct ReceiptResponseV2 {
    pub transaction_hash: CryptoHash,
    pub receipt: Option<ReceiptV1ToV2>,
    pub block_hash: Option<CryptoHash>,
    pub position: Option<u32>,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub enum TransactionV1OrV2 {
    V1(TransactionV1),
    V2(TransactionV2)
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub enum TransactionV1ToV2 {
    V1(TransactionV1),
    V2(TransactionV2)
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub enum ReceiptV1ToV2 {
    V1(ReceiptV1),
    V2(ReceiptV2)
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub enum CommandReceiptV1ToV2 {
    V1(CommandReceiptV1),
    V2(CommandReceiptV2)
}

/// A Filter used in the RPC Request [SubscribeToTransactionEventsRequest].
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub enum TransactionEventsFilter {
    ByTransactionHash(HashSet<CryptoHash>),
    BySigner(HashSet<PublicAddress>),
}

/// Enumerates the events which indicate the thing happened to a Transaction.
/// It is part of a RPC response from a Notification WebSocket.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub enum TransactionEvent {
    Received(TransactionV1OrV2),
    InsertedToMempool,
    RejectedFromMempool(RejectedFromMempoolReason),
    RemovedFromMempool(RemovedFromMempoolReason),
    PoppedToExecutor,
    IncludedInBlock,
    RejectedFromBlock(RejectedFromBlockReason),
    BlockPruned,
    BlockCommitted(CryptoHash),
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub enum RejectedFromMempoolReason {
    NonceLTCommitted,
    BaseFeePerGasTooLow,
    MempoolIsFull,
    Other,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub enum RemovedFromMempoolReason {
    NonceLTCommitted,
    BaseFeePerGasTooLow,
    MempoolIsFull,
    DuplicateTransaction,
    Other,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub enum RejectedFromBlockReason {
    NonceLTCommitted,
    NonceNESpeculative,
    BaseFeePerGasTooLow,
    BalanceLTInclusionCost,
    Other,
}

/* Block RPCs */

/// Get a block by its block hash.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct BlockRequest {
    pub block_hash: CryptoHash
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct BlockResponseV1 {
    pub block: Option<BlockV1>,
}

/// In version 2, the block in the response is versioned, which means it is possible
/// to get a block in older version.
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct BlockResponseV2 {
    pub block: Option<BlockV1ToV2>,
}

/// Get a block header by its block hash.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct BlockHeaderRequest {
    pub block_hash: CryptoHash
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct BlockHeaderResponseV1 {
    pub block_header: Option<BlockHeaderV1>,
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct BlockHeaderResponseV2 {
    pub block_header: Option<BlockHeaderV1ToV2>,
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

#[derive(BorshSerialize, BorshDeserialize, Clone)]
pub enum BlockV1ToV2 {
    V1(BlockV1),
    V2(BlockV2)
}

#[derive(BorshSerialize, BorshDeserialize, Clone)]
pub enum BlockHeaderV1ToV2 {
    V1(BlockHeaderV1),
    V2(BlockHeaderV2)
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
pub struct ViewResponseV1 {
    pub receipt: CommandReceiptV1
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct ViewResponseV2 {
    pub receipt: CommandReceiptV1ToV2
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
    SubmitTransactionRequestV1, SubmitTransactionResponseV1,
    SubmitTransactionRequestV2, SubmitTransactionResponseV2,
    SubmitTransactionErrorV1, SubmitTransactionErrorV2,
    TransactionV1OrV2,

    SubscribeToTransactionEventsRequest,
    TransactionEvent,

    TransactionRequest, TransactionResponseV1, TransactionResponseV2,
    TransactionPositionRequest, TransactionPositionResponse, 
    ReceiptRequest, ReceiptResponseV1, ReceiptResponseV2,
    BlockRequest, BlockResponseV1, BlockResponseV2,
    BlockHeaderRequest, BlockHeaderResponseV1, BlockHeaderResponseV2,
    BlockHeightByHashRequest, BlockHeightByHashResponse,
    BlockHashByHeightRequest, BlockHashByHeightResponse,
    HighestCommittedBlockResponse,

    StateRequest, StateResponse,
    ValidatorSetsRequest, ValidatorSetsResponse,
    PoolsRequest, PoolsResponse,
    StakesRequest, StakesResponse,
    DepositsRequest, DepositsResponse,
    ViewRequest, ViewResponseV1, ViewResponseV2
);
