/*
    Copyright © 2023, ParallelChain Lab 
    Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
*/

//! Types which appear in blocks like [transactions](Transaction) and [receipts](Receipt), and also [blocks](Block) themselves.

use borsh::{BorshSerialize, BorshDeserialize};
use crate::serialization::{Serializable, Deserializable};
use crate::cryptography::{Keypair, PublicKey, PublicAddress, SignatureBytes, Signer, Verifier, Sha256Hash, BloomFilter, sha256};
use crate::runtime::*;

/// A data structure that describes and authorizes the execution of a batch of transactions (state transitions) on the blockchain.
#[derive(BorshSerialize, BorshDeserialize, Clone)]
pub struct Block {
    /// Block header
    pub header : BlockHeader,

    /// A dynamically sized list of Transactions
    pub transactions : Vec<Transaction>,

    /// A dynamically sized list of Receipts. If a Block contains a Transaction,
    /// it must also contain its Receipt. Receipts appear in the order of their Transactions.
    pub receipts : Vec<Receipt>,
}

impl Serializable for Block {}
impl Deserializable for Block {}

/// Block header defines meta information of a block, including evidence for verifying validity of the block.
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct BlockHeader {
    /// Block hash of this block
    pub hash: Sha256Hash,

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
    pub txs_hash: Sha256Hash,

    /// Receipts Hash, the Binary Merkle Tree root hash over the Block’s Receipts
    pub receipts_hash: Sha256Hash,

    /// State Hash, the SHA256 root hash of the blockchain’s World State Merkle Patricia 
    /// Trie (MPT) after executing all of this Block’s Transactions
    pub state_hash: Sha256Hash,

    /// Log Bloom, the 256-byte Block-level Bloom Filter union of all the Bloom Filters of each Log topic from the Block’s Receipts
    pub log_bloom: BloomFilter,
}

impl Serializable for BlockHeader {}
impl Deserializable for BlockHeader {}

/// Digitally signed instructions that tell the ParallelChain state machine to execute a sequence of [commands](Command). 
/// 
/// ## Creating a Transaction
/// 
/// There are two ways of creating an instance of transaction:
/// 1. Using the [constructor function](Transaction::new): this takes in the user-provided fields of a transaction and
///    computes its signature and hash automatically.
/// 2. Using a struct expression (i.e., `Transaction { signer: ..., }`): this does not check the signature and hash 
///    fields.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Transaction {
    /// The public address of the external account which signed this transaction
    pub signer: PublicAddress,

    /// The number of transactions signed by the signer that have been included on 
    /// the blockchain before this transaction. This ensures that all of the signer’s transactions are
    /// included in the blockchain in an expected order, and prevents the same transaction from
    /// being included in multiple blocks.
    pub nonce: u64,

    /// A list of execution commands that triggers a sequence of state transitions
    pub commands: Vec<Command>,

    /// The maximum number of gas units (ref.) that should be used in executing this transaction
    pub gas_limit: u64,

    /// The maximum number of grays that the signer is willing to burn for a gas unit used in this transaction
    pub max_base_fee_per_gas: u64,

    /// the number of grays that the signer is willing to pay the block proposer for including this transaction in a block
    pub priority_fee_per_gas: u64,

    /// the signature formed by signing over content of this transaction by using the signer’s private key
    pub signature: SignatureBytes,

    /// The cryptographic hash of signature
    pub hash: Sha256Hash,
}

impl Transaction {
    pub fn new(signer: &Keypair, nonce: u64, commands: Vec<Command>, gas_limit: u64, max_base_fee_per_gas: u64, priority_fee_per_gas: u64) -> Transaction {
        let mut transaction = Transaction {
            signer: signer.public.to_bytes(),
            nonce,
            commands,
            gas_limit,
            max_base_fee_per_gas,
            priority_fee_per_gas,
            signature: [0u8; 64],
            hash: [0u8; 32],
        };

        let signature = signer.sign(&Serializable::serialize(&transaction));
        transaction.signature = signature.into();
        
        let hash = sha256(ed25519_dalek::ed25519::signature::Signature::as_bytes(&signature));
        transaction.hash = hash;

        transaction
    }

    /// Check whether the Transaction's:
    /// 1. Signer is a valid Ed25519 public key.
    /// 2. Signature is a valid Ed25519 signature.
    /// 3. Signature is produced by the signer over the intermediate transaction.
    /// 4. Hash is the SHA256 hash over the signature.
    pub fn is_cryptographically_correct(&self) -> Result<(), CryptographicallyIncorrectTransactionError> { 
        // 1.
        let public_key = PublicKey::from_bytes(&self.signer)
            .map_err(|_| CryptographicallyIncorrectTransactionError::InvalidSigner)?;

        // 2.
        let signature = ed25519_dalek::Signature::from_bytes(&self.signature)
            .map_err(|_| CryptographicallyIncorrectTransactionError::InvalidSignature)?;

        // 3.
        let signed_msg = {
            let intermediate_txn = Transaction {
                signature: [0u8; 64],
                hash: [0u8; 32],
                ..self.to_owned()
            };

            Serializable::serialize(&intermediate_txn)
        };
        public_key.verify(&signed_msg, &signature).map_err(|_| CryptographicallyIncorrectTransactionError::WrongSignature)?;

        // 4.
        if self.hash != sha256(ed25519_dalek::ed25519::signature::Signature::as_bytes(&signature)) {
            return Err(CryptographicallyIncorrectTransactionError::WrongHash)
        }
        
        Ok(())
    }
}

pub enum CryptographicallyIncorrectTransactionError {
    InvalidSigner,
    InvalidSignature,
    WrongSignature,
    WrongHash,
}

impl Serializable for Transaction {}
impl Deserializable for Transaction {}


#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Command {
    Transfer(TransferInput),
    Deploy(DeployInput),
    Call(CallInput),
    CreatePool(CreatePoolInput),
    SetPoolSettings(SetPoolSettingsInput),
    DeletePool,
    CreateDeposit(CreateDepositInput),
    SetDepositSettings(SetDepositSettingsInput),
    TopUpDeposit(TopUpDepositInput),
    WithdrawDeposit(WithdrawDepositInput),
    StakeDeposit(StakeDepositInput),
    UnstakeDeposit(UnstakeDepositInput),
    NextEpoch,
}

impl Serializable for Command {}
impl Deserializable for Command {}

/// Log are messages produced by smart contract executions that are persisted on the blockchain
/// in a cryptographically-provable way. Log produced by transactions that call smart contracts
/// are stored in the `logs` field of a Block in the order in which they are emitted.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Log { 
    /// Key of this event. It is created from contract execution.
    pub topic: Vec<u8>,
    /// Value of this event. It is created from contract execution.
    pub value: Vec<u8>,
}

impl Serializable for Log {}
impl Deserializable for Log {}

/// Receipt defines the result of transaction execution.
pub type Receipt = Vec<CommandReceipt>;

/// A CommandReceipt summarizes the result of execution of a [Command].
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CommandReceipt {
    /// Exit status tells whether the corresponding command in the sequence
    /// succeeded in doing its operation, and, if it failed, whether the 
    /// failure is because of gas exhaustion or some other reason.
    pub exit_status: ExitStatus,
    /// How much gas was used in the execution of the transaction. 
    /// This will at most be the transaction’s gas limit.
    pub gas_used: u64,
    /// The return value of the corresponding command.
    pub return_values: Vec<u8>,
    /// The logs emitted during the corresponding call command.
    pub logs: Vec<Log>,
}

impl Serializable for CommandReceipt {}
impl Deserializable for CommandReceipt {}

/// ExitStatus defines the success and error types of receipt.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ExitStatus {
    /// The Transaction successfully accomplished everything that it could have been expected to do.
    Success,

    /// The Transaction failed to accomplish the primary operation that Transactions of its kinds are expected to accomplish.
    Failed,

    /// The Gas Limit was exceeded by a dynamically costed activity in a dynamic-cost Transaction.
    GasExhausted,
}

impl Serializable for ExitStatus {}
impl Deserializable for ExitStatus {}
