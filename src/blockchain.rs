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

impl Serializable for Block {}
impl Deserializable for Block {}

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

impl Serializable for BlockHeader {}
impl Deserializable for BlockHeader {}

/// Transactions are digitally signed instructions that tell 
/// the Mainnet state machine to execute a sequence of ‘commands’. 
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct Transaction {
    /// The public address of the external account which signed this transaction
    pub signer: crypto::PublicAddress,
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
    pub signature: crypto::Signature,
    /// The cryptographic hash of signature
    pub hash: crypto::Sha256Hash,
}

impl Serializable for Transaction {}
impl Deserializable for Transaction {}

impl Transaction {
    /// `to_signed` hashes and signs transactions and creates SignedTx which is a data structure suitable for submitting transactions 
    ///  to the ParallelChain ecosystem.
    /// ### Use of this method
    /// 1. If signature is all zeros, it computes a new one with the existing hash in transaction
    /// 2. If hash is all zeros, it computes a new one over the signature (after step 1).
    pub fn to_signed(mut self, keypair: &[u8]) -> Result<SignedTx, CryptographicallyIncorrectTransactionError> {

        let keypair = keypair.as_keypair()
            .map_err(|_|{CryptographicallyIncorrectTransactionError::InvalidKeypair})?;
        
        let serialized_transaction =  Transaction::serialize(&self);
        
        if self.signature == [0u8; 64] {
            self.signature = keypair.sign(serialized_transaction.as_slice()).to_bytes();
        }

        if self.hash == [0u8; 32] {
            self.hash = crypto::sha256(&self.signature);
        }

        Ok(SignedTx(self))
    }

    /// validated return transaction itself after validation of hash and signature
    /// ### Example
    /// ```no_run
    /// let tx = Transaction::deserialize(&value).unwrap();
    /// /// validated the transaction first before converting it to signed transaction
    /// let signed_tx = tx.validated().unwrap().to_signed(keypair);
    /// /// or converting it to "signed" transaction first. It is now optional to validate it.
    /// let signed_tx = tx.to_signed(keypair).validated().unwrap();
    /// ```
    pub fn validated(self) -> Result<Self, CryptographicallyIncorrectTransactionError> {
        self.is_cryptographically_correct()?;
        Ok(self)
    }

    /// Check whether the Transaction is hashed and signed correctly.
    pub fn is_cryptographically_correct(&self) -> Result<(), CryptographicallyIncorrectTransactionError> {
        // Verify the signature using the from_address (public key).
        let signed_msg = {
            let intermediate_txn = Transaction {
                hash: [0; 32],
                signature: [0; 64],
                ..self.to_owned()
            };

            Transaction::serialize(&intermediate_txn)
        };
        let public_key = PublicKey::from_bytes(&self.signer)
            .map_err(|_| CryptographicallyIncorrectTransactionError::InvalidFromAddress)?;
        let signature = Signature::from_bytes(&self.signature)
            .map_err(|_| CryptographicallyIncorrectTransactionError::InvalidSignature)?;
        public_key.verify(&signed_msg, &signature).map_err(|_| CryptographicallyIncorrectTransactionError::WrongSignature)?;

        // Verify the hash over the signature.
        if self.hash != crypto::sha256(signature.to_bytes().as_slice()) {
            return Err(CryptographicallyIncorrectTransactionError::WrongHash)
        }
        
        Ok(())
    }
}

/// Log are messages produced by smart contract executions that are persisted on the blockchain
/// in a cryptographically-provable way. Log produced by transactions that call smart contracts
/// are stored in the `logs` field of a Block in the order in which they are emitted.
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
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

/// SignedTx is a data structure utlized in generating 
/// signed [Transaction] for submission to ParallelChain.
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SignedTx(Transaction);

impl Serializable for SignedTx {}
impl Deserializable for SignedTx {}

impl Deref for SignedTx {
    type Target = Transaction;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<SignedTx> for Transaction {
    fn from(signed_tx: SignedTx) -> Self {
        signed_tx.0
    }
}