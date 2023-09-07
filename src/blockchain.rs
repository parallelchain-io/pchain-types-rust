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

/// A data structure that describes and authorizes the execution of a batch of transactions (state transitions) on the blockchain.
/// 
/// [V1](Block) -> V2: 
/// - "Header" is now of type BlockHeaderV2.
/// - "Transactions" is now of type TransactionV2.
/// - "Receipts" is now of type ReceiptV2.
#[derive(BorshSerialize, BorshDeserialize, Clone)]
pub struct BlockV2 {
    /// Block header
    pub header : BlockHeaderV2,

    /// A dynamically sized list of Transactions.
    pub transactions : Vec<TransactionV2>,

    /// A dynamically sized list of Receipts. If a Block contains a
    /// Transaction, it must also contain its Receipt. Receipts appear in the order of their
    /// Transactions.
    pub receipts : Vec<ReceiptV2>,
}

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

/// Block header defines meta information of a block, including evidence for verifying validity of the block.
/// 
/// [V1](BlockHeader) -> V2:
/// - The position of the “Hash” and “Height” fields are now reversed. Height comes first.
/// - "Transactions Hash" is now the root of the binary merkle tree over the block’s transactions’ hashes, instead of full transactions.
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct BlockHeaderV2 {
    /// The number of Justify-links between this Block and the Genesis Block. 0 for the Genesis Block
    pub height: u64, 

    /// Block hash of this block
    pub hash: Sha256Hash,

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

/// Digitally signed instructions that tell the ParallelChain state machine to execute a sequence of [commands](Command). 
/// 
/// ## Creating a Transaction
/// 
/// There are two ways of creating an instance of transaction:
/// 1. Using the [constructor function](Transaction::new): this takes in the user-provided fields of a transaction and
///    computes its signature and hash automatically.
/// 2. Using a struct expression (i.e., `Transaction { signer: ..., }`): this does not check the signature and hash 
///    fields.
/// 
/// [V1](Transaction) -> V2:
/// - "Signature" is now computed over the tuple: (2u8, Signer, Nonce, Commands, Gas Limit, Max Base Fee per Gas,
/// Priority Fee Per Gas) instead of an “intermediate transaction” (in the tuple, 2u8 corresponds to the fact that
/// TransactionV2 is the second version of transaction)
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TransactionV2 {
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


impl TransactionV2 {
    const VERSION_BYTE: u8 = 2u8;

    pub fn new(
        keypair: &Keypair,
        nonce: u64,
        commands: Vec<Command>,
        gas_limit: u64,
        max_base_fee_per_gas: u64,
        priority_fee_per_gas: u64
    ) -> Self {
        let signer = keypair.public.to_bytes();

        let msg_to_sign = [
            [Self::VERSION_BYTE].to_vec(),
            Serializable::serialize(&signer),
            Serializable::serialize(&nonce),
            Serializable::serialize(&commands),
            Serializable::serialize(&gas_limit),
            Serializable::serialize(&max_base_fee_per_gas),
            Serializable::serialize(&priority_fee_per_gas),
        ].concat();

        let signature = keypair.sign(&msg_to_sign);
        
        let hash = sha256(ed25519_dalek::ed25519::signature::Signature::as_bytes(&signature));
        
        TransactionV2 {
            signer,
            nonce,
            commands,
            gas_limit,
            max_base_fee_per_gas,
            priority_fee_per_gas,
            signature: signature.into(),
            hash
        }
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
        let signed_msg = [
            [Self::VERSION_BYTE].to_vec(),
            Serializable::serialize(&self.signer),
            Serializable::serialize(&self.nonce),
            Serializable::serialize(&self.commands),
            Serializable::serialize(&self.gas_limit),
            Serializable::serialize(&self.max_base_fee_per_gas),
            Serializable::serialize(&self.priority_fee_per_gas),
        ].concat();

        public_key.verify(&signed_msg, &signature).map_err(|_| CryptographicallyIncorrectTransactionError::WrongSignature)?;

        // 4.
        if self.hash != sha256(ed25519_dalek::ed25519::signature::Signature::as_bytes(&signature)) {
            return Err(CryptographicallyIncorrectTransactionError::WrongHash)
        }
        
        Ok(())
    }
}

#[derive(Debug)]
pub enum CryptographicallyIncorrectTransactionError {
    InvalidSigner,
    InvalidSignature,
    WrongSignature,
    WrongHash,
}

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

/// Receipt defines the result of transaction execution.
pub type Receipt = Vec<CommandReceipt>;

/// Receipt defines the result of transaction execution.
/// 
/// [V1](Receipt) -> V2: 
/// - Add Gas Used
/// - Add Exit Code
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ReceiptV2 {
    /// The transaction’s inclusion cost + the sum of the "Gas Used"s of each of the command’s Command Receipts.
    pub gas_used: u64, 
    /// The exit code of the last command in the transaction that was executed.
    pub exit_code: ExitCodeV2,
    /// Describes the execution of each command in the transaction. receipt.command_receipts.len() is always equal
    /// to transaction.commands.len(). If execution exits before a command begins executing (e.g., because of gas
    /// exhaustion), the command receipts of the non-executed commands have exit code NotExecuted.
    pub command_receipts: Vec<CommandReceiptV2>
}

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

/// A CommandReceipt summarizes the result of execution of a [Command].
/// 
/// [V1](CommandReceipt) -> V2:
/// - Remove return values and logs
/// - Add additional field "info" which contains output variants for specific commands
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CommandReceiptV2{
    /// Exit code tells whether the corresponding command in the sequence
    /// succeeded in doing its operation, and, if it failed, whether the 
    /// failure is because of gas exhaustion or some other reason.
    pub exit_code: ExitCodeV2,
    /// How much gas was used in the execution of the transaction. 
    /// This will at most be the transaction’s gas limit.
    pub gas_used: u64,
    /// Additional information which is command-specific. For example, Call command
    /// outputs additional fields, "return value" and "log".
    pub info: CommandReceiptInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum CommandReceiptInfo {
    Transfer,
    Call(CallOutput),
    Deploy,
    CreatePool,
    SetPoolSettings,
    DeletePool,
    CreateDeposit,
    SetDepositSettings,
    TopUpDeposit,
    WithdrawDeposit(WithdrawDepositOutput),
    StakeDeposit(StakeDepositOutput),
    UnstakeDeposit(UnstakeDepositOutput),
    NextEpoch,
}

/// Defines the success and error types of receipt or command receipt.
/// 
/// [V1](ExitStatus) -> V2:
/// - Add "Not Executed" variant
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ExitCodeV2 {
    /// The Transaction successfully accomplished everything that it could have been expected to do.
    Ok,
    /// The Transaction failed to accomplish the primary operation that Transactions of its kinds are expected to accomplish.
    Error,
    /// The Gas Limit was exceeded by a dynamically costed activity in a dynamic-cost Transaction.
    GasExhausted,
    /// Transaction execution exited before the command was executed, for example due to gas exhaustion. 
    NotExecuted,
}

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

macro_rules! define_serde {
    ($($t:ty),*) => {
        $(
            impl Serializable for $t {}
            impl Deserializable for $t {}
        )*
    }
}

define_serde!(
    Block, BlockV2, BlockHeader, BlockHeaderV2,
    Transaction, TransactionV2, Command, Log, 
    ReceiptV2, CommandReceipt, CommandReceiptV2, CommandReceiptInfo, ExitStatus, ExitCodeV2
);

#[cfg(test)]
mod test {
    use rand::rngs::OsRng;
    use ed25519_dalek::Keypair;

    use crate::{runtime::TransferInput, blockchain::CryptographicallyIncorrectTransactionError};
    use super::{Command, Transaction};

    #[test]
    fn verify_transaction_signer() {
        let mut csprng = OsRng{};
        let signer: Keypair = Keypair::generate(&mut csprng);

        let command = Command::Transfer( TransferInput{
            recipient: [0;32],
            amount: 1000,
        });

        // Create new transaction for test
        let mut txn = Transaction::new(&signer, 0, vec![command], 500000, 8, 0);
        assert!(txn.is_cryptographically_correct().is_ok());

        // set another signer key that cannot decompress Edwards point
        txn.signer = [5;32];
        let result = txn.is_cryptographically_correct();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(),CryptographicallyIncorrectTransactionError::InvalidSigner));
    }

    #[test]
    fn verify_invalid_transaction_signature() {
        let mut csprng = OsRng{};
        let signer: Keypair = Keypair::generate(&mut csprng);

        let command = Command::Transfer( TransferInput{
            recipient: [0;32],
            amount: 1000,
        });

        // Create new transaction for test
        let mut txn = Transaction::new(&signer, 0, vec![command], 500000, 8, 0);
        assert!(txn.is_cryptographically_correct().is_ok());

        // set invalid signature that cannot decompress Edwards point
        txn.signature = [224;64];
        let result = txn.is_cryptographically_correct();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(),CryptographicallyIncorrectTransactionError::InvalidSignature));
    }

    #[test]
    fn verify_mismatch_transaction_signature() {
        let mut csprng = OsRng{};
        let signer: Keypair = Keypair::generate(&mut csprng);
        let mut csprng = OsRng{};
        let receiver: Keypair = Keypair::generate(&mut csprng);

        let command = Command::Transfer( TransferInput{
            recipient: receiver.public.to_bytes(),
            amount: 1000,
        });

        // Create new transaction for test
        let mut txn = Transaction::new(&signer, 0, vec![command], 500000, 8, 0);
        assert!(txn.is_cryptographically_correct().is_ok());

        // set another signer with wrong signature
        txn.signer = receiver.public.to_bytes();
        let result = txn.is_cryptographically_correct();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(),CryptographicallyIncorrectTransactionError::WrongSignature));
    }

    #[test]
    fn verify_transaction_hash() {
        let mut csprng = OsRng{};
        let signer: Keypair = Keypair::generate(&mut csprng);

        let command = Command::Transfer( TransferInput{
            recipient: [1;32],
            amount: 1000,
        });

        // Create new transaction for test
        let mut txn = Transaction::new(&signer, 0, vec![command], 500000, 8, 0);
        assert!(txn.is_cryptographically_correct().is_ok());

        // intensionally set invalid hash
        txn.hash = [0;32];
        let result = txn.is_cryptographically_correct();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(),CryptographicallyIncorrectTransactionError::WrongHash));
    }
}