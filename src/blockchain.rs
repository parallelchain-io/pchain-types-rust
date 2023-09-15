/*
    Copyright © 2023, ParallelChain Lab 
    Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
*/

//! Types which appear in blocks like transactions and receipts, and also blocks themselves.

use borsh::{BorshSerialize, BorshDeserialize};
use crate::block_data::{BlockDataV1, BlockDataV2};
use crate::serialization::{Serializable, Deserializable};
use crate::cryptography::{Keypair, PublicKey, PublicAddress, SignatureBytes, Signer, Verifier, Sha256Hash, BloomFilter, sha256};
use crate::{runtime::*, block_data};

/// A data structure that describes and authorizes the execution of a batch of transactions (state transitions) on the blockchain.
#[derive(BorshSerialize, BorshDeserialize, Clone)]
pub struct BlockV1 {
    /// Block header
    pub header : BlockHeaderV1,

    /// A dynamically sized list of Transactions
    pub transactions : Vec<TransactionV1>,

    /// A dynamically sized list of Receipts. If a Block contains a Transaction,
    /// it must also contain its Receipt. Receipts appear in the order of their Transactions.
    pub receipts : Vec<ReceiptV1>,
}

/// A data structure that describes and authorizes the execution of a batch of transactions (state transitions) on the blockchain.
/// 
/// [V1](BlockV1) -> V2: 
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

/// Create `Impl`s for Block exclusively from Version 1 to Version 2. The `impl`s define
/// same set of functions across versions.
/// 
/// Arguments: (Block struct, Block Header struct, Block Data struct)
macro_rules! block_impl_v1_to_v2 {
    ($block:tt, $block_header:tt, $block_data:tt) => {
        impl $block {
            /// Conversion from [hotstuff_rs::types::Block], with an option to validate
            /// signature of the transactions.
            pub fn from_hotstuff_block(
                block: hotstuff_rs::types::Block, verify_transaction_signatures: bool
            ) -> Result<Self, block_data::BlockDataFromHotStuffDataError> {
                let blockdata = $block_data::from_data(&block.data, verify_transaction_signatures)?;
                Ok(Self{
                    header: $block_header {
                        height: block.height,
                        hash: block.hash,
                        justify: block.justify,
                        data_hash: block.data_hash,
                        chain_id: blockdata.header.chain_id,
                        proposer: blockdata.header.proposer,
                        timestamp: blockdata.header.timestamp,
                        base_fee_per_gas: blockdata.header.base_fee_per_gas,
                        gas_used: blockdata.header.gas_used,
                        txns_hash: blockdata.header.transactions_hash,
                        receipts_hash: blockdata.header.receipts_hash,
                        state_hash: blockdata.header.state_hash,
                        logs_bloom: blockdata.header.logs_bloom
                    },
                    transactions: blockdata.transactions,
                    receipts: blockdata.receipts
                })
        
            }
        }        
    };
}

block_impl_v1_to_v2!(BlockV1, BlockHeaderV1, BlockDataV1);
block_impl_v1_to_v2!(BlockV2, BlockHeaderV2, BlockDataV2);

/// Block header defines meta information of a block, including evidence for verifying validity of the block.
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct BlockHeaderV1 {
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
    pub base_fee_per_gas: u64,

    /// The total gas used for producing the block.
    pub gas_used: u64,

    /// Transactions Hash, the Binary Merkle Tree root hash over the Block’s Transactions
    pub txns_hash: Sha256Hash,

    /// Receipts Hash, the Binary Merkle Tree root hash over the Block’s Receipts
    pub receipts_hash: Sha256Hash,

    /// State Hash, the SHA256 root hash of the blockchain’s World State Merkle Patricia 
    /// Trie (MPT) after executing all of this Block’s Transactions
    pub state_hash: Sha256Hash,

    /// Logs Bloom, the 256-byte Block-level Bloom Filter union of all the Bloom Filters of each Log topic from the Block’s Receipts
    pub logs_bloom: BloomFilter,
}

/// Block header defines meta information of a block, including evidence for verifying validity of the block.
/// 
/// [V1](BlockHeaderV1) -> V2:
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
    pub base_fee_per_gas: u64,

    /// The total gas used for producing the block.
    pub gas_used: u64,

    /// Transactions Hash, the Binary Merkle Tree root hash over the Block’s Transactions
    pub txns_hash: Sha256Hash,

    /// Receipts Hash, the Binary Merkle Tree root hash over the Block’s Receipts
    pub receipts_hash: Sha256Hash,

    /// State Hash, the SHA256 root hash of the blockchain’s World State Merkle Patricia 
    /// Trie (MPT) after executing all of this Block’s Transactions
    pub state_hash: Sha256Hash,

    /// Logs Bloom, the 256-byte Block-level Bloom Filter union of all the Bloom Filters of each Log topic from the Block’s Receipts
    pub logs_bloom: BloomFilter,
}

/// Digitally signed instructions that tell the ParallelChain state machine to execute a sequence of [commands](Command). 
/// 
/// ## Creating a Transaction
/// 
/// There are two ways of creating an instance of transaction:
/// 1. Using the constructor function, `TransactionV1::new(..)`: this takes in the user-provided fields of a transaction and
///    computes its signature and hash automatically.
/// 2. Using a struct expression (i.e., `TransactionV1 { signer: ..., }`): this does not check the signature and hash 
///    fields.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TransactionV1 {
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

impl TransactionV1 {
    pub fn new(signer: &Keypair, nonce: u64, commands: Vec<Command>, gas_limit: u64, max_base_fee_per_gas: u64, priority_fee_per_gas: u64) -> TransactionV1 {
        let mut transaction = TransactionV1 {
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
            let intermediate_txn = TransactionV1 {
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
/// 1. Using the constructor function, `TransactionV2::new()`: this takes in the user-provided fields of a transaction and
///    computes its signature and hash automatically.
/// 2. Using a struct expression (i.e., `TransactionV2 { signer: ..., }`): this does not check the signature and hash 
///    fields.
/// 
/// [V1](TransactionV1) -> V2:
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
        ]
        .concat();

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
        ]
        .concat();

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
pub type ReceiptV1 = Vec<CommandReceiptV1>;

/// Receipt defines the result of transaction execution.
/// 
/// [V1](ReceiptV1) -> V2: 
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
pub struct CommandReceiptV1 {
    /// Exit code tells whether the corresponding command in the sequence
    /// succeeded in doing its operation, and, if it failed, whether the 
    /// failure is because of gas exhaustion or some other reason.
    pub exit_code: ExitCodeV1,
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
/// [V1](CommandReceiptV1) -> V2:
/// - Command Receipt is now an enum type. Its variants come in the same order as Command.
/// - All variants have common fields: Exit Code and Gas Used. Some varients have additional
/// fields.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum CommandReceiptV2 {
    Transfer(TransferReceipt),
    Call(CallReceipt),
    Deploy(DeployReceipt),
    CreatePool(CreatePoolReceipt),
    SetPoolSettings(SetPoolSettingsReceipt),
    DeletePool(DeletePoolReceipt),
    CreateDeposit(CreateDepositReceipt),
    SetDepositSettings(SetDepositSettingsReceipt),
    TopUpDeposit(TopUpDepositReceipt),
    WithdrawDeposit(WithdrawDepositReceipt),
    StakeDeposit(StakeDepositReceipt),
    UnstakeDeposit(UnstakeDepositReceipt),
    NextEpoch(NextEpochReceipt),
}

/// Command Receipt structs with common fields
macro_rules! command_receipt_common_fields {
    ($($t:tt),*) => {
        $(
            #[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
            pub struct $t {
                /// Exit code tells whether the corresponding command in the sequence
                /// succeeded in doing its operation, and, if it failed, whether the 
                /// failure is because of gas exhaustion or some other reason.
                pub exit_code: ExitCodeV2,
                /// How much gas was used in the execution of the transaction. 
                /// This will at most be the transaction’s gas limit.
                pub gas_used: u64,
            }
        )*
    }
}

command_receipt_common_fields!(
    TransferReceipt, DeployReceipt,
    CreatePoolReceipt, SetPoolSettingsReceipt, DeletePoolReceipt,
    CreateDepositReceipt, SetDepositSettingsReceipt, TopUpDepositReceipt,
    NextEpochReceipt
);


#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CallReceipt {
    /// Exit code tells whether the corresponding command in the sequence
    /// succeeded in doing its operation, and, if it failed, whether the 
    /// failure is because of gas exhaustion or some other reason.
    pub exit_code: ExitCodeV2,
    /// How much gas was used in the execution of the transaction. 
    /// This will at most be the transaction’s gas limit.
    pub gas_used: u64,
    /// The return value of the corresponding command.
    pub return_value: Vec<u8>,
    /// The logs emitted during the corresponding call command.
    pub logs: Vec<Log>,
}


#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct WithdrawDepositReceipt {
    /// Exit code tells whether the corresponding command in the sequence
    /// succeeded in doing its operation, and, if it failed, whether the 
    /// failure is because of gas exhaustion or some other reason.
    pub exit_code: ExitCodeV2,
    /// How much gas was used in the execution of the transaction. 
    /// This will at most be the transaction’s gas limit.
    pub gas_used: u64,
    /// The amount of deposit withdrawn.
    pub amount_withdrawn: u64
}


#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct StakeDepositReceipt {
    /// Exit code tells whether the corresponding command in the sequence
    /// succeeded in doing its operation, and, if it failed, whether the 
    /// failure is because of gas exhaustion or some other reason.
    pub exit_code: ExitCodeV2,
    /// How much gas was used in the execution of the transaction. 
    /// This will at most be the transaction’s gas limit.
    pub gas_used: u64,
    /// The amount of deposit staked.
    pub amount_staked: u64
}

#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct UnstakeDepositReceipt {
    /// Exit code tells whether the corresponding command in the sequence
    /// succeeded in doing its operation, and, if it failed, whether the 
    /// failure is because of gas exhaustion or some other reason.
    pub exit_code: ExitCodeV2,
    /// How much gas was used in the execution of the transaction. 
    /// This will at most be the transaction’s gas limit.
    pub gas_used: u64,
    /// The amount of deposit unstaked.
    pub amount_unstaked: u64
}

/// Defines the success and error types of a receipt or command receipt.
/// 
/// [V1](ExitCodeV1) -> V2:
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

/// Defines the success and error types of receipt.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ExitCodeV1 {
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
    BlockV1, BlockV2, BlockHeaderV1, BlockHeaderV2,
    TransactionV1, TransactionV2, Command, Log, 
    ReceiptV2, CommandReceiptV1, CommandReceiptV2, ExitCodeV1, ExitCodeV2,

    TransferReceipt, DeployReceipt, CallReceipt,
    CreatePoolReceipt, SetPoolSettingsReceipt, DeletePoolReceipt,
    CreateDepositReceipt, SetDepositSettingsReceipt, TopUpDepositReceipt, WithdrawDepositReceipt,
    StakeDepositReceipt, UnstakeDepositReceipt, NextEpochReceipt
);

#[cfg(test)]
mod test {
    use std::convert::TryFrom;

    use rand::rngs::OsRng;
    use ed25519_dalek::Keypair;

    use crate::{runtime::TransferInput, blockchain::{CryptographicallyIncorrectTransactionError, TransactionV2, CommandReceiptV1, BlockV1}, block_data::{BlockDataV2, BlockHeaderDataV2, DatumIndexV2, BlockDataFromHotStuffDataError, BlockHeaderDataFromHotStuffDataError, BlockDataV1, BlockHeaderDataV1, DatumIndexV1}, serialization::Serializable};
    use super::{Command, TransactionV1, BlockV2, ReceiptV2, ExitCodeV2};

    #[test]
    fn verify_transaction_v1() {
        // Create new transaction for test
        let txn = {
            let mut csprng = OsRng{};
            let signer: Keypair = Keypair::generate(&mut csprng);

            let command = Command::Transfer( TransferInput{
                recipient: [0;32],
                amount: 1000,
            });
            TransactionV1::new(&signer, 0, vec![command], 500000, 8, 0)
        };

        // Verify transaction signature
        assert!(txn.is_cryptographically_correct().is_ok());

        // Set another signer key that cannot decompress Edwards point
        let invalid_txn = TransactionV1 {
            signer: [5; 32],
            ..txn.clone()
        };
        let result = invalid_txn.is_cryptographically_correct();
        assert!(matches!(result,Err(CryptographicallyIncorrectTransactionError::InvalidSigner)));

        // Set invalid signature that cannot decompress Edwards point
        let invalid_txn = TransactionV1 {
            signature: [224;64],
            ..txn.clone()
        };
        let result = invalid_txn.is_cryptographically_correct();
        assert!(matches!(result,Err(CryptographicallyIncorrectTransactionError::InvalidSignature)));

        // Intensionally set invalid hash
        let invalid_txn = TransactionV1 {
            hash: [0;32],
            ..txn.clone()
        };
        let result = invalid_txn.is_cryptographically_correct();
        assert!(matches!(result,Err(CryptographicallyIncorrectTransactionError::WrongHash)));

        // Set another signer with wrong signature
        let mut csprng = OsRng{};
        let wrong_signer: Keypair = Keypair::generate(&mut csprng);
        let invalid_txn = TransactionV1 {
            signer: wrong_signer.public.to_bytes(),
            ..txn.clone()
        };
        let result = invalid_txn.is_cryptographically_correct();
        assert!(matches!(result,Err(CryptographicallyIncorrectTransactionError::WrongSignature)));
    }

    #[test]
    fn verify_transaction_v2() {
        // Create new transaction for test
        let txn = {
            let mut csprng = OsRng{};
            let signer: Keypair = Keypair::generate(&mut csprng);

            let command = Command::Transfer( TransferInput{
                recipient: [0;32],
                amount: 1000,
            });
            TransactionV2::new(&signer, 0, vec![command], 500000, 8, 0)
        };

        // Verify transaction signature
        assert!(txn.is_cryptographically_correct().is_ok());

        // Set another signer key that cannot decompress Edwards point
        let invalid_txn = TransactionV2 {
            signer: [5; 32],
            ..txn.clone()
        };
        let result = invalid_txn.is_cryptographically_correct();
        assert!(matches!(result,Err(CryptographicallyIncorrectTransactionError::InvalidSigner)));

        // Set invalid signature that cannot decompress Edwards point
        let invalid_txn = TransactionV2 {
            signature: [224;64],
            ..txn.clone()
        };
        let result = invalid_txn.is_cryptographically_correct();
        assert!(matches!(result,Err(CryptographicallyIncorrectTransactionError::InvalidSignature)));

        // Intensionally set invalid hash
        let invalid_txn = TransactionV2 {
            hash: [0;32],
            ..txn.clone()
        };
        let result = invalid_txn.is_cryptographically_correct();
        assert!(matches!(result,Err(CryptographicallyIncorrectTransactionError::WrongHash)));

        // Set another signer with wrong signature
        let mut csprng = OsRng{};
        let wrong_signer: Keypair = Keypair::generate(&mut csprng);
        let invalid_txn = TransactionV2 {
            signer: wrong_signer.public.to_bytes(),
            ..txn.clone()
        };
        let result = invalid_txn.is_cryptographically_correct();
        assert!(matches!(result,Err(CryptographicallyIncorrectTransactionError::WrongSignature)));
    }

    #[test]
    fn verify_block_data_v2_conversion() {
        // Prepare test data: transaction receipt and a Hotsuff Block
        let transaction = {
            let mut csprng = OsRng{};
            let signer: Keypair = Keypair::generate(&mut csprng);

            let command = Command::Transfer( TransferInput{
                recipient: [0;32],
                amount: 1000,
            });
            TransactionV2::new(&signer, 0, vec![command], 500000, 8, 0)
        };
        let receipt = ReceiptV2 {
            command_receipts: Vec::new(),
            exit_code: ExitCodeV2::Ok,
            gas_used: 12345,
        };
        let block = {
            let block_data = BlockDataV2 {
                header: BlockHeaderDataV2 {
                    chain_id: 123,
                    base_fee_per_gas: 8, 
                    proposer: [3u8; 32],
                    timestamp: 12345678,
                    gas_used: 100,
                    transactions_hash: [45u8; 32],
                    receipts_hash: [56u8; 32],
                    state_hash: [99u8; 32],
                    logs_bloom: [11u8; 256]
                },
                transactions: vec![transaction.clone()],
                receipts: vec![receipt.clone()]
            };

            let hotstuff_data = hotstuff_rs::types::Data::from(block_data);
            hotstuff_rs::types::Block::new(
                1234, 
                hotstuff_rs::types::QuorumCertificate {
                    chain_id: 123,
                    view: 2,
                    block: [32u8; 32],
                    phase: hotstuff_rs::types::Phase::Generic,
                    signatures: vec![]
                }, 
                [45u8; 32],
                hotstuff_data
            )
        };
        let block_hash_computed_from_hotstuff_rs = block.hash;

        let verify_block = |blockv2: BlockV2| {
            assert_eq!(blockv2.header.height, 1234);
            assert_eq!(blockv2.header.chain_id, 123);
            assert_eq!(blockv2.header.proposer, [3u8; 32]);
            assert_eq!(blockv2.header.base_fee_per_gas, 8);
            assert_eq!(blockv2.header.gas_used, 100);
            assert_eq!(blockv2.header.justify.chain_id, 123);
            assert_eq!(blockv2.header.justify.view, 2);
            assert_eq!(blockv2.header.justify.block, [32u8; 32]);
            assert_eq!(blockv2.header.justify.phase, hotstuff_rs::types::Phase::Generic);
            assert_eq!(blockv2.header.justify.signatures, vec![]);
            assert_eq!(blockv2.header.timestamp, 12345678);
            assert_eq!(blockv2.header.txns_hash, [45u8; 32]);
            assert_eq!(blockv2.header.receipts_hash, [56u8; 32]);
            assert_eq!(blockv2.header.state_hash, [99u8; 32]);
            assert_eq!(blockv2.header.data_hash, [45u8; 32]);
            assert_eq!(blockv2.header.logs_bloom, [11u8; 256]);
            assert_eq!(blockv2.header.hash, block_hash_computed_from_hotstuff_rs);
    
            assert_eq!(blockv2.transactions.first().unwrap(), &transaction);
            assert_eq!(blockv2.receipts.first().unwrap(), &receipt);
        };

        // Without verifying transaction signature
        let blockv2 = BlockV2::from_hotstuff_block(block.clone(), false).unwrap();
        verify_block(blockv2);

        // Block Conversion with verifying transaction signature.
        assert!(BlockDataV2::try_from(&block.data).is_ok());
        let blockv2 = BlockV2::from_hotstuff_block(block.clone(), true).unwrap();
        verify_block(blockv2);

        // Verify transaction signature
        let mut invalid_block = block.clone();
        match invalid_block.data.get_mut(DatumIndexV2::transactions_start_index() as usize) {
            Some(tx_ptr) => {
                *tx_ptr = Serializable::serialize(&TransactionV2 {
                    signature: [99u8; 64], // wrong signature
                    ..transaction
                });
            },
            None => panic!("cannot find the first transaction in block data!")
        }
        assert!(matches!(BlockDataV2::try_from(&invalid_block.data),Err(BlockDataFromHotStuffDataError::InvalidTransactionSignature)));
        assert!(matches!(BlockV2::from_hotstuff_block(invalid_block, true),Err(BlockDataFromHotStuffDataError::InvalidTransactionSignature)));

        // Verify transaction integrity
        let mut invalid_block = block.clone();
        match invalid_block.data.get_mut(DatumIndexV2::transactions_start_index() as usize) {
            Some(tx_ptr) => {
                *tx_ptr = vec![1u8];
            },
            None => panic!("cannot find the first transaction in block data!")
        }
        assert!(matches!(BlockV2::from_hotstuff_block(invalid_block, false),Err(BlockDataFromHotStuffDataError::Transaction)));

        // Verify receipt integrity
        let mut invalid_block = block.clone();
        match invalid_block.data.get_mut(DatumIndexV2::receipts_start_index(1) as usize) {
            Some(recp_ptr) => {
                *recp_ptr = vec![1u8];
            },
            None => panic!("cannot find the first receipt in block data!")
        }
        assert!(matches!(BlockV2::from_hotstuff_block(invalid_block, false),Err(BlockDataFromHotStuffDataError::Receipt)));

        // Verify number of Transactions and Receipts
        let mut invalid_block = block.clone();
        invalid_block.data.remove(DatumIndexV2::receipts_start_index(1));
        assert!(matches!(
            BlockV2::from_hotstuff_block(invalid_block, false),
            Err(BlockDataFromHotStuffDataError::IncorrectNumberOfTxnsAndReceipts)
        ));

        // Verify block header integrity
        // - Number of Slots
        let mut invalid_block = block.clone();
        invalid_block.data = Vec::new();
        assert!(matches!(
            BlockV2::from_hotstuff_block(invalid_block, false),
            Err(BlockDataFromHotStuffDataError::WrongHeader(BlockHeaderDataFromHotStuffDataError::NumberOfSlots))
        ));
        // - chain id
        let mut invalid_block = block.clone();
        DatumIndexV2::set_chain_id(&mut invalid_block.data, Vec::new());
        assert!(matches!(
            BlockV2::from_hotstuff_block(invalid_block, false),
            Err(BlockDataFromHotStuffDataError::WrongHeader(BlockHeaderDataFromHotStuffDataError::ChainID))
        ));
        // - proposer
        let mut invalid_block = block.clone();
        DatumIndexV2::set_proposer(&mut invalid_block.data, Vec::new());
        assert!(matches!(
            BlockV2::from_hotstuff_block(invalid_block, false),
            Err(BlockDataFromHotStuffDataError::WrongHeader(BlockHeaderDataFromHotStuffDataError::Proposer))
        ));
        // - base_fee_per_gas
        let mut invalid_block = block.clone();
        DatumIndexV2::set_base_fee_per_gas(&mut invalid_block.data, Vec::new());
        assert!(matches!(
            BlockV2::from_hotstuff_block(invalid_block, false),
            Err(BlockDataFromHotStuffDataError::WrongHeader(BlockHeaderDataFromHotStuffDataError::BaseFeePerGas))
        ));
        // - gas_used
        let mut invalid_block = block.clone();
        DatumIndexV2::set_gas_used(&mut invalid_block.data, Vec::new());
        assert!(matches!(
            BlockV2::from_hotstuff_block(invalid_block, false),
            Err(BlockDataFromHotStuffDataError::WrongHeader(BlockHeaderDataFromHotStuffDataError::GasUsed))
        ));
        // - timestamp
        let mut invalid_block = block.clone();
        DatumIndexV2::set_timestamp(&mut invalid_block.data, Vec::new());
        assert!(matches!(
            BlockV2::from_hotstuff_block(invalid_block, false),
            Err(BlockDataFromHotStuffDataError::WrongHeader(BlockHeaderDataFromHotStuffDataError::Timestamp))
        ));
        // - transactions_hash
        let mut invalid_block = block.clone();
        DatumIndexV2::set_transactions_hash(&mut invalid_block.data, Vec::new());
        assert!(matches!(
            BlockV2::from_hotstuff_block(invalid_block, false),
            Err(BlockDataFromHotStuffDataError::WrongHeader(BlockHeaderDataFromHotStuffDataError::TxnsHash))
        ));
        // - receipts_hash
        let mut invalid_block = block.clone();
        DatumIndexV2::set_receipts_hash(&mut invalid_block.data, Vec::new());
        assert!(matches!(
            BlockV2::from_hotstuff_block(invalid_block, false),
            Err(BlockDataFromHotStuffDataError::WrongHeader(BlockHeaderDataFromHotStuffDataError::ReceiptsHash))
        ));
        // - state_hash
        let mut invalid_block = block.clone();
        DatumIndexV2::set_state_hash(&mut invalid_block.data, Vec::new());
        assert!(matches!(
            BlockV2::from_hotstuff_block(invalid_block, false),
            Err(BlockDataFromHotStuffDataError::WrongHeader(BlockHeaderDataFromHotStuffDataError::StateHash))
        ));
        // - logs_bloom
        let mut invalid_block = block.clone();
        DatumIndexV2::set_logs_bloom(&mut invalid_block.data, Vec::new());
        assert!(matches!(
            BlockV2::from_hotstuff_block(invalid_block, false),
            Err(BlockDataFromHotStuffDataError::WrongHeader(BlockHeaderDataFromHotStuffDataError::LogsBloom))
        ));
    }

    #[test]
    fn verify_block_data_v1_conversion() {
        // Prepare test data: transaction receipt and a Hotsuff Block
        let transaction = {
            let mut csprng = OsRng{};
            let signer: Keypair = Keypair::generate(&mut csprng);

            let command = Command::Transfer( TransferInput{
                recipient: [0;32],
                amount: 1000,
            });
            TransactionV1::new(&signer, 0, vec![command], 500000, 8, 0)
        };
        let receipt = Vec::<CommandReceiptV1>::new();
        let block = {
            let block_data = BlockDataV1 {
                header: BlockHeaderDataV1 {
                    chain_id: 123,
                    base_fee_per_gas: 8, 
                    proposer: [3u8; 32],
                    timestamp: 12345678,
                    gas_used: 100,
                    transactions_hash: [45u8; 32],
                    receipts_hash: [56u8; 32],
                    state_hash: [99u8; 32],
                    logs_bloom: [11u8; 256]
                },
                transactions: vec![transaction.clone()],
                receipts: vec![receipt.clone()]
            };

            let hotstuff_data = hotstuff_rs::types::Data::from(block_data);
            hotstuff_rs::types::Block::new(
                1234, 
                hotstuff_rs::types::QuorumCertificate {
                    chain_id: 123,
                    view: 2,
                    block: [32u8; 32],
                    phase: hotstuff_rs::types::Phase::Generic,
                    signatures: vec![]
                }, 
                [45u8; 32],
                hotstuff_data
            )
        };
        let block_hash_computed_from_hotstuff_rs = block.hash;

        let verify_block = |blockv1: BlockV1| {
            assert_eq!(blockv1.header.height, 1234);
            assert_eq!(blockv1.header.chain_id, 123);
            assert_eq!(blockv1.header.proposer, [3u8; 32]);
            assert_eq!(blockv1.header.base_fee_per_gas, 8);
            assert_eq!(blockv1.header.gas_used, 100);
            assert_eq!(blockv1.header.justify.chain_id, 123);
            assert_eq!(blockv1.header.justify.view, 2);
            assert_eq!(blockv1.header.justify.block, [32u8; 32]);
            assert_eq!(blockv1.header.justify.phase, hotstuff_rs::types::Phase::Generic);
            assert_eq!(blockv1.header.justify.signatures, vec![]);
            assert_eq!(blockv1.header.timestamp, 12345678);
            assert_eq!(blockv1.header.txns_hash, [45u8; 32]);
            assert_eq!(blockv1.header.receipts_hash, [56u8; 32]);
            assert_eq!(blockv1.header.state_hash, [99u8; 32]);
            assert_eq!(blockv1.header.data_hash, [45u8; 32]);
            assert_eq!(blockv1.header.logs_bloom, [11u8; 256]);
            assert_eq!(blockv1.header.hash, block_hash_computed_from_hotstuff_rs);
    
            assert_eq!(blockv1.transactions.first().unwrap(), &transaction);
            assert_eq!(blockv1.receipts.first().unwrap(), &receipt);
        };

        // Without verifying transaction signature
        let blockv1 = BlockV1::from_hotstuff_block(block.clone(), false).unwrap();
        verify_block(blockv1);

        // Block Conversion with verifying transaction signature.
        assert!(BlockDataV1::try_from(&block.data).is_ok());
        let blockv1 = BlockV1::from_hotstuff_block(block.clone(), true).unwrap();
        verify_block(blockv1);

        // Verify transaction signature
        let mut invalid_block = block.clone();
        match invalid_block.data.get_mut(DatumIndexV1::transactions_start_index() as usize) {
            Some(tx_ptr) => {
                *tx_ptr = Serializable::serialize(&TransactionV1 {
                    signature: [99u8; 64], // wrong signature
                    ..transaction
                });
            },
            None => panic!("cannot find the first transaction in block data!")
        }
        assert!(matches!(BlockDataV1::try_from(&invalid_block.data),Err(BlockDataFromHotStuffDataError::InvalidTransactionSignature)));
        assert!(matches!(BlockV1::from_hotstuff_block(invalid_block, true),Err(BlockDataFromHotStuffDataError::InvalidTransactionSignature)));

        // Verify transaction integrity
        let mut invalid_block = block.clone();
        match invalid_block.data.get_mut(DatumIndexV1::transactions_start_index() as usize) {
            Some(tx_ptr) => {
                *tx_ptr = vec![1u8];
            },
            None => panic!("cannot find the first transaction in block data!")
        }
        assert!(matches!(BlockV1::from_hotstuff_block(invalid_block, false),Err(BlockDataFromHotStuffDataError::Transaction)));

        // Verify receipt integrity
        let mut invalid_block = block.clone();
        match invalid_block.data.get_mut(DatumIndexV1::receipts_start_index(1) as usize) {
            Some(recp_ptr) => {
                *recp_ptr = vec![1u8];
            },
            None => panic!("cannot find the first receipt in block data!")
        }
        assert!(matches!(BlockV1::from_hotstuff_block(invalid_block, false),Err(BlockDataFromHotStuffDataError::Receipt)));

        // Verify number of Transactions and Receipts
        let mut invalid_block = block.clone();
        invalid_block.data.remove(DatumIndexV1::receipts_start_index(1));
        assert!(matches!(
            BlockV1::from_hotstuff_block(invalid_block, false),
            Err(BlockDataFromHotStuffDataError::IncorrectNumberOfTxnsAndReceipts)
        ));

        // Verify block header integrity
        // - Number of Slots
        let mut invalid_block = block.clone();
        invalid_block.data = Vec::new();
        assert!(matches!(
            BlockV1::from_hotstuff_block(invalid_block, false),
            Err(BlockDataFromHotStuffDataError::WrongHeader(BlockHeaderDataFromHotStuffDataError::NumberOfSlots))
        ));
        // - chain id
        let mut invalid_block = block.clone();
        DatumIndexV1::set_chain_id(&mut invalid_block.data, Vec::new());
        assert!(matches!(
            BlockV1::from_hotstuff_block(invalid_block, false),
            Err(BlockDataFromHotStuffDataError::WrongHeader(BlockHeaderDataFromHotStuffDataError::ChainID))
        ));
        // - proposer
        let mut invalid_block = block.clone();
        DatumIndexV1::set_proposer(&mut invalid_block.data, Vec::new());
        assert!(matches!(
            BlockV1::from_hotstuff_block(invalid_block, false),
            Err(BlockDataFromHotStuffDataError::WrongHeader(BlockHeaderDataFromHotStuffDataError::Proposer))
        ));
        // - base_fee_per_gas
        let mut invalid_block = block.clone();
        DatumIndexV1::set_base_fee_per_gas(&mut invalid_block.data, Vec::new());
        assert!(matches!(
            BlockV1::from_hotstuff_block(invalid_block, false),
            Err(BlockDataFromHotStuffDataError::WrongHeader(BlockHeaderDataFromHotStuffDataError::BaseFeePerGas))
        ));
        // - gas_used
        let mut invalid_block = block.clone();
        DatumIndexV1::set_gas_used(&mut invalid_block.data, Vec::new());
        assert!(matches!(
            BlockV1::from_hotstuff_block(invalid_block, false),
            Err(BlockDataFromHotStuffDataError::WrongHeader(BlockHeaderDataFromHotStuffDataError::GasUsed))
        ));
        // - timestamp
        let mut invalid_block = block.clone();
        DatumIndexV1::set_timestamp(&mut invalid_block.data, Vec::new());
        assert!(matches!(
            BlockV1::from_hotstuff_block(invalid_block, false),
            Err(BlockDataFromHotStuffDataError::WrongHeader(BlockHeaderDataFromHotStuffDataError::Timestamp))
        ));
        // - transactions_hash
        let mut invalid_block = block.clone();
        DatumIndexV1::set_transactions_hash(&mut invalid_block.data, Vec::new());
        assert!(matches!(
            BlockV1::from_hotstuff_block(invalid_block, false),
            Err(BlockDataFromHotStuffDataError::WrongHeader(BlockHeaderDataFromHotStuffDataError::TxnsHash))
        ));
        // - receipts_hash
        let mut invalid_block = block.clone();
        DatumIndexV1::set_receipts_hash(&mut invalid_block.data, Vec::new());
        assert!(matches!(
            BlockV1::from_hotstuff_block(invalid_block, false),
            Err(BlockDataFromHotStuffDataError::WrongHeader(BlockHeaderDataFromHotStuffDataError::ReceiptsHash))
        ));
        // - state_hash
        let mut invalid_block = block.clone();
        DatumIndexV1::set_state_hash(&mut invalid_block.data, Vec::new());
        assert!(matches!(
            BlockV1::from_hotstuff_block(invalid_block, false),
            Err(BlockDataFromHotStuffDataError::WrongHeader(BlockHeaderDataFromHotStuffDataError::StateHash))
        ));
        // - logs_bloom
        let mut invalid_block = block.clone();
        DatumIndexV1::set_logs_bloom(&mut invalid_block.data, Vec::new());
        assert!(matches!(
            BlockV1::from_hotstuff_block(invalid_block, false),
            Err(BlockDataFromHotStuffDataError::WrongHeader(BlockHeaderDataFromHotStuffDataError::LogsBloom))
        ));
    }

    #[test]
    fn verify_block_header_data_v1_and_v2() {
        let block_header_data_v1 = BlockHeaderDataV1 {
            chain_id: 123,
            base_fee_per_gas: 8, 
            proposer: [3u8; 32],
            timestamp: 12345678,
            gas_used: 100,
            transactions_hash: [45u8; 32],
            receipts_hash: [56u8; 32],
            state_hash: [99u8; 32],
            logs_bloom: [11u8; 256]
        };

        let block_header_data_v2 = BlockHeaderDataV2 {
            chain_id: 123,
            base_fee_per_gas: 8, 
            proposer: [3u8; 32],
            timestamp: 12345678,
            gas_used: 100,
            transactions_hash: [45u8; 32],
            receipts_hash: [56u8; 32],
            state_hash: [99u8; 32],
            logs_bloom: [11u8; 256]
        };

        // Verify the difference in data hash computation on same block header context
        assert_ne!(block_header_data_v1.data_hash(), block_header_data_v2.data_hash());
    }
}