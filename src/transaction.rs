/*
    Copyright © 2023, ParallelChain Lab 
    Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
*/

//! The data structures relevant to Transactions.

use std::ops::Deref;

use ed25519_dalek::{PublicKey, Signature, Signer, Verifier};
use crate::{crypto, Serializable, Deserializable, CryptographicallyIncorrectTransactionError, AsKeyPair, PublicAddress, ExitStatus};

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

/// Command is the Transaction Kind that define how state mahcine transits.
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub enum Command {
    /// Transfer Balance from transaction signer to recipient.
    Transfer {
        /// Recipient of the transfer
        recipient: PublicAddress,
        /// The amount to transfer
        amount: u64
    },
    /// Deploy smart contract to the state of the blockchain.
    Deploy{
        /// Smart contract in format of WASM bytecode
        contract: Vec<u8>,
        /// Version of Contract Binary Interface
        cbi_version: u32
    },
    /// Trigger method call of a deployed smart contract.
    Call{
        /// The address of the target contract
        target: PublicAddress,
        /// The method to be invoked
        method: String,
        /// The arguments supplied to the invoked method. It is a list of serialized method arguments (see [Serializable])
        arguments: Option<Vec<Vec<u8>>>,
        /// The amount sent to the target contract. The invoked contract can check the received amount 
        /// by host function `amount()` according to the CBI.
        amount: Option<u64>
    },
    /// Instantiation of a Pool in state
    CreatePool {
        /// Commission rate (in unit of percentage) is the portion that 
        /// the owners of its delegated stakes should pay from the reward in an epoch transaction.
        commission_rate: u8
    },
    /// Update settings of an existing Pool.
    SetPoolSettings {
        /// Commission rate (in unit of percentage) is the portion that 
        /// the owners of its delegated stakes should pay from the reward in an epoch transaction.
        commission_rate: u8,
    },
    /// Delete an existing Pool in state.
    DeletePool,
    /// Instantiation of a Pool in state
    CreateDeposit {
        /// The address of operator of the target pool
        operator: PublicAddress,
        /// The deposit amount
        balance: u64,
        /// Flag to indicate whether the received reward in epoch transaction should be automatically
        /// staked to the pool
        auto_stake_rewards: bool,
    },
    /// Update settings of an existing Deposit.
    SetDepositSettings {
        /// The address of operator of the target pool
        operator: PublicAddress,
        /// Flag to indicate whether the received reward in epoch transaction should be automatically
        /// staked to the pool
        auto_stake_rewards: bool,
    },
    /// Increase balance of an existing Deposit.
    TopUpDeposit {
        /// The address of operator of the target pool
        operator: PublicAddress,
        /// The amount added to Deposit's Balance
        amount: u64,
    },
    /// Withdraw balance from an existing Deposit.
    WithdrawDeposit {
        /// The address of operator of the target pool
        operator: PublicAddress,
        /// The amount of deposits that the stake owner wants to withdraw. The prefix 'max'
        /// is denoted here because the actual withdrawal amount can be less than 
        /// the wanted amount.
        max_amount: u64,
    },
    /// Increase stakes to an existing Pool
    StakeDeposit {
        /// The address of operator of the target pool
        operator: PublicAddress,
        /// The amount of stakes that the stake owner wants to stake to the target pool. 
        /// The prefix 'max' is denoted here because the actual amount to be staked
        /// can be less than the wanted amount.
        max_amount: u64,
    },
    /// Remove stakes from an existing Pool.
    UnstakeDeposit {
        /// The address of operator of the target pool
        operator: PublicAddress,
        /// The amount of stakes that the stake owner wants to remove from the target pool. 
        /// The prefix 'max' is denoted here because the actual amount to be removed
        /// can be less than the wanted amount.
        max_amount: u64,
    },
    /// Administration Command: proceed to next epoch.
    NextEpoch,
}

impl Serializable for Command {}
impl Deserializable for Command {}

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