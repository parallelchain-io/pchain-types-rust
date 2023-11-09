/*
    Copyright © 2023, ParallelChain Lab 
    Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
*/

//! Inputs of transaction commands as structures.

use crate::serialization::{Serializable, Deserializable};
use crate::cryptography::PublicAddress;

#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct TransferInput {
    /// Recipient of the transfer
    pub recipient: PublicAddress,

    /// The amount to transfer
    pub amount: u64
}

#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct DeployInput {
    /// Smart contract in format of WASM bytecode
    pub contract: Vec<u8>,

    /// Version of Contract Binary Interface
    pub cbi_version: u32
}

#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct CallInput {
    /// The address of the target contract
    pub target: PublicAddress,

    /// The method to be invoked
    pub method: String,

    /// The arguments supplied to the invoked method. It is a list of serialized method arguments (see [Serializable])
    pub arguments: Option<Vec<Vec<u8>>>,

    /// The amount sent to the target contract. The invoked contract can check the received amount 
    /// by host function `amount()` according to the CBI.
    pub amount: Option<u64>
}

#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct CreatePoolInput {
    /// Commission rate (in unit of percentage) is the portion that 
    /// the owners of its delegated stakes should pay from the reward in an epoch transaction.
    pub commission_rate: u8
}

#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SetPoolSettingsInput {
    /// Commission rate (in unit of percentage) is the portion that 
    /// the owners of its delegated stakes should pay from the reward in an epoch transaction.
    pub commission_rate: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct CreateDepositInput {
    /// The address of operator of the target pool
    pub operator: PublicAddress,

    /// The deposit amount
    pub balance: u64,

    /// Flag to indicate whether the received reward in epoch transaction should be automatically
    /// staked to the pool
    pub auto_stake_rewards: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SetDepositSettingsInput {
    /// The address of operator of the target pool
    pub operator: PublicAddress,

    /// Flag to indicate whether the received reward in epoch transaction should be automatically
    /// staked to the pool
    pub auto_stake_rewards: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct TopUpDepositInput {
    /// The address of operator of the target pool
    pub operator: PublicAddress,

    /// The amount added to Deposit's Balance
    pub amount: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct WithdrawDepositInput {
    /// The address of operator of the target pool
    pub operator: PublicAddress,

    /// The amount of deposits that the stake owner wants to withdraw. The prefix 'max'
    /// is denoted here because the actual withdrawal amount can be less than 
    /// the wanted amount.
    pub max_amount: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct StakeDepositInput {
    /// The address of operator of the target pool
    pub operator: PublicAddress,

    /// The amount of stakes that the stake owner wants to stake to the target pool. 
    /// The prefix 'max' is denoted here because the actual amount to be staked
    /// can be less than the wanted amount.
    pub max_amount: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct UnstakeDepositInput {
    /// The address of operator of the target pool
    pub operator: PublicAddress,

    /// The amount of stakes that the stake owner wants to remove from the target pool. 
    /// The prefix 'max' is denoted here because the actual amount to be removed
    /// can be less than the wanted amount.
    pub max_amount: u64,
}

crate::serialization::define_serde!(
    TransferInput, DeployInput, CallInput,
    CreatePoolInput, SetPoolSettingsInput, 
    CreateDepositInput, SetDepositSettingsInput,
    TopUpDepositInput, WithdrawDepositInput,
    StakeDepositInput, UnstakeDepositInput
);