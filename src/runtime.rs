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
    recipient: PublicAddress,

    /// The amount to transfer
    amount: u64
}

impl Serializable for TransferInput {}
impl Deserializable for TransferInput {}

#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct DeployInput {
    /// Smart contract in format of WASM bytecode
    contract: Vec<u8>,

    /// Version of Contract Binary Interface
    cbi_version: u32
}

impl Serializable for DeployInput {}
impl Deserializable for DeployInput {}

#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct CallInput {
    /// The address of the target contract
    target: PublicAddress,

    /// The method to be invoked
    method: String,

    /// The arguments supplied to the invoked method. It is a list of serialized method arguments (see [Serializable])
    arguments: Option<Vec<Vec<u8>>>,

    /// The amount sent to the target contract. The invoked contract can check the received amount 
    /// by host function `amount()` according to the CBI.
    amount: Option<u64>
}

impl Serializable for CallInput {}
impl Deserializable for CallInput {}

#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct CreatePoolInput {
    /// Commission rate (in unit of percentage) is the portion that 
    /// the owners of its delegated stakes should pay from the reward in an epoch transaction.
    commission_rate: u8
}

impl Serializable for CreatePoolInput {}
impl Deserializable for CreatePoolInput {}

#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SetPoolSettingsInput {
    /// Commission rate (in unit of percentage) is the portion that 
    /// the owners of its delegated stakes should pay from the reward in an epoch transaction.
    commission_rate: u8,
}

impl Serializable for SetPoolSettingsInput {}
impl Deserializable for SetPoolSettingsInput {}

#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct CreateDepositInput {
    /// The address of operator of the target pool
    operator: PublicAddress,

    /// The deposit amount
    balance: u64,

    /// Flag to indicate whether the received reward in epoch transaction should be automatically
    /// staked to the pool
    auto_stake_rewards: bool,
}

impl Serializable for CreateDepositInput {}
impl Deserializable for CreateDepositInput {} 

#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SetDepositSettingsInput {
    /// The address of operator of the target pool
    operator: PublicAddress,

    /// Flag to indicate whether the received reward in epoch transaction should be automatically
    /// staked to the pool
    auto_stake_rewards: bool,
}

impl Serializable for SetDepositSettingsInput {}
impl Deserializable for SetDepositSettingsInput {}

#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct TopUpDepositInput {
    /// The address of operator of the target pool
    operator: PublicAddress,

    /// The amount added to Deposit's Balance
    amount: u64,
}

impl Serializable for TopUpDepositInput {}
impl Deserializable for TopUpDepositInput {}

#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct WithdrawDepositInput {
    /// The address of operator of the target pool
    operator: PublicAddress,

    /// The amount of deposits that the stake owner wants to withdraw. The prefix 'max'
    /// is denoted here because the actual withdrawal amount can be less than 
    /// the wanted amount.
    max_amount: u64,
}

impl Serializable for WithdrawDepositInput {}
impl Deserializable for WithdrawDepositInput {}

#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct StakeDepositInput {
    /// The address of operator of the target pool
    operator: PublicAddress,

    /// The amount of stakes that the stake owner wants to stake to the target pool. 
    /// The prefix 'max' is denoted here because the actual amount to be staked
    /// can be less than the wanted amount.
    max_amount: u64,
}

impl Serializable for StakeDepositInput {}
impl Deserializable for StakeDepositInput {}

#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct UnstakeDepositInput {
    /// The address of operator of the target pool
    operator: PublicAddress,

    /// The amount of stakes that the stake owner wants to remove from the target pool. 
    /// The prefix 'max' is denoted here because the actual amount to be removed
    /// can be less than the wanted amount.
    max_amount: u64,
}

impl Serializable for UnstakeDepositInput {}
impl Deserializable for UnstakeDepositInput {}
