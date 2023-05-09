/*
    Copyright © 2023, ParallelChain Lab 
    Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
*/

//! The data structures relevant to staking operations.

use crate::{PublicAddress, Serializable, Deserializable};

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

