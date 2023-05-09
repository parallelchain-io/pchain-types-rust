/*
    Copyright © 2023, ParallelChain Lab 
    Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
*/

//! Defines [ExitStatus], an enum included in every Transaction Receipt that provides
//! a succinct way to describe what happened during the execution of the transaction command. 

use crate::{Serializable, Deserializable};
use std::convert::TryFrom;

/// ExitStatus defines the success and error types of receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitStatus {

    /// The Transaction successfully accomplished everything that it could have been expected to do.
    Success,

    /// The Transaction failed to accomplish the primary operation that Transactions of its kinds are expected to accomplish.
    Failed,

    /// The Gas Limit was exceeded by a dynamically costed activity in a dynamic-cost Transaction.
    GasExhausted,
}

impl borsh::BorshSerialize for ExitStatus {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let c: u8 = self.clone().into();
        c.serialize(writer)
    }
}

impl borsh::BorshDeserialize for ExitStatus {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let b = u8::deserialize_reader(reader)?;
        match Self::try_from(b) {
            Ok(sc) => Ok(sc),
            Err(_) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Cannot convert from ExitStatus"))
        }
    }
}

impl From<ExitStatus> for u8 {
    fn from(exit_status: ExitStatus) -> Self {
        exit_status as u8
    }
}

impl TryFrom<u8> for ExitStatus {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            x if x == ExitStatus::Success as u8 => Ok(ExitStatus::Success),
            x if x == ExitStatus::Failed as u8 => Ok(ExitStatus::Failed),
            x if x == ExitStatus::GasExhausted as u8 => Ok(ExitStatus::GasExhausted),
            _ => Err(()),
        }
    }
}

impl Serializable for ExitStatus {}
impl Deserializable for ExitStatus {}