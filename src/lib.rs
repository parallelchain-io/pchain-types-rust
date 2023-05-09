/*
    Copyright © 2023, ParallelChain Lab 
    Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
*/

//! ParallelChain F Protocol Types (pchain-types) defines data structures prescribed by the ParallelChain F Blockchain Protocol. 
//! These definitions help Web Applications, clients, and differing implementations of 'Node' software developed by different groups 
//! communicate with each other and exhibit correct, protocol-specified semantics and behavior.
//! 
//! run `cargo doc --open` to view rich documentation on the available types.

pub mod base64url;

pub mod blanket_impls;

pub mod block;

pub mod consensus;

pub mod constants;

pub mod crypto;

pub mod exit_status;

pub mod keypair;

pub mod rpc;

pub mod stake;

pub mod transaction; 

// Re-exports
pub use base64url::*;
pub use blanket_impls::*;
pub use block::*;
pub use consensus::*;
pub use constants::*;
pub use crypto::*;
pub use exit_status::*;
pub use keypair::*;
pub use stake::*;
pub use transaction::*;


/// Serializable encapsulates implementation of serialization on data structures that are defined in pchain-types.
pub trait Serializable: borsh::BorshSerialize {
    fn serialize(&self) -> Vec<u8> {
        self.try_to_vec().unwrap()
    }
}

/// Deserializable encapsulates implementation of deserialization on data structures that are defined in pchain-types.
pub trait Deserializable: borsh::BorshDeserialize {
    fn deserialize(args: &[u8]) -> Result<Self, std::io::Error> {
        Self::try_from_slice(args)
    }
}
