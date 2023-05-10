/*
    Copyright © 2023, ParallelChain Lab 
    Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
*/

//! ParallelChain F Protocol Types (pchain-types) defines data structures prescribed by the ParallelChain F Blockchain Protocol. 
//! These definitions help Web Applications, clients, and differing implementations of 'Node' software developed by different groups 
//! communicate with each other and exhibit correct, protocol-specified semantics and behavior.
//! 
//! run `cargo doc --open` to view rich documentation on the available types.

pub mod serialization;

pub mod blockchain;

pub mod replication;

pub mod crypto;

pub mod rpc;

pub mod runtime;

// Re-exports
pub use serialization::*;
pub use blockchain::*;
pub use replication::*;
pub use crypto::*;
