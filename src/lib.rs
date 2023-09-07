/*
    Copyright © 2023, ParallelChain Lab 
    Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
*/

//! Rust implementations of the data types defined in the
//! [ParallelChain Protocol](https://github.com/parallelchain-io/parallelchain-protocol), including
//! transactions, blocks, cryptographic primitives, and RPC requests and responses.
//! 
//! ## Organization
//!
//! The organization of this library into modules mirror the organization of the protocol specification
//! into chapters. For example, transactions, which are specified in the "Blockchain" chapter of the
//! [specification](https://github.com/parallelchain-io/parallelchain-protocol/blob/master/Blockchain.md#transaction),
//! are defined in the blockchain module of this [library](blockchain::Transaction). The exception are the cryptographic
//! primitives specified in the Blockchain chapter, which are here defined in its own module.

pub mod cryptography;

pub mod blockchain;

pub mod data;

pub mod rpc;

pub mod runtime;

pub mod serialization;
