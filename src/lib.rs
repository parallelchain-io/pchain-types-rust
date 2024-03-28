/*
    Copyright © 2023, ParallelChain Lab 
    Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
*/

//! Rust implementations of the data types defined in the
//! [ParallelChain Protocol](https://github.com/parallelchain-io/parallelchain-protocol), including
//! transactions, blocks, cryptographic primitives, and RPC requests and responses.

pub mod cryptography;

pub mod blockchain;

pub mod block_data;

pub mod rpc;

pub mod runtime;

pub mod serialization;
