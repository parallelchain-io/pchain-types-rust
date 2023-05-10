/*
    Copyright © 2023, ParallelChain Lab 
    Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
*/

//! ParallelChain F Protocol Types (pchain-types) defines data structures prescribed by the ParallelChain F Blockchain Protocol. 
//! These definitions help Web Applications, clients, and differing implementations of 'Node' software developed by different groups 
//! communicate with each other and exhibit correct, protocol-specified semantics and behavior.
//! 
//! run `cargo doc --open` to view rich documentation on the available types.

pub mod cryptography;

pub mod blockchain;

pub mod rpc;

pub mod runtime;

pub mod serialization;
