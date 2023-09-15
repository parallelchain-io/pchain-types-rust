# ParallelChain Types (Rust)

Rust implementation of the data types defined in the [ParallelChain Protocol](https://github.com/parallelchain-io/parallelchain-protocol), including transactions, blocks, cryptographic primitives, and RPC requests and responses.

Read the docs at: [docs.rs](https://docs.rs/pchain-types/latest/pchain_types/)

## Modules

- [Cryptography](https://docs.rs/pchain-types/latest/pchain_types/cryptography): cryptographic primitives like keypairs and SHA256 hashes.
- [Blockchain](https://docs.rs/pchain-types/latest/pchain_types/blockchain): types which appear in blocks like transactions and receipts, and also blocks themselves.
- [Block Data](https://docs.rs/pchain-types/latest/pchain_types/block_data): types which define the use of Hotstuff Data to realize Block structure in Protocol.
- [Runtime](https://docs.rs/pchain-types/latest/pchain_types/runtime): inputs of transaction commands as structures.
- [RPC](https://docs.rs/pchain-types/latest/pchain_types/rpc): RPC requests and responses, and the additional types included in them.
- [Serialization](https://docs.rs/pchain-types/latest/pchain_types/serialization): traits for deterministic serialization of protocol-defined types. 

## Common use cases

- [Generating a keypair](https://docs.rs/pchain-types/latest/pchain_types/cryptography/index.html#generating-a-keypair).
- [Creating and signing a transaction](https://docs.rs/pchain-types/latest/pchain-types/blockchain/struct.TransactionV2.html#creating-a-transaction).
- [Creating RPC requests](https://docs.rs/pchain-types/latest/pchain_types/rpc).

## Versioning

The version of this library reflects the version of the ParallelChain Protocol which it implements. For example, the current version is 0.5.0, and this implements protocol version 0.5. Patch version increases are not guaranteed to be non-breaking.

## Opening an issue

Open an issue in GitHub if you:
1. Have a feature request / feature idea,
2. Have any questions (particularly software related questions),
3. Think you may have discovered a bug.

Please try to label your issues appropriately.
