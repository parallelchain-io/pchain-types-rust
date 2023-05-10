/*
    Copyright © 2023, ParallelChain Lab 
    Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
*/

//! Cryptographic primitives like [keypairs](Keypair) and [SHA256](sha256) hashes.
//! 
//! ## Generating a Keypair 
//! 
//! ```
//! // OsRng and ChaCha are good defaults for pseudorandom number generation.
//! use rand::rngs::OsRng;
//! use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
//! 
//! let mut osrng = OsRng{};
//! let mut chacha20_rng = ChaCha20Rng::from_rng(&mut osrng).unwrap();
//! let keypair = Keypair::generate(&mut chacha20_rng);
//! ```


use rs_merkle::{MerkleTree, algorithms::Sha256};

/// An Ed25519 keypair.
pub type Keypair = ed25519_dalek::Keypair;

/// An Ed25519 secret key.
pub type SecretKey = ed25519_dalek::SecretKey;

/// An Ed25519 public key.
pub type PublicKey = ed25519_dalek::PublicKey;

/// An Ed25519 signature.
pub type Signature = ed25519_dalek::Signature;

/// 64 bytes that *should be* an Ed25519 signature. 
/// 
/// Can be acquired from [Signature] using [Signature::to_bytes], and converted into it using `try_from`.
pub type SignatureBytes = [u8; 64];

/// Implemented by [Keypair] and [SecretKey] to [Signer::sign] arbitrary bytesequences.
pub use ed25519_dalek::Signer;

/// Implemented by [Keypair] and [PublicKey] to cryptographically [Verifier::verify] arbitrary bytesequences.
pub use ed25519_dalek::Verifier;

/// Either:
/// - an Ed25519 public key representing an external account, or
/// - a contract address.
pub type PublicAddress = [u8; 32];

/// A SHA256 hash over some message.
pub type Sha256Hash = [u8; 32];

/// Compute the SHA256 hash over some data.
pub fn sha256<T: AsRef<[u8]>>(data: T) -> Sha256Hash {
    use sha2::{Sha256, Digest};
    let mut ret = Sha256::new();
    ret.update(data);
    ret.finalize().into()
}

// Compute the Binary Merkle Tree root hash over a list of arbitrary data, e.g., [crate::blockchain::Transaction](transactions) or [crate::blockchain::Receipt](receipts).
pub fn merkle_root<O: AsRef<[I]>, I: AsRef<[u8]>>(data: O) -> Sha256Hash {
    // null hash really isn't all 0s. There is no hash value for a tree without root. But here 
    // we use the 32-byte hash values to fill in the field definition inside data structures, for example, block header.
    if data.as_ref().is_empty() {
        return [0; 32]
    }

    let prehashed_leaves: Vec<[u8; 32]> = data
        .as_ref()
        .iter()
        .map(sha256)
        .collect();

    let merkle_tree = MerkleTree::<Sha256>::from_leaves(&prehashed_leaves);
    merkle_tree.root().unwrap()
}

/// A 256-bit Bloom Filter.
pub type BloomFilter = [u8; 256];
