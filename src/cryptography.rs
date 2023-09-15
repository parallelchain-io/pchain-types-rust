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


use sha2::{Sha256, Digest};
use rs_merkle::{MerkleTree, algorithms};

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

/// Compute contract address. It is the first version of contract address formula which is 
/// defined in ParallelChain Protocol V0.4.
pub fn contract_address_v1(signer: &PublicAddress, nonce: u64) -> PublicAddress {
    let mut hasher = Sha256::new();
    let mut pre_image = Vec::new();
    pre_image.extend(signer);
    pre_image.extend(nonce.to_le_bytes().to_vec());

    hasher.update(pre_image);

    hasher.finalize().into()
}

/// Compute contract address. It is the second version of contract address formula which is introduced 
/// in ParallelChain Protocol V0.5.
/// 
/// [V1](contract_address_v1) -> V2:
/// - Contract address is to be a function of the `index` of the deploy command
/// in a transaction submitted by the `signer` with nonce = `nonce`.
pub fn contract_address_v2(signer: &PublicAddress, nonce: u64, cmd_index: u32) -> PublicAddress {
    let mut hasher = Sha256::new();
    let mut pre_image = Vec::new();
    pre_image.extend(signer);
    pre_image.extend(nonce.to_le_bytes().to_vec());
    pre_image.extend(cmd_index.to_le_bytes().to_vec());

    hasher.update(pre_image);

    hasher.finalize().into()
}

/// A SHA256 hash over some message.
pub type Sha256Hash = [u8; 32];

/// Compute the SHA256 hash over some data.
pub fn sha256<T: AsRef<[u8]>>(data: T) -> Sha256Hash {
    let mut ret = Sha256::new();
    ret.update(data);
    ret.finalize().into()
}

/// Compute the Binary Merkle Tree root hash over a list of arbitrary data, e.g., [crate::blockchain::Transaction](transactions) or [crate::blockchain::Receipt](receipts).
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

    let merkle_tree = MerkleTree::<algorithms::Sha256>::from_leaves(&prehashed_leaves);
    merkle_tree.root().unwrap()
}

/// A 256-bit Bloom Filter.
pub type BloomFilter = [u8; 256];

#[cfg(test)]
mod test {
    use sha2::{Sha256, Digest};
    use crate::cryptography::{contract_address_v1, contract_address_v2};
    use super::{PublicAddress, merkle_root};

    #[test]
    fn compute_contract_address() {
        let public_key: PublicAddress = [79, 219, 143, 101, 101, 30, 7, 240, 226, 225, 53, 61, 92, 149, 233, 23, 2, 91, 251, 246, 191, 245, 83, 59, 53, 40, 126, 239, 84, 133, 130, 30];
        let nonce: u64 = 100;

        // Version 1
        let bytes = [79, 219, 143, 101, 101, 30, 7, 240, 226, 225, 53, 61, 92, 149, 233, 23, 2, 91, 251, 246, 191, 245, 83, 59, 53, 40, 126, 239, 84, 133, 130, 30, 100, 0, 0, 0, 0, 0, 0, 0];
        let addr_v1: PublicAddress = {
            let mut hasher = Sha256::new();
            hasher.update(bytes);
            hasher.finalize().into()
        };

        assert_eq!(addr_v1, contract_address_v1(&public_key, nonce));
        // check the result of same address with different nonce
        assert_ne!(contract_address_v1(&public_key, nonce), contract_address_v1(&public_key, nonce + 1));

        // Version 2
        let bytes = [79, 219, 143, 101, 101, 30, 7, 240, 226, 225, 53, 61, 92, 149, 233, 23, 2, 91, 251, 246, 191, 245, 83, 59, 53, 40, 126, 239, 84, 133, 130, 30, 100, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0];
        let addr_v2: PublicAddress = {
            let mut hasher = Sha256::new();
            hasher.update(bytes);
            hasher.finalize().into()
        };

        assert_eq!(addr_v2, contract_address_v2(&public_key, nonce, 1));
        // check the result of same address with different nonce
        assert_ne!(contract_address_v2(&public_key, nonce, 1), contract_address_v2(&public_key, nonce + 1, 1));
        // check the result of same address with different index
        assert_ne!(contract_address_v2(&public_key, nonce, 1), contract_address_v2(&public_key, nonce, 2));
    }

    #[test]
    fn compute_empty_data_merkle_root() {
        let elements: Vec<[u8;1]> = vec![];
        let root = merkle_root(elements);
        assert_eq!(root, [0;32]);
    }

    #[test]
    fn compute_non_empty_data_merkle_root() {
        let elements = [b"a", b"b", b"c", b"d", b"e", b"f"];
        let root = merkle_root(&elements);
        assert_eq!(
            rs_merkle::utils::collections::to_hex_string(&root),
            "1f7379539707bcaea00564168d1d4d626b09b73f8a2a365234c62d763f854da2".to_string()
        );
    }
}