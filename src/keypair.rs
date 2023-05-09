/*
    Copyright © 2023, ParallelChain Lab 
    Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
*/

//! Keypair Definition and its generation method as well as definition of private and public keys of an account on ParallelChain ecosystem.

use crate::{PublicAddress, SecretKey};

/// A Keypair is defined by a public key and a private key.
#[derive(Debug, Clone)]
pub struct Keypair {
    pub private_key: SecretKey,
    pub public_key: PublicAddress,
}

impl Keypair {
    #[cfg(feature = "keygen")]
    /// `generate` creates a new pchain_types::Keypair.
    pub fn generate() -> Keypair {
        use rand::rngs::OsRng;
        use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
        use std::convert::TryInto;
        
        const KEYPAIR_LENGTH: usize = 64;
        const PRIVATEKEY_LENGTH: usize = 32;

        let mut osrng = OsRng{};
        let mut chacha20_rng = ChaCha20Rng::from_rng(&mut osrng).unwrap();
        let keypair = ed25519_dalek::Keypair::generate(&mut chacha20_rng).to_bytes();
        let private_key: SecretKey = keypair[0..PRIVATEKEY_LENGTH].try_into().unwrap();
        let public_key: PublicAddress = keypair[PRIVATEKEY_LENGTH..KEYPAIR_LENGTH].try_into().unwrap();

        Keypair {
            public_key,
            private_key
        }
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Keypair {
        let keypair = ed25519_dalek::Keypair::from_bytes(&bytes).unwrap();
        Keypair {
            public_key: keypair.public.to_bytes(),
            private_key: keypair.secret.to_bytes()
        }
    }
}