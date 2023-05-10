/*
    Copyright © 2023, ParallelChain Lab 
    Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
*/

//! The data structure interfacing with consensus message types in [hotstuff_rs] for specific purpose,
//! for example, implementing the trait [Debug], [Serializable] and [Deserializable].

use std::ops::{Deref, DerefMut};
use borsh::{BorshSerialize, BorshDeserialize};
use hotstuff_rs::types::{ChainID, CryptoHash};
use crate::{Serializable, Deserializable};

pub type ViewNumber = hotstuff_rs::types::ViewNumber;

/// A vote received from peers in consensus network. It is a wrapper struct for [hotstuff_rs::messages::Vote].
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct Vote {
    inner: hotstuff_rs::messages::Vote
}

impl Vote {
    pub fn new(chain_id: ChainID, view: ViewNumber, block: CryptoHash, phase: hotstuff_rs::types::Phase, signature: hotstuff_rs::types::SignatureBytes) -> Self {
        Self {
            inner: hotstuff_rs::messages::Vote {
                chain_id,
                view,
                block,
                phase,
                signature,
            }
        }
    }
}

impl Deref for Vote {
    type Target = hotstuff_rs::messages::Vote;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for Vote {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl From<Vote> for hotstuff_rs::messages::Vote {
    fn from(vote: Vote) -> Self {
        vote.inner
    }
}

impl Eq for Vote {}
impl PartialEq for Vote {
    fn eq(&self, other: &Self) -> bool {
        self.chain_id.eq(&other.chain_id) &&
        self.view.eq(&other.view) &&
        self.block.eq(&other.block) &&
        self.phase.eq(&other.phase) &&
        self.signature.eq(&other.signature)
    }
}

impl std::fmt::Debug for Vote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Vote {{ chain_id: {:?}, view: {:?}, block: {:?}, phase: {:?}, signature: {:?} }}", 
            self.chain_id,
            self.view,
            self.block,
            self.phase,
            self.signature
        )
    }
}

impl Serializable for Vote {}
impl Deserializable for Vote {}
