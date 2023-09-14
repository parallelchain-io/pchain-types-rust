/*
    Copyright © 2023, ParallelChain Lab 
    Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
*/

//! Defines the data utilization of [hotstuff_rs::types::Data] (i.e. HotstuffData, a vector of vector of bytes) to serve the application. 
//! The module also provides a struct called BlockData as a data abstraction of [hotstuff_rs::types::Block].data.
//! 
//! HotstuffData is a vector of vector of bytes. Each slot contains data in bytes (`Vec<u8>`). Block data is allocated into slots as below:
//! 
//! \[ BlockHeader Field 1, BlockHeader Field 2, ... , BlockHeader Field N, Tx 1, Tx 2, ... , Tx M, Receipt 1, Receipt 2, ... , Receipt M \]
//! 
//! where N is the number of fields in BlockHeader, M is the number of transactions (as well as receipts).

use std::convert::{TryFrom, TryInto};

use borsh::{BorshSerialize, BorshDeserialize};
use hotstuff_rs::types::Data;

use crate::{cryptography::{PublicAddress, Sha256Hash, BloomFilter, sha256}, serialization::{Serializable, Deserializable}, blockchain::{TransactionV2, ReceiptV2}};

/// Indexes definitions for [hotstuff_rs::types::Block] interoperability.
pub enum DatumIndexV2 {
    ChainID = 0,
    Proposer,
    Timestamp,
    BaseFeePerGas,
    GasUsed,
    TransactionsHash,
    ReceiptsHash,
    StateHash,
    LogBloom,
    /// Number of Datum for block header
    BlockHeaderSize,
    // The following data are indexed dynamically:
    // - Transactions
    // - Receipts
    // For instance, the first transaction is indexed at [BlockHeaderSize]. The second transaction is indexed at 
    // [BlockHeaderSize + 1]. The sequent transactions are indexed orderly until the end, and then follow by
    // the first receipt.
}


/// Create getter and setter functions on DatumIndex.
/// 
/// Example: (Enum, getter function name, setter function name)
/// 
/// The getter and setter functions are used to enforce the input data slice to be typed
/// as [hotstuff_rs::types::Data]. It is not good to directly index on an arbitrary vector of
/// bytes by the Enum directly in other code place.
macro_rules! datum_index_getter_setter {
    ($t:tt, $g:ident, $s:ident) => {
        /// Get the value from a slot at the corresponding datum index
        pub fn $g (hotstuff_data: &Data) -> &[u8] {
            hotstuff_data[DatumIndexV2::$t as usize].as_slice()
        }

        /// Set the value into a slot at the corresponding datum index
        pub fn $s (hotstuff_data: &mut Data, value: Vec<u8>) {
            hotstuff_data[DatumIndexV2::$t as usize] = value;
        }
    };
}

impl DatumIndexV2 {
    
    datum_index_getter_setter!(ChainID, chain_id, set_chain_id);
    datum_index_getter_setter!(Proposer, proposer, set_proposer);
    datum_index_getter_setter!(Timestamp, timestamp, set_timestamp);
    datum_index_getter_setter!(BaseFeePerGas, base_fee_per_gas, set_base_fee_per_gas);
    datum_index_getter_setter!(GasUsed, gas_used, set_gas_used);
    datum_index_getter_setter!(TransactionsHash, transactions_hash, set_transactions_hash);
    datum_index_getter_setter!(ReceiptsHash, receipts_hash, set_receipts_hash);
    datum_index_getter_setter!(StateHash, state_hash, set_state_hash);
    datum_index_getter_setter!(LogBloom, log_bloom, set_log_bloom);

    /// Start index of the datum transaction
    pub const fn transactions_start_index() -> usize {
        DatumIndexV2::BlockHeaderSize as usize
    }

    /// Start index of the datum receipt. It depends on the length of the transactions
    /// in the data.
    pub const fn receipts_start_index(txn_len: usize) -> usize {
        DatumIndexV2::BlockHeaderSize as usize + txn_len
    }

    /// Returns the slice of the datum which is the serialized transaction and receipt.
    #[allow(clippy::type_complexity)]
    pub fn transactions_and_receipts(hotstuff_data: &Data) -> Option<(&[Vec<u8>], &[Vec<u8>])> {
        let data = &hotstuff_data[Self::transactions_start_index()..];
        let num_remaining_slots = data.len();
        if num_remaining_slots % 2 != 0 {
            return None;
        }
        Some((&data[..num_remaining_slots/2], &data[num_remaining_slots/2..]))
    }
}


/// A data structure that can be converted from [hotstuff_rs::types::Data].
pub struct BlockDataV2 {
    pub header: BlockHeaderDataV2,
    pub transactions: Vec<TransactionV2>,
    pub receipts: Vec<ReceiptV2>,
}

impl BlockDataV2 {

    /// Conversion from [hotstuff_rs::types::Data] with an option to validate the transactions.
    pub fn from_data(
        hotstuff_data: &Data,
        verify_transaction_signatures: bool
    ) -> Result<BlockDataV2, BlockConversionError> {
        // Construct BlockDataheader from fixed datum indexes 
        let header: BlockHeaderDataV2 = BlockHeaderDataV2::try_from(hotstuff_data)
            .map_err(BlockConversionError::WrongHeader)?;
        
        // Construct Transactions and Receipts from dynamic datum indexes
        let (txns_bs, receipts_bs) = DatumIndexV2::transactions_and_receipts(hotstuff_data)
            .ok_or(BlockConversionError::IncorrectNumberOfTxsAndReceipts)?;

        // Deserialize transactions (and validate the signatures)
        let mut transactions = Vec::with_capacity(txns_bs.len());
        for txn_bs in txns_bs {
            let txn: TransactionV2 = Deserializable::deserialize(txn_bs)
                .map_err(|_| BlockConversionError::Transaction)?;
            // Check transactions signature and return error immediately if there is an invalid transaction.
            if verify_transaction_signatures {
                txn.is_cryptographically_correct()
                    .map_err(|_| BlockConversionError::InvalidTransactionSignature)?;
            }
            transactions.push(txn);
        }

        // Deserialize receipts
        let mut receipts: Vec<ReceiptV2> = Vec::with_capacity(receipts_bs.len());
        for receipt_bs in receipts_bs {
            receipts.push(
                Deserializable::deserialize(receipt_bs)
                    .map_err(|_| BlockConversionError::Receipt)?,
            )
        }

        Ok(BlockDataV2{
            header,
            transactions,
            receipts,
        })
    }
}

impl From<BlockDataV2> for Data {
    fn from(value: BlockDataV2) -> Data {
        let header = Data::from(value.header);

        let transactions: Data = value
            .transactions
            .into_iter()
            .map(|tx| Serializable::serialize(&tx))
            .collect();

        let receipts: Data = value
            .receipts
            .into_iter()
            .map(|recp| Serializable::serialize(&recp))
            .collect();

        [header, transactions, receipts].concat()
    }
}

impl<'a> TryFrom<&'a Data> for BlockDataV2 {
    type Error = BlockConversionError;
    fn try_from(data: &'a Data) -> std::result::Result<Self, Self::Error> {
        BlockDataV2::from_data(data, true)
    }
}


/// A data structure that encapsulates the data of block header from [hotstuff_rs::types::Data].
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct BlockHeaderDataV2 {
    pub chain_id: hotstuff_rs::types::ChainID,
    pub proposer: PublicAddress,
    pub timestamp: u32,
    pub base_fee_per_gas: u64,
    pub gas_used: u64,
    pub transactions_hash: Sha256Hash,
    pub receipts_hash: Sha256Hash,
    pub state_hash: Sha256Hash,
    pub log_bloom: BloomFilter,
}
impl Serializable for BlockHeaderDataV2 { }

impl BlockHeaderDataV2 {
    pub fn hash(&self) -> hotstuff_rs::types::CryptoHash {
        sha256(self.try_to_vec().unwrap())
    }
}

impl TryFrom<&Data> for BlockHeaderDataV2 {
    type Error = BlockHeaderConversionError;

    fn try_from(data_slice: &Data) -> Result<Self, Self::Error> {
        // Check if there is the correct number of slots.
        if data_slice.len() < DatumIndexV2::BlockHeaderSize as usize {
            return Err(BlockHeaderConversionError::NumberOfSlots);
        }

        // Check if each slot is of the correct length.
        let chain_id = u64::from_le_bytes(
            DatumIndexV2::chain_id(data_slice)
                .try_into()
                .map_err(|_| BlockHeaderConversionError::ChainID)?,
        );
        let proposer = DatumIndexV2::proposer(data_slice)
            .try_into()
            .map_err(|_| BlockHeaderConversionError::Proposer)?;
        let timestamp = u32::from_le_bytes(
            DatumIndexV2::timestamp(data_slice)
                .try_into()
                .map_err(|_| BlockHeaderConversionError::Timestamp)?,
        );
        let transactions_hash = DatumIndexV2::transactions_hash(data_slice)
            .try_into()
            .map_err(|_| BlockHeaderConversionError::TxsHash)?;
        let state_hash = DatumIndexV2::state_hash(data_slice)
            .try_into()
            .map_err(|_| BlockHeaderConversionError::StateHash)?;
        let receipts_hash = DatumIndexV2::receipts_hash(data_slice)
            .try_into()
            .map_err(|_| BlockHeaderConversionError::ReceiptsHash)?;
        let base_fee_per_gas = u64::from_le_bytes(
            DatumIndexV2::base_fee_per_gas(data_slice)
                .try_into()
                .map_err(|_| BlockHeaderConversionError::BaseFee)?,
        );
        let gas_used = u64::from_le_bytes(
            DatumIndexV2::gas_used(data_slice)
                .try_into()
                .map_err(|_| BlockHeaderConversionError::GasUsed)?,
        );
        let log_bloom = DatumIndexV2::log_bloom(data_slice)
            .try_into()
            .map_err(|_| BlockHeaderConversionError::LogBloom)?;


        Ok(BlockHeaderDataV2 {
            chain_id,
            proposer,
            timestamp,
            transactions_hash,
            state_hash,
            receipts_hash,
            base_fee_per_gas,
            gas_used,
            log_bloom,
        })
    }
}

/// Enumerates errors in conversion from HotStuffData to BlockDataHeader.
#[derive(Debug)]
pub enum BlockHeaderConversionError {
    /// Wrong number of slice of bytes
    NumberOfSlots,
    /// Fail to convert bytes into Chain ID
    ChainID,
    /// Fail to convert bytes into Proposer
    Proposer,
    /// Fail to convert bytes into Timestamp
    Timestamp,
    /// Fail to convert bytes into Transactions Hash
    TxsHash,
    /// Fail to convert bytes into State Hash
    StateHash,
    /// Fail to convert bytes into Receipt Hash
    ReceiptsHash,
    /// Fail to convert bytes into Base Fee
    BaseFee,
    /// Fail to convert bytes into Gas Used
    GasUsed,
    /// Fail to convert bytes into Log Bloom
    LogBloom,
}

impl From<BlockHeaderDataV2> for Data {
    fn from(value: BlockHeaderDataV2) -> Data {
        let mut buf = vec![Vec::new(); DatumIndexV2::BlockHeaderSize as usize];
        DatumIndexV2::set_chain_id(&mut buf, value.chain_id.to_le_bytes().to_vec());
        DatumIndexV2::set_proposer(&mut buf, value.proposer.to_vec());
        DatumIndexV2::set_timestamp(&mut buf, value.timestamp.to_le_bytes().to_vec());
        DatumIndexV2::set_transactions_hash(&mut buf, value.transactions_hash.to_vec());
        DatumIndexV2::set_state_hash(&mut buf, value.state_hash.to_vec());
        DatumIndexV2::set_receipts_hash(&mut buf, value.receipts_hash.to_vec());
        DatumIndexV2::set_base_fee_per_gas(&mut buf, value.base_fee_per_gas.to_le_bytes().to_vec());
        DatumIndexV2::set_gas_used(&mut buf, value.gas_used.to_le_bytes().to_vec());
        DatumIndexV2::set_log_bloom(&mut buf, value.log_bloom.to_vec());
        buf
    }

}


/// Enumerates errors in conversion from HotStuffData to BlockData.
#[derive(Debug)]
pub enum BlockConversionError {
    /// Fail to convert Block Header.
    WrongHeader(BlockHeaderConversionError),
    /// Wrong number of slice of bytes. It should contain equal number of transactions
    /// and receipts.
    IncorrectNumberOfTxsAndReceipts,
    /// Fail to deserialize a transaction.
    Transaction,
    /// Signature of a transaction is invalid.
    InvalidTransactionSignature,
    /// Fail to deserialize a receipt.
    Receipt,
}
