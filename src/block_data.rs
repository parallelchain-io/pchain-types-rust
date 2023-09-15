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

use hotstuff_rs::types::Data;

use crate::{cryptography::{PublicAddress, Sha256Hash, BloomFilter, sha256}, serialization::{Serializable, Deserializable}, blockchain::{TransactionV2, ReceiptV2, TransactionV1, ReceiptV1}};

/// Indexes definitions for [hotstuff_rs::types::Block] interoperability.
pub enum DatumIndexV1 {
    ChainID = 0,
    Proposer,
    Timestamp,
    TransactionsHash,
    StateHash,
    ReceiptsHash,
    BaseFeePerGas,
    GasUsed,
    LogsBloom,
    /// Number of Datum for block header
    BlockHeaderSize,
    // The following data are indexed dynamically:
    // - Transactions
    // - Receipts
    // For instance, the first transaction is indexed at [BlockHeaderSize]. The second transaction is indexed at 
    // [BlockHeaderSize + 1]. The sequent transactions are indexed orderly until the end, and then follow by
    // the first receipt.
}

/// Indexes definitions for [hotstuff_rs::types::Block] interoperability.
/// 
/// [V1](DatumIndexV1) -> V2:
/// - The order of fields is changed to match the order of fields in protocol blocks.
/// - Data Hash pre-image is also changed to match the new order of fields.
pub enum DatumIndexV2 {
    ChainID = 0,
    Proposer,
    Timestamp,
    BaseFeePerGas,
    GasUsed,
    TransactionsHash,
    ReceiptsHash,
    StateHash,
    LogsBloom,
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
/// Arguments: (Enum, getter function name, setter function name)
/// 
/// The getter and setter functions are used to enforce the input data slice to be typed
/// as [hotstuff_rs::types::Data]. It is not good to directly index on an arbitrary vector of
/// bytes by the Enum directly in other code place.
macro_rules! datum_index_getter_setter {
    ($enum_name:tt, $getter_fn_name:ident, $setter_fn_name:ident) => {
        /// Get the value from a slot at the corresponding datum index
        pub fn $getter_fn_name (hotstuff_data: &Data) -> &[u8] {
            hotstuff_data[Self::$enum_name as usize].as_slice()
        }

        /// Set the value into a slot at the corresponding datum index
        pub fn $setter_fn_name (hotstuff_data: &mut Data, value: Vec<u8>) {
            hotstuff_data[Self::$enum_name as usize] = value;
        }
    };
}

/// Create `Impl` for DatumIndex exclusively from Version 1 to Version 2. The `impl` defines
/// same set of functions across versions.
/// 
/// Arguments: (the DatumIndex enum type)
macro_rules! datum_index_impl_v1_to_v2 {
    ($datum_index:tt) => {
        impl $datum_index {
            datum_index_getter_setter!(ChainID, chain_id, set_chain_id);
            datum_index_getter_setter!(Proposer, proposer, set_proposer);
            datum_index_getter_setter!(Timestamp, timestamp, set_timestamp);
            datum_index_getter_setter!(BaseFeePerGas, base_fee_per_gas, set_base_fee_per_gas);
            datum_index_getter_setter!(GasUsed, gas_used, set_gas_used);
            datum_index_getter_setter!(TransactionsHash, transactions_hash, set_transactions_hash);
            datum_index_getter_setter!(ReceiptsHash, receipts_hash, set_receipts_hash);
            datum_index_getter_setter!(StateHash, state_hash, set_state_hash);
            datum_index_getter_setter!(LogsBloom, logs_bloom, set_logs_bloom);
            
            /// Start index of the datum transaction
            pub const fn transactions_start_index() -> usize {
                Self::BlockHeaderSize as usize
            }

            /// Start index of the datum receipt. It depends on the length of the transactions
            /// in the data.
            pub const fn receipts_start_index(num_txns: usize) -> usize {
                Self::BlockHeaderSize as usize + num_txns
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
    };
}

datum_index_impl_v1_to_v2!(DatumIndexV1);
datum_index_impl_v1_to_v2!(DatumIndexV2);

/// A data structure that can be converted from [hotstuff_rs::types::Data].
pub struct BlockDataV1 {
    pub header: BlockHeaderDataV1,
    pub transactions: Vec<TransactionV1>,
    pub receipts: Vec<ReceiptV1>,
}

/// A data structure that can be converted from [hotstuff_rs::types::Data].
/// 
/// [V1](BlockDataV1) -> V2:
/// - "Header" is now of type BlockHeaderDataV2.
/// - "Transactions" is now of type TransactionV2.
/// - "Receipts" is now of type ReceiptV2.
pub struct BlockDataV2 {
    pub header: BlockHeaderDataV2,
    pub transactions: Vec<TransactionV2>,
    pub receipts: Vec<ReceiptV2>,
}

/// Create `Impl`s for BlockData exclusively from Version 1 to Version 2. The `impl`s define
/// same set of functions across versions.
/// 
/// Arguments: (Block Data struct, Block Header Data struct, DatumIndex enum, Transaction struct, Receipt struct)
macro_rules! block_data_impls_v1_to_v2 {
    ($block_data:tt, $block_header_data:tt, $datum_index:tt, $transaction:tt, $receipt:tt) => {
        impl $block_data {

            /// Conversion from [hotstuff_rs::types::Data] with an option to validate the transactions.
            pub fn from_data(
                hotstuff_data: &Data,
                verify_transaction_signatures: bool
            ) -> Result<$block_data, BlockDataFromHotStuffDataError> {
                // Construct BlockHeaderData from fixed datum indexes 
                let header = $block_header_data::try_from(hotstuff_data)
                    .map_err(BlockDataFromHotStuffDataError::WrongHeader)?;
                
                // Construct Transactions and Receipts from dynamic datum indexes
                let (txns_bs, receipts_bs) = $datum_index::transactions_and_receipts(hotstuff_data)
                    .ok_or(BlockDataFromHotStuffDataError::IncorrectNumberOfTxnsAndReceipts)?;
        
                // Deserialize transactions (and validate the signatures)
                let mut transactions = Vec::with_capacity(txns_bs.len());
                for txn_bs in txns_bs {
                    let txn: $transaction = Deserializable::deserialize(txn_bs)
                        .map_err(|_| BlockDataFromHotStuffDataError::Transaction)?;
                    // Check transactions signature and return error immediately if there is an invalid transaction.
                    if verify_transaction_signatures {
                        txn.is_cryptographically_correct()
                            .map_err(|_| BlockDataFromHotStuffDataError::InvalidTransactionSignature)?;
                    }
                    transactions.push(txn);
                }
        
                // Deserialize receipts
                let mut receipts: Vec<$receipt> = Vec::with_capacity(receipts_bs.len());
                for receipt_bs in receipts_bs {
                    receipts.push(
                        Deserializable::deserialize(receipt_bs)
                            .map_err(|_| BlockDataFromHotStuffDataError::Receipt)?,
                    )
                }
        
                Ok($block_data{
                    header,
                    transactions,
                    receipts,
                })
            }
        }

        impl From<$block_data> for Data {
            fn from(value: $block_data) -> Data {
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

        impl<'a> TryFrom<&'a Data> for $block_data {
            type Error = BlockDataFromHotStuffDataError;
            fn try_from(data: &'a Data) -> std::result::Result<Self, Self::Error> {
                $block_data::from_data(data, true)
            }
        }
    };
}

block_data_impls_v1_to_v2!(BlockDataV1, BlockHeaderDataV1, DatumIndexV1, TransactionV1, ReceiptV1);
block_data_impls_v1_to_v2!(BlockDataV2, BlockHeaderDataV2, DatumIndexV2, TransactionV2, ReceiptV2);

/// A data structure that encapsulates the data of block header from [hotstuff_rs::types::Data].
pub struct BlockHeaderDataV1 {
    pub chain_id: hotstuff_rs::types::ChainID,
    pub proposer: PublicAddress,
    pub timestamp: u32,
    pub transactions_hash: Sha256Hash,
    pub state_hash: Sha256Hash,
    pub receipts_hash: Sha256Hash,
    pub base_fee_per_gas: u64,
    pub gas_used: u64,
    pub logs_bloom: BloomFilter,
}

impl BlockHeaderDataV1 {
    /// Hash over all the fields in BlockHeaderData. It is used as a field in [hotstuff_rs::app::ProduceBlockResponse].
    pub fn data_hash(&self) -> hotstuff_rs::types::CryptoHash {
        let pre_image = [
            Serializable::serialize(&self.chain_id),
            Serializable::serialize(&self.proposer),
            Serializable::serialize(&self.timestamp),
            Serializable::serialize(&self.transactions_hash),
            Serializable::serialize(&self.state_hash),
            Serializable::serialize(&self.receipts_hash),
            Serializable::serialize(&self.base_fee_per_gas),
            Serializable::serialize(&self.gas_used),
            Serializable::serialize(&self.logs_bloom),
        ]
        .concat();
        sha256(pre_image)
    }
}

/// A data structure that encapsulates the data of block header from [hotstuff_rs::types::Data].
/// 
/// [V1](BlockHeaderDataV1) -> V2:
/// - The order of fields is changed to match the order of fields in protocol blocks.
/// - Data Hash pre-image is also changed to match the new order of fields.
pub struct BlockHeaderDataV2 {
    pub chain_id: hotstuff_rs::types::ChainID,
    pub proposer: PublicAddress,
    pub timestamp: u32,
    pub base_fee_per_gas: u64,
    pub gas_used: u64,
    pub transactions_hash: Sha256Hash,
    pub receipts_hash: Sha256Hash,
    pub state_hash: Sha256Hash,
    pub logs_bloom: BloomFilter,
}

impl BlockHeaderDataV2 {
    /// Hash over all the fields in BlockHeaderData. It is used as a field in [hotstuff_rs::app::ProduceBlockResponse].
    pub fn data_hash(&self) -> hotstuff_rs::types::CryptoHash {
        let pre_image = [
            Serializable::serialize(&self.chain_id),
            Serializable::serialize(&self.proposer),
            Serializable::serialize(&self.timestamp),
            Serializable::serialize(&self.base_fee_per_gas),
            Serializable::serialize(&self.gas_used),
            Serializable::serialize(&self.transactions_hash),
            Serializable::serialize(&self.receipts_hash),
            Serializable::serialize(&self.state_hash),
            Serializable::serialize(&self.logs_bloom),
        ]
        .concat();
        sha256(pre_image)
    }
}

/// Create `Impl`s for BlockHeaderData exclusively from Version 1 to Version 2. The `impl`s define
/// same set of functions across versions.
/// 
/// Arguments: (BlockHeaderData struct, DatumIndex enum)
macro_rules! block_header_data_v1_to_v2 {
    ($block_header_data:tt, $datum_index:tt) => {

        impl TryFrom<&Data> for $block_header_data {
            type Error = BlockHeaderDataFromHotStuffDataError;
        
            fn try_from(data_slice: &Data) -> Result<Self, Self::Error> {
                // Check if there is the correct number of slots.
                if data_slice.len() < $datum_index::BlockHeaderSize as usize {
                    return Err(BlockHeaderDataFromHotStuffDataError::NumberOfSlots);
                }
        
                // Check if each slot is of the correct length.
                let chain_id = u64::from_le_bytes(
                    $datum_index::chain_id(data_slice)
                        .try_into()
                        .map_err(|_| BlockHeaderDataFromHotStuffDataError::ChainID)?,
                );
                let proposer = $datum_index::proposer(data_slice)
                    .try_into()
                    .map_err(|_| BlockHeaderDataFromHotStuffDataError::Proposer)?;
                let timestamp = u32::from_le_bytes(
                    $datum_index::timestamp(data_slice)
                        .try_into()
                        .map_err(|_| BlockHeaderDataFromHotStuffDataError::Timestamp)?,
                );
                let transactions_hash = $datum_index::transactions_hash(data_slice)
                    .try_into()
                    .map_err(|_| BlockHeaderDataFromHotStuffDataError::TxnsHash)?;
                let state_hash = $datum_index::state_hash(data_slice)
                    .try_into()
                    .map_err(|_| BlockHeaderDataFromHotStuffDataError::StateHash)?;
                let receipts_hash = $datum_index::receipts_hash(data_slice)
                    .try_into()
                    .map_err(|_| BlockHeaderDataFromHotStuffDataError::ReceiptsHash)?;
                let base_fee_per_gas = u64::from_le_bytes(
                    $datum_index::base_fee_per_gas(data_slice)
                        .try_into()
                        .map_err(|_| BlockHeaderDataFromHotStuffDataError::BaseFeePerGas)?,
                );
                let gas_used = u64::from_le_bytes(
                    $datum_index::gas_used(data_slice)
                        .try_into()
                        .map_err(|_| BlockHeaderDataFromHotStuffDataError::GasUsed)?,
                );
                let logs_bloom = $datum_index::logs_bloom(data_slice)
                    .try_into()
                    .map_err(|_| BlockHeaderDataFromHotStuffDataError::LogsBloom)?;
        
        
                Ok($block_header_data {
                    chain_id,
                    proposer,
                    timestamp,
                    transactions_hash,
                    state_hash,
                    receipts_hash,
                    base_fee_per_gas,
                    gas_used,
                    logs_bloom,
                })
            }
        }

        impl From<$block_header_data> for Data {
            fn from(value: $block_header_data) -> Data {
                let mut buf = vec![Vec::new(); $datum_index::BlockHeaderSize as usize];
                $datum_index::set_chain_id(&mut buf, value.chain_id.to_le_bytes().to_vec());
                $datum_index::set_proposer(&mut buf, value.proposer.to_vec());
                $datum_index::set_timestamp(&mut buf, value.timestamp.to_le_bytes().to_vec());
                $datum_index::set_transactions_hash(&mut buf, value.transactions_hash.to_vec());
                $datum_index::set_state_hash(&mut buf, value.state_hash.to_vec());
                $datum_index::set_receipts_hash(&mut buf, value.receipts_hash.to_vec());
                $datum_index::set_base_fee_per_gas(&mut buf, value.base_fee_per_gas.to_le_bytes().to_vec());
                $datum_index::set_gas_used(&mut buf, value.gas_used.to_le_bytes().to_vec());
                $datum_index::set_logs_bloom(&mut buf, value.logs_bloom.to_vec());
                buf
            }

        }
    };
}

block_header_data_v1_to_v2!(BlockHeaderDataV1, DatumIndexV1);
block_header_data_v1_to_v2!(BlockHeaderDataV2, DatumIndexV2);

/// Enumerates errors in conversion from HotStuffData to BlockDataHeader.
#[derive(Debug)]
pub enum BlockHeaderDataFromHotStuffDataError {
    /// Wrong number of slice of bytes
    NumberOfSlots,
    /// Fail to convert bytes into Chain ID
    ChainID,
    /// Fail to convert bytes into Proposer
    Proposer,
    /// Fail to convert bytes into Timestamp
    Timestamp,
    /// Fail to convert bytes into Transactions Hash
    TxnsHash,
    /// Fail to convert bytes into State Hash
    StateHash,
    /// Fail to convert bytes into Receipts Hash
    ReceiptsHash,
    /// Fail to convert bytes into Base Fee Per Gas
    BaseFeePerGas,
    /// Fail to convert bytes into Gas Used
    GasUsed,
    /// Fail to convert bytes into Logs Bloom
    LogsBloom,
}

/// Enumerates errors in conversion from HotStuffData to BlockData.
#[derive(Debug)]
pub enum BlockDataFromHotStuffDataError {
    /// Fail to convert Block Header.
    WrongHeader(BlockHeaderDataFromHotStuffDataError),
    /// Wrong number of slice of bytes. It should contain equal number of transactions
    /// and receipts.
    IncorrectNumberOfTxnsAndReceipts,
    /// Fail to deserialize a transaction.
    Transaction,
    /// Signature of a transaction is invalid.
    InvalidTransactionSignature,
    /// Fail to deserialize a receipt.
    Receipt,
}
