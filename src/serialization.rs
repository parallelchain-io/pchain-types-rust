/*
    Copyright © 2023, ParallelChain Lab 
    Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
*/


/// Serializable encapsulates implementation of serialization on data structures that are defined in pchain-types.
pub trait Serializable: borsh::BorshSerialize {
    fn serialize(&self) -> Vec<u8> {
        self.try_to_vec().unwrap()
    }
}

/// Deserializable encapsulates implementation of deserialization on data structures that are defined in pchain-types.
pub trait Deserializable: borsh::BorshDeserialize {
    fn deserialize(args: &[u8]) -> Result<Self, std::io::Error> {
        Self::try_from_slice(args)
    }
}

impl Serializable for u32 {}
impl Deserializable for u32 {}

impl Serializable for u64 {}
impl Deserializable for u64 {}

impl Serializable for Vec<u8> {}
impl Deserializable for Vec<u8> {}

impl Serializable for bool {}
impl Deserializable for bool {}

impl Serializable for String {}
impl Deserializable for String {}

impl<T: Serializable> Serializable for Option<T>{}
impl<T: Deserializable> Deserializable for Option<T>{}

impl<T: Serializable> Serializable for Vec<T> {}
impl<T: Deserializable> Deserializable for Vec<T> {}

impl<T1: Serializable> Serializable for (T1,) {}
impl<T1: Deserializable> Deserializable for (T1,) {}

impl<const N: usize> Serializable for [u8; N] {}
impl<const N: usize> Deserializable for [u8; N] {}

macro_rules! impl_tuple_serializable {
    ($($idx:tt $name:ident)+) => {
      impl<$($name: Serializable),+> Serializable for ($($name),+) {}
    };
}

macro_rules! impl_tuple_deserializable {
    ($($idx:tt $name:ident)+) => {
        impl<$($name: Deserializable),+> Deserializable for ($($name),+) {}
    };
}

impl_tuple_serializable!(0 T0 1 T1);
impl_tuple_serializable!(0 T0 1 T1 2 T2);
impl_tuple_serializable!(0 T0 1 T1 2 T2 3 T3);
impl_tuple_serializable!(0 T0 1 T1 2 T2 3 T3 4 T4);
impl_tuple_serializable!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5);
impl_tuple_serializable!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6);
impl_tuple_serializable!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7);
impl_tuple_serializable!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8);
impl_tuple_serializable!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9);
impl_tuple_serializable!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10);
impl_tuple_serializable!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10 11 T11);
impl_tuple_serializable!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10 11 T11 12 T12);
impl_tuple_serializable!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10 11 T11 12 T12 13 T13);
impl_tuple_serializable!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10 11 T11 12 T12 13 T13 14 T14);
impl_tuple_serializable!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10 11 T11 12 T12 13 T13 14 T14 15 T15);
impl_tuple_serializable!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10 11 T11 12 T12 13 T13 14 T14 15 T15 16 T16);
impl_tuple_serializable!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10 11 T11 12 T12 13 T13 14 T14 15 T15 16 T16 17 T17);
impl_tuple_serializable!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10 11 T11 12 T12 13 T13 14 T14 15 T15 16 T16 17 T17 18 T18);
impl_tuple_serializable!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10 11 T11 12 T12 13 T13 14 T14 15 T15 16 T16 17 T17 18 T18 19 T19);

impl_tuple_deserializable!(0 T0 1 T1);
impl_tuple_deserializable!(0 T0 1 T1 2 T2);
impl_tuple_deserializable!(0 T0 1 T1 2 T2 3 T3);
impl_tuple_deserializable!(0 T0 1 T1 2 T2 3 T3 4 T4);
impl_tuple_deserializable!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5);
impl_tuple_deserializable!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6);
impl_tuple_deserializable!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7);
impl_tuple_deserializable!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8);
impl_tuple_deserializable!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9);
impl_tuple_deserializable!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10);
impl_tuple_deserializable!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10 11 T11);
impl_tuple_deserializable!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10 11 T11 12 T12);
impl_tuple_deserializable!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10 11 T11 12 T12 13 T13);
impl_tuple_deserializable!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10 11 T11 12 T12 13 T13 14 T14);
impl_tuple_deserializable!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10 11 T11 12 T12 13 T13 14 T14 15 T15);
impl_tuple_deserializable!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10 11 T11 12 T12 13 T13 14 T14 15 T15 16 T16);
impl_tuple_deserializable!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10 11 T11 12 T12 13 T13 14 T14 15 T15 16 T16 17 T17);
impl_tuple_deserializable!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10 11 T11 12 T12 13 T13 14 T14 15 T15 16 T16 17 T17 18 T18);
impl_tuple_deserializable!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10 11 T11 12 T12 13 T13 14 T14 15 T15 16 T16 17 T17 18 T18 19 T19);
