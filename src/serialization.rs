/*
    Copyright © 2023, ParallelChain Lab 
    Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
*/


//! Traits for deterministic serialization of protocol-defined types. 

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

#[cfg(test)]
mod test {
    use super::{Serializable, Deserializable};

    macro_rules! check {
        ($v: expr, $t: ty) => {
            let expected: $t = $v;
            let buf = expected.serialize();
            
            let actual = <$t>::deserialize(&buf).expect("failed to deserialize");
            assert_eq!(actual, expected);
        };
    }

    macro_rules! test_primitive {
        ($test_name: ident, $v: expr, $t: ty) => {
            #[test]
            fn $test_name() {
                check!($v, $t);
            }
        };
    }

    test_primitive!( test_u32, 100_u32, u32);
    test_primitive!( test_u64, 100_u64, u64);
    test_primitive!( test_vec_u8, vec![100_u8; 1000], Vec<u8>);
    test_primitive!( test_bool, true, bool);
    test_primitive!( test_string, "test_string".to_string(), String);

    #[test]
    fn test_option() {
        check!(None, Option<u32>);
        check!(Some(100_u32), Option<u32>);
        check!(None, Option<u64>);
        check!(Some(100_u64), Option<u64>);
        check!(Some(vec![100_u8; 1000]), Option<Vec<u8>>);
        check!(Some(false), Option<bool>);
        check!(Some("test_string".to_string()), Option<String>);
        check!(Some(vec![vec![100_u8; 10], vec![200_u8; 10]]), Option<Vec<Vec<u8>>>);
        check!(Some((255_u32,)), Option<(u32,)>);
        check!(Some([255_u8; 10]), Option<[u8; 10]>);
    }

    #[test]
    fn test_vec() {
        check!(vec![100_u32], Vec<u32>);
        check!(vec![1_u64, 2_u64, 3_u64], Vec<u64>);
        check!(vec![vec![100_u8; 1000]], Vec<Vec<u8>>);
        check!(vec![false], Vec<bool>);
        check!(vec!["test_string".to_string()], Vec<String>);
        check!(vec![vec![100_u8; 10], vec![200_u8; 10]], Vec<Vec<u8>>);
        check!(vec![(255_u32,)], Vec<(u32,)>);
        check!(vec![[255_u8; 10]], Vec<[u8; 10]>);
    }

    #[test]
    fn test_tuple() {
        check!((10_u32, true, "test_string".to_string()), (u32, bool, String));
    }
}