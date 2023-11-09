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

macro_rules! define_serde {
    ($($t:ty),*) => {
        $(
            impl Serializable for $t {}
            impl Deserializable for $t {}
        )*
    }
}
pub(crate) use define_serde;


define_serde!(
    u8, u16, u32, u64, bool, String
);

impl<T: Serializable> Serializable for Option<T>{}
impl<T: Deserializable> Deserializable for Option<T>{}

impl<T: Serializable> Serializable for Vec<T> {}
impl<T: Deserializable> Deserializable for Vec<T> {}

impl<T1: Serializable> Serializable for (T1,) {}
impl<T1: Deserializable> Deserializable for (T1,) {}

impl<T: Serializable, const N: usize> Serializable for [T; N] {}
impl<T: Deserializable, const N: usize> Deserializable for [T; N] {}

macro_rules! impl_tuple_serde {
    ($($idx:tt $name:ident)+) => {
      impl<$($name: Serializable),+> Serializable for ($($name),+) {}
      impl<$($name: Deserializable),+> Deserializable for ($($name),+) {}
    };
}
impl_tuple_serde!(0 T0 1 T1);
impl_tuple_serde!(0 T0 1 T1 2 T2);
impl_tuple_serde!(0 T0 1 T1 2 T2 3 T3);
impl_tuple_serde!(0 T0 1 T1 2 T2 3 T3 4 T4);
impl_tuple_serde!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5);
impl_tuple_serde!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6);
impl_tuple_serde!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7);
impl_tuple_serde!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8);
impl_tuple_serde!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9);
impl_tuple_serde!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10);
impl_tuple_serde!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10 11 T11);
impl_tuple_serde!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10 11 T11 12 T12);
impl_tuple_serde!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10 11 T11 12 T12 13 T13);
impl_tuple_serde!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10 11 T11 12 T12 13 T13 14 T14);
impl_tuple_serde!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10 11 T11 12 T12 13 T13 14 T14 15 T15);
impl_tuple_serde!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10 11 T11 12 T12 13 T13 14 T14 15 T15 16 T16);
impl_tuple_serde!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10 11 T11 12 T12 13 T13 14 T14 15 T15 16 T16 17 T17);
impl_tuple_serde!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10 11 T11 12 T12 13 T13 14 T14 15 T15 16 T16 17 T17 18 T18);
impl_tuple_serde!(0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10 11 T11 12 T12 13 T13 14 T14 15 T15 16 T16 17 T17 18 T18 19 T19);

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

    test_primitive!( test_u8, 101_u8, u8);
    test_primitive!( test_u16, 102_u16, u16);
    test_primitive!( test_u32, 103_u32, u32);
    test_primitive!( test_u64, 104_u64, u64);
    test_primitive!( test_vec_u8, vec![105_u8; 1000], Vec<u8>);
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
    fn test_slice() {
        check!([1u8], [u8; 1]);
        check!([1u16, 2], [u16; 2]);
        check!([1u32, 2, 3], [u32; 3]);
        check!([1u64, 2, 3, 4], [u64; 4]);
        check!([true, false], [bool; 2]);
        check!(["true".to_string(), "false".to_string(), "".to_string()], [String; 3]);
        check!([Some("true".to_string()), None, Some("".to_string())], [Option<String>; 3]);
        check!([(1u8, 2u64), (3u8, 4u64)], [(u8, u64); 2]);
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