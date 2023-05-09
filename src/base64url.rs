/*
    Copyright © 2023, ParallelChain Lab 
    Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
*/

//! Implementation of the encode and decode operations (as defined in IETF RFC 4648) on a type [Base64URL]. 
//! It is the *only* binary-to-text encoding scheme used in ParallelChain F. 
//! 
//! In general, we use `-` and `_` instead of `+` and `/`, without paddings.

use std::ops::Deref;

use base64;

/// Base64URL are Strings restricted to containing the 2^6 UTF-8 code points in the Base64URL bytes-to-characters encoding.
/// Base64URL MUST NOT contain padding. 
pub struct Base64URL(String);


impl Base64URL {
    /// encode takes in a slice of bytes and returns the bytes encoded as a Base64URL String. 
    pub fn encode<T: AsRef<[u8]>>(bytes: T) -> Base64URL { 
        Base64URL(base64::encode_config(bytes, base64::Config::new(base64::CharacterSet::UrlSafe, false)))
    }

    /// decode takes in a string and tries to decode it into a Vector of bytes. It returns a base64::DecodeError if `string`
    /// is not valid Base64URL.
    pub fn decode<T: ?Sized + AsRef<[u8]>>(base64_url: &T) -> Result<Vec<u8>, base64::DecodeError> {
        base64::decode_config(base64_url, base64::Config::new(base64::CharacterSet::UrlSafe, false))
    } 
}


impl Deref for Base64URL {
    type Target = String;

    fn deref(&self) -> &String {
        &self.0
    }
}
