//! Hash chain: `hash = SHA-256(prev_hash || encode(row))`.

use sha2::{Digest, Sha256};

use crate::encode::{CanonicalRow, Encoding, encode};
use crate::error::CoreError;

/// The previous-hash value used for the first row of a chain.
pub const GENESIS: [u8; 32] = [0u8; 32];

/// Computes a row's hash from the previous row's hash and the row's canonical encoding.
pub fn row_hash(
    prev_hash: &[u8; 32],
    row: &CanonicalRow,
    encoding: Encoding,
) -> Result<[u8; 32], CoreError> {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash);
    hasher.update(encode(row, encoding)?);
    Ok(hasher.finalize().into())
}

/// Lower-case hex rendering of a hash, for reports and golden vectors.
pub fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}
