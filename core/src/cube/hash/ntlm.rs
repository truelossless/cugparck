use cubecl::prelude::*;

use crate::cube::{
    compute::{Digest, Password},
    hash::utils::{memcpy, rotate_left},
};

/// UTF-16LE encodes an ASCII password.
// #[inline]
// fn utf16_le(password: &[u8]) -> ArrayVec<[u8; MAX_PASSWORD_LENGTH_ALLOWED * 2]> {
//     let mut buf = ArrayVec::new();

//     for el in password {
//         buf.push(*el);
//         buf.push(0);
//     }

//     buf
// }

/// Hashes a password using NTLM.
// #[cube]
// pub fn ntlm(password: Digest) -> Digest {
//     md4(utf16_le(password))
// }
//

#[cube]
pub fn md4_f(x: u32, y: u32, z: u32) -> u32 {
    z ^ (x & (y ^ z))
}

#[cube]
pub fn md4_g(x: u32, y: u32, z: u32) -> u32 {
    (x & (y | z)) | (y & z)
}

#[cube]
pub fn md4_h(x: u32, y: u32, z: u32) -> u32 {
    (x) ^ (y) ^ (z)
}

#[cube]
pub fn md4_ff(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32) -> u32 {
    let mut a = a + md4_f(b, c, d) + x;
    a = rotate_left(a, s);
    a
}

#[cube]
pub fn md4_gg(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32) -> u32 {
    let mut a = a + md4_g(b, c, d) + x + 0x5A827999;
    a = rotate_left(a, s);
    a
}

#[cube]
pub fn md4_hh(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32) -> u32 {
    let mut a = a + md4_h(b, c, d) + x + 0x6ED9EBA1;
    a = rotate_left(a, s);
    a
}

#[cube]
fn md4_process_block(block: &Array<u32>) -> Array<u32> {
    let mut hash = Array::new(4);
    hash[0] = 0x67452301u32;
    hash[1] = 0xEFCDAB89u32;
    hash[2] = 0x98BADCFEu32;
    hash[3] = 0x10325476u32;

    let mut a = hash[0];
    let mut b = hash[1];
    let mut c = hash[2];
    let mut d = hash[3];

    a = md4_ff(a, b, c, d, block[0], 3);
    d = md4_ff(d, a, b, c, block[1], 7);
    c = md4_ff(c, d, a, b, block[2], 11);
    b = md4_ff(b, c, d, a, block[3], 19);
    a = md4_ff(a, b, c, d, block[4], 3);
    d = md4_ff(d, a, b, c, block[5], 7);
    c = md4_ff(c, d, a, b, block[6], 11);
    b = md4_ff(b, c, d, a, block[7], 19);
    a = md4_ff(a, b, c, d, block[8], 3);
    d = md4_ff(d, a, b, c, block[9], 7);
    c = md4_ff(c, d, a, b, block[10], 11);
    b = md4_ff(b, c, d, a, block[11], 19);
    a = md4_ff(a, b, c, d, block[12], 3);
    d = md4_ff(d, a, b, c, block[13], 7);
    c = md4_ff(c, d, a, b, block[14], 11);
    b = md4_ff(b, c, d, a, block[15], 19);

    a = md4_gg(a, b, c, d, block[0], 3);
    d = md4_gg(d, a, b, c, block[4], 5);
    c = md4_gg(c, d, a, b, block[8], 9);
    b = md4_gg(b, c, d, a, block[12], 13);
    a = md4_gg(a, b, c, d, block[1], 3);
    d = md4_gg(d, a, b, c, block[5], 5);
    c = md4_gg(c, d, a, b, block[9], 9);
    b = md4_gg(b, c, d, a, block[13], 13);
    a = md4_gg(a, b, c, d, block[2], 3);
    d = md4_gg(d, a, b, c, block[6], 5);
    c = md4_gg(c, d, a, b, block[10], 9);
    b = md4_gg(b, c, d, a, block[14], 13);
    a = md4_gg(a, b, c, d, block[3], 3);
    d = md4_gg(d, a, b, c, block[7], 5);
    c = md4_gg(c, d, a, b, block[11], 9);
    b = md4_gg(b, c, d, a, block[15], 13);

    a = md4_hh(a, b, c, d, block[0], 3);
    d = md4_hh(d, a, b, c, block[8], 9);
    c = md4_hh(c, d, a, b, block[4], 11);
    b = md4_hh(b, c, d, a, block[12], 15);
    a = md4_hh(a, b, c, d, block[2], 3);
    d = md4_hh(d, a, b, c, block[10], 9);
    c = md4_hh(c, d, a, b, block[6], 11);
    b = md4_hh(b, c, d, a, block[14], 15);
    a = md4_hh(a, b, c, d, block[1], 3);
    d = md4_hh(d, a, b, c, block[9], 9);
    c = md4_hh(c, d, a, b, block[5], 11);
    b = md4_hh(b, c, d, a, block[13], 15);
    a = md4_hh(a, b, c, d, block[3], 3);
    d = md4_hh(d, a, b, c, block[11], 9);
    c = md4_hh(c, d, a, b, block[7], 11);
    b = md4_hh(b, c, d, a, block[15], 15);

    hash[0] += a;
    hash[1] += b;
    hash[2] += c;
    hash[3] += d;

    hash
}

/// A MD4 hash implementation.
/// Only handles up to 56 input bytes.
#[cube]
pub fn md4(password: &Password) -> Digest {
    // make the input the size of a block
    let mut input = Array::<u8>::new(64);
    for i in 0..password.len() {
        input[i] = password.data[i];
    }

    // add padding
    input[password.len()] = 0x80;
    for i in password.len() + 1..64 {
        input[i] = 0;
    }

    // create block
    let mut block = Array::new(16);
    memcpy(&mut block, &input, 64);
    block[14] = password.len() << 3;
    block[15] = password.len() >> 29;

    // process block
    let hash = md4_process_block(&block);

    let mut digest = Digest::new(16);
    memcpy(&mut digest, &hash, 16);
    digest
}

#[cfg(test)]
mod tests {
    use crate::test_hash_function;
    use cubecl::prelude::*;

    #[test]
    fn test_md4() {
        test_hash_function!(
            crate::cube::hash::ntlm::md4,
            16,
            "message digest",
            &[
                0xd9, 0x13, 0x0a, 0x81, 0x64, 0x54, 0x9f, 0xe8, 0x18, 0x87, 0x48, 0x06, 0xe1, 0xc7,
                0x01, 0x4b
            ]
        );
    }
}
