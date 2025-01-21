use md4::{digest::generic_array::GenericArray, digest::OutputSizeUser, Digest as Md4Digest, Md4};

use tinyvec::ArrayVec;

use crate::MAX_PASSWORD_LENGTH_ALLOWED;

/// UTF-16LE encodes an ASCII password.
#[inline]
fn utf16_le(password: &[u8]) -> ArrayVec<[u8; MAX_PASSWORD_LENGTH_ALLOWED * 2]> {
    let mut buf = ArrayVec::new();

    for el in password {
        buf.push(*el);
        buf.push(0);
    }

    buf
}

/// Hashes a password using NTLM.
#[inline]
pub fn ntlm(password: &[u8]) -> GenericArray<u8, <Md4 as OutputSizeUser>::OutputSize> {
    Md4::digest(utf16_le(password))
}

// #[cfg(test)]
// mod tests {
//     use crate::{ntlm, Password};
//
//     #[test]
//     fn test_ntlm() {
//         let password = Password::new(b"password");
//         let expected = [
//             0x88u8, 0x46, 0xF7, 0xEA, 0xEE, 0x8F, 0xB1, 0x17, 0xAD, 0x06, 0xBD, 0xD8, 0x30, 0xB7,
//             0x58, 0x6C,
//         ];
//         let actual = ntlm(&password);
//         assert_eq!(expected, actual.as_slice());
//     }
// }
