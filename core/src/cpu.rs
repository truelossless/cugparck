use crate::{ctx::RainbowTableCtx, CompressedPassword};

/// An ASCII password stored in a stack-allocated vector.
pub type Password = Vec<u8>;

/// A digest stored in a stack-allocated vector.
pub type Digest = Vec<u8>;

/// Reduces a digest into a password.
// Notice how we multiply the table number with the iteration instead of just adding it.
// This allows the reduce functions to be very different from one table to another.
// On 4 tables, it bumps the success rate from 96.5% to 99.9% (way closer to the theoritical bound).
#[inline]
pub fn reduce(digest: &Digest, iteration: u64, ctx: &RainbowTableCtx) -> CompressedPassword {
    // we can use the 8 first bytes of the digest as the seed, since it is pseudo-random.
    // SAFETY: The digest is at least 8 bytes long.
    let first_bytes = unsafe { u64::from_le_bytes(digest[0..8].try_into().unwrap_unchecked()) };
    first_bytes.wrapping_add(iteration.wrapping_mul(ctx.tn as u64)) % ctx.n
}

/// Creates a plaintext from a counter.
#[inline]
pub fn counter_to_plaintext(mut counter: u64, ctx: &RainbowTableCtx) -> Password {
    // SAFETY: A search space is always guaratenteed to be found.
    let search_space_rev = unsafe {
        ctx.search_spaces
            .iter()
            .rev()
            .position(|space| counter >= *space)
            .unwrap_unchecked()
    };
    let len = ctx.search_spaces.len() - search_space_rev - 1;

    counter -= ctx.search_spaces[len];

    let mut plaintext = Password::new();
    for _ in 0..len {
        plaintext.push(charset_to_ascii(
            counter % ctx.charset.len() as u64,
            &ctx.charset,
        ));
        counter /= ctx.charset.len() as u64;
    }

    plaintext
}

/// Creates a counter from a plaintext.
#[inline]
pub fn plaintext_to_counter(plaintext: Password, ctx: &RainbowTableCtx) -> u64 {
    let mut counter = ctx.search_spaces[plaintext.len()];
    for (i, &c) in plaintext.iter().enumerate() {
        counter +=
            ascii_to_charset(c, &ctx.charset) as u64 * (ctx.charset.len() as u64).pow(i as u32);
    }

    counter
}

/// Converts a character from a charset to its ASCII representation.
#[inline]
pub fn charset_to_ascii(n: u64, charset: &[u8]) -> u8 {
    charset[n as usize]
}

/// Converts an ASCII character to the given charset.
#[inline]
pub fn ascii_to_charset(c: u8, charset: &[u8]) -> u8 {
    charset.iter().position(|x| *x == c).unwrap() as u8
}

#[cfg(test)]
mod tests {
    use crate::{
        cpu::{ascii_to_charset, counter_to_plaintext, plaintext_to_counter},
        ctx::build_test_ctx,
        DEFAULT_CHARSET,
    };

    #[test]
    fn test_ascii_to_charset() {
        assert_eq!(9, ascii_to_charset(b'9', DEFAULT_CHARSET));
        assert_eq!(63, ascii_to_charset(b'_', DEFAULT_CHARSET));
    }

    #[test]
    fn test_counter_to_plaintext() {
        let ctx = build_test_ctx();

        let plaintexts = (0..14).map(|i| counter_to_plaintext(i, &ctx));

        let expected = [
            b"".to_vec(),
            b"a".to_vec(),
            b"b".to_vec(),
            b"c".to_vec(),
            b"aa".to_vec(),
            b"ba".to_vec(),
            b"ca".to_vec(),
            b"ab".to_vec(),
            b"bb".to_vec(),
            b"cb".to_vec(),
            b"ac".to_vec(),
            b"bc".to_vec(),
            b"cc".to_vec(),
            b"aaa".to_vec(),
        ];

        assert!(expected.into_iter().eq(plaintexts));
    }

    #[test]
    fn test_plaintext_to_counter() {
        let ctx = build_test_ctx();

        let counters = [
            b"".to_vec(),
            b"a".to_vec(),
            b"b".to_vec(),
            b"c".to_vec(),
            b"aa".to_vec(),
            b"ba".to_vec(),
            b"ca".to_vec(),
            b"ab".to_vec(),
            b"bb".to_vec(),
            b"cb".to_vec(),
            b"ac".to_vec(),
            b"bc".to_vec(),
            b"cc".to_vec(),
            b"aaa".to_vec(),
        ]
        .map(|plaintext| plaintext_to_counter(plaintext, &ctx));

        let expected = 0..14;

        assert!(expected.into_iter().eq(counters));
    }
}
