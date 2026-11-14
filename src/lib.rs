#![doc = include_str!("../README.md")]

use aes::{Aes128, Aes192, Aes256};
use cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use std::collections::HashMap;
use zeroize::Zeroizing;
mod reduction;
use reduction::ModReducer;
use reduction::conditional_subtract;

const MAX_FF3_SYMBOLS: usize = 192;

/// Errors returned by the FF3 Cipher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The AES key length is not 16, 24, or 32 bytes.
    InvalidKeyLength { actual: usize },
    /// The tweak length is not 7 bytes (FF3-1) or 8 bytes (FF3).
    InvalidTweakLength { actual: usize },
    /// The alphabet contains fewer than 2 or more than 256 symbols.
    InvalidAlphabetLength { actual: usize },
    /// The alphabet contains the same symbol more than once.
    DuplicateUnicodeSymbol { symbol: char },
    /// The input contains fewer than 2 symbols.
    InputTooShort { actual: usize },
    /// The input contains a symbol that is not present in the alphabet.
    InvalidSymbol,
    /// The input domain has fewer than 1,000,000 possible values (`radix^length`).
    DomainTooSmall { radix: usize, length: usize },
    /// The input exceeds the supported FF3 domain: either it is longer than
    /// 192 symbols or either half's radix-powered domain exceeds 96 bits.
    DomainTooLarge { radix: usize, length: usize },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKeyLength { actual } => write!(
                f,
                "invalid AES key length: got {actual} bytes; expected 16, 24, or 32"
            ),
            Self::InvalidTweakLength { actual } => write!(
                f,
                "invalid tweak length: got {actual} bytes; expected 7 (FF3-1) or 8 (FF3)"
            ),
            Self::InvalidAlphabetLength { actual } => write!(
                f,
                "invalid alphabet size: got {actual} symbols; expected 2..=256"
            ),
            Self::DuplicateUnicodeSymbol { symbol } => {
                write!(f, "alphabet contains duplicate symbol {symbol:?}")
            }
            Self::InputTooShort { actual } => write!(
                f,
                "input is too short: got {actual} symbols; expected at least 2"
            ),
            Self::InvalidSymbol => write!(f, "input contains a symbol not in the alphabet"),
            Self::DomainTooSmall { radix, length } => write!(
                f,
                "domain too small: radix {radix} with input length {length} has fewer than 1,000,000 values"
            ),
            Self::DomainTooLarge { radix, length } => write!(
                f,
                "domain too large: radix {radix} with input length {length} exceeds FF3's 96-bit half-domain limit"
            ),
        }
    }
}

impl std::error::Error for Error {}

enum AesKey {
    A128(Aes128),
    A192(Aes192),
    A256(Aes256),
}
impl AesKey {
    fn encrypt(&self, block: &mut [u8; 16]) {
        let b = GenericArray::from_mut_slice(block);
        match self {
            Self::A128(a) => a.encrypt_block(b),
            Self::A192(a) => a.encrypt_block(b),
            Self::A256(a) => a.encrypt_block(b),
        }
    }
}

/// FF3/FF3-1 cipher for a fixed alphabet of symbols.
///
/// ```
/// use ff3::Ff3;
///
/// let cipher = Ff3::new(&[0; 16], "0123456789")?;
/// let tweak = [0; 7];
/// let encrypted = cipher.encrypt(&tweak, "1234567890")?;
/// assert_eq!(cipher.decrypt(&tweak, &encrypted)?, "1234567890");
/// # Ok::<(), ff3::Error>(())
/// ```
pub struct Ff3 {
    aes: AesKey,
    alphabet: String,
    symbols: Vec<char>,
    radix: u128,
    reducers: Vec<ModReducer>,
    ascii_lookup: [u16; 128],
    unicode_lookup: HashMap<char, u8>,
}

impl Ff3 {
    /// Create a cipher with the provided alphabet and key.
    /// The created cipher may be used for multiple operations.
    pub fn new(key: &[u8], alphabet: &str) -> Result<Self, Error> {
        Self::create(key, alphabet)
    }

    /// Return this cipher's alphabet.
    pub fn alphabet(&self) -> &str {
        &self.alphabet
    }

    /// Return the radix of the cipher's alphabet.
    pub fn radix(&self) -> usize {
        self.symbols.len()
    }

    /// Encrypt `input` using the supplied 8-byte (FF3) or 7-byte (FF3-1) tweak.
    pub fn encrypt(&self, tweak: &[u8], input: &str) -> Result<String, Error> {
        self.crypt_string(tweak, input, false)
    }
    /// Decrypt `input` using the supplied 8-byte (FF3) or 7-byte (FF3-1) tweak.
    pub fn decrypt(&self, tweak: &[u8], input: &str) -> Result<String, Error> {
        self.crypt_string(tweak, input, true)
    }

    /// Encrypt into a reusable `String` buffer.
    pub fn encrypt_into(
        &self,
        tweak: &[u8],
        input: &str,
        output: &mut String,
    ) -> Result<(), Error> {
        self.crypt_string_into(tweak, input, output, false)
    }

    /// Decrypt into a reusable `String` buffer.
    pub fn decrypt_into(
        &self,
        tweak: &[u8],
        input: &str,
        output: &mut String,
    ) -> Result<(), Error> {
        self.crypt_string_into(tweak, input, output, true)
    }

    fn create(key: &[u8], alphabet: &str) -> Result<Self, Error> {
        if !matches!(key.len(), 16 | 24 | 32) {
            return Err(Error::InvalidKeyLength { actual: key.len() });
        }
        let symbols: Vec<char> = alphabet.chars().collect();
        if !(2..=256).contains(&symbols.len()) {
            return Err(Error::InvalidAlphabetLength {
                actual: symbols.len(),
            });
        }
        let mut ascii_lookup = [256u16; 128];
        let mut unicode_lookup = HashMap::with_capacity(symbols.len());
        for (i, &symbol) in symbols.iter().enumerate() {
            if unicode_lookup.insert(symbol, i as u8).is_some() {
                return Err(Error::DuplicateUnicodeSymbol { symbol });
            }
            if (symbol as u32) < 128 {
                ascii_lookup[symbol as usize] = i as u16;
            }
        }
        // FF3 applies AES with the byte-reversed key.
        let mut reversed = Zeroizing::new(key.to_vec());
        reversed.reverse();
        let aes = match key.len() {
            16 => AesKey::A128(
                Aes128::new_from_slice(&reversed)
                    .map_err(|_| Error::InvalidKeyLength { actual: key.len() })?,
            ),
            24 => AesKey::A192(
                Aes192::new_from_slice(&reversed)
                    .map_err(|_| Error::InvalidKeyLength { actual: key.len() })?,
            ),
            _ => AesKey::A256(
                Aes256::new_from_slice(&reversed)
                    .map_err(|_| Error::InvalidKeyLength { actual: key.len() })?,
            ),
        };
        let radix = symbols.len() as u128;
        let mut reducers = Vec::new();
        let mut modulus = radix;
        while modulus <= (1u128 << 96) {
            reducers.push(ModReducer::new(modulus));
            match modulus.checked_mul(radix) {
                Some(next) => modulus = next,
                None => break,
            }
        }
        Ok(Self {
            aes,
            alphabet: alphabet.to_owned(),
            symbols,
            radix,
            reducers,
            ascii_lookup,
            unicode_lookup,
        })
    }

    fn crypt_string(&self, tweak: &[u8], input: &str, decrypt: bool) -> Result<String, Error> {
        let mut output = String::with_capacity(input.len());
        self.crypt_string_into(tweak, input, &mut output, decrypt)?;
        Ok(output)
    }

    fn crypt_string_into(
        &self,
        tweak: &[u8],
        input: &str,
        output: &mut String,
        decrypt: bool,
    ) -> Result<(), Error> {
        let length = if input.is_ascii() {
            input.len()
        } else {
            input.chars().count()
        };
        if length > MAX_FF3_SYMBOLS {
            return Err(Error::DomainTooLarge {
                radix: self.radix as usize,
                length,
            });
        }
        let mut digits = [0u8; MAX_FF3_SYMBOLS];
        if input.is_ascii() {
            for (index, symbol) in input.bytes().enumerate() {
                let digit = self.ascii_lookup[symbol as usize];
                if digit == 256 {
                    return Err(Error::InvalidSymbol);
                }
                digits[index] = digit as u8;
            }
        } else {
            for (index, symbol) in input.chars().enumerate() {
                digits[index] = self
                    .unicode_lookup
                    .get(&symbol)
                    .copied()
                    .ok_or(Error::InvalidSymbol)?;
            }
        }
        let mut output_digits = [0u8; MAX_FF3_SYMBOLS];
        self.crypt_digits_into(
            tweak,
            &digits[..length],
            &mut output_digits[..length],
            decrypt,
        )?;
        output.clear();
        for &digit in &output_digits[..length] {
            output.push(self.symbols[digit as usize]);
        }
        Ok(())
    }

    fn crypt_digits_into(
        &self,
        tweak: &[u8],
        input: &[u8],
        output: &mut [u8],
        decrypt: bool,
    ) -> Result<(), Error> {
        if !matches!(tweak.len(), 7 | 8) {
            return Err(Error::InvalidTweakLength {
                actual: tweak.len(),
            });
        }
        let ff3_1 = tweak.len() == 7;
        let n = input.len();
        if n < 2 {
            return Err(Error::InputTooShort { actual: n });
        }
        let u = n.div_ceil(2);
        let v = n - u;
        let (mut a, mut b) = (0u128, 0u128);
        for &digit in input {
            if digit as u128 >= self.radix {
                return Err(Error::InvalidSymbol);
            }
        }
        // FF3's numeral conversion is defined over REV(A) and REV(B).
        for &ch in input[..u].iter().rev() {
            a = a
                .checked_mul(self.radix)
                .and_then(|x| x.checked_add(ch as u128))
                .ok_or(Error::DomainTooLarge {
                    radix: self.radix as usize,
                    length: n,
                })?;
        }
        for &ch in input[u..].iter().rev() {
            b = b
                .checked_mul(self.radix)
                .and_then(|x| x.checked_add(ch as u128))
                .ok_or(Error::DomainTooLarge {
                    radix: self.radix as usize,
                    length: n,
                })?;
        }
        let mut domain = 1u128;
        for _ in 0..n {
            domain = domain.saturating_mul(self.radix).min(1_000_000);
        }
        if domain < 1_000_000 {
            return Err(Error::DomainTooSmall {
                radix: self.radix as usize,
                length: n,
            });
        }
        let reducer_u = self.reducers.get(u - 1).ok_or(Error::DomainTooLarge {
            radix: self.radix as usize,
            length: n,
        })?;
        let reducer_v = self.reducers.get(v - 1).ok_or(Error::DomainTooLarge {
            radix: self.radix as usize,
            length: n,
        })?;
        if reducer_u.modulus() > (1u128 << 96) || reducer_v.modulus() > (1u128 << 96) {
            return Err(Error::DomainTooLarge {
                radix: self.radix as usize,
                length: n,
            });
        }
        let (tl, tr) = if ff3_1 {
            (
                [tweak[0], tweak[1], tweak[2], tweak[3] & 0xf0],
                [tweak[4], tweak[5], tweak[6], (tweak[3] & 0x0f) << 4],
            )
        } else {
            (
                [tweak[0], tweak[1], tweak[2], tweak[3]],
                [tweak[4], tweak[5], tweak[6], tweak[7]],
            )
        };
        for step in 0..8 {
            let round = if decrypt { 7 - step } else { step };
            let even = round % 2 == 0;
            let reducer = if even { &reducer_u } else { &reducer_v };
            let modulus = reducer.modulus();
            let w = if even { &tr } else { &tl };
            let x = if decrypt { a } else { b };
            let mut p = [0u8; 16];
            p[..4].copy_from_slice(w);
            p[3] ^= round as u8;
            let mut num = x;
            for j in (4..16).rev() {
                p[j] = (num & 0xff) as u8;
                num >>= 8;
            }
            p.reverse();
            self.aes.encrypt(&mut p);
            p.reverse();
            let yval = u128::from_be_bytes(p);
            let reduced_y = reducer.reduce(yval);
            if !decrypt {
                let sum = a + reduced_y;
                let c = conditional_subtract(sum, modulus);
                a = b;
                b = c;
            } else {
                let c = conditional_subtract(b + modulus - reduced_y, modulus);
                let old_a = a;
                a = c;
                b = old_a;
            }
        }
        let (mut left, mut right) = (a, b);
        for slot in output.iter_mut().take(u) {
            let quotient = left / self.radix;
            let remainder = left - quotient * self.radix;
            *slot = remainder as u8;
            left = quotient;
        }
        for slot in output.iter_mut().skip(u) {
            let quotient = right / self.radix;
            let remainder = right - quotient * self.radix;
            *slot = remainder as u8;
            right = quotient;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let cipher = Ff3::new(&[0; 16], "0123456789").unwrap();
        assert_eq!(cipher.alphabet(), "0123456789");
        assert_eq!(cipher.radix(), 10);
        let tweak = [0; 7];
        let text = "1234567890";
        let encrypted = cipher.encrypt(&tweak, text).unwrap();
        assert_ne!(encrypted, text);
        assert_eq!(cipher.decrypt(&tweak, &encrypted).unwrap(), text);
        let mut output = String::new();
        cipher.encrypt_into(&tweak, text, &mut output).unwrap();
        assert_eq!(output, encrypted);
        let mut plaintext = String::new();
        cipher
            .decrypt_into(&tweak, &output, &mut plaintext)
            .unwrap();
        assert_eq!(plaintext, text);
    }

    #[test]
    fn rejects_invalid_configuration_and_inputs() {
        assert!(matches!(
            Ff3::new(&[0; 15], "0123456789"),
            Err(Error::InvalidKeyLength { actual: 15 })
        ));
        assert!(matches!(
            Ff3::new(&[0; 16], "1"),
            Err(Error::InvalidAlphabetLength { actual: 1 })
        ));
        assert!(matches!(
            Ff3::new(&[0; 16], "001"),
            Err(Error::DuplicateUnicodeSymbol { .. })
        ));

        let cipher = Ff3::new(&[0; 16], "0123456789").unwrap();
        assert!(matches!(
            cipher.encrypt(&[0; 6], "123456"),
            Err(Error::InvalidTweakLength { actual: 6 })
        ));
        assert!(matches!(
            cipher.encrypt(&[0; 7], "1"),
            Err(Error::InputTooShort { actual: 1 })
        ));
        assert!(matches!(
            cipher.encrypt(&[0; 7], "12345"),
            Err(Error::DomainTooSmall {
                radix: 10,
                length: 5
            })
        ));
        assert!(matches!(
            cipher.encrypt(&[0; 7], "12345x"),
            Err(Error::InvalidSymbol)
        ));
        assert!(matches!(
            cipher.encrypt(&[0; 7], &"0".repeat(58)),
            Err(Error::DomainTooLarge {
                radix: 10,
                length: 58
            })
        ));
    }

    #[test]
    fn tweak_length_selects_variant_without_mutating_cipher_state() {
        let cipher = Ff3::new(&[0x42; 16], "0123456789").unwrap();
        let plaintext = "1234567890";
        let ff3_1_tweak = [0x11; 7];
        let ff3_tweak = [0x11; 8];

        let ff3_1_ciphertext = cipher.encrypt(&ff3_1_tweak, plaintext).unwrap();
        let ff3_ciphertext = cipher.encrypt(&ff3_tweak, plaintext).unwrap();
        assert_ne!(ff3_1_ciphertext, ff3_ciphertext);
        assert_eq!(
            cipher.encrypt(&ff3_1_tweak, plaintext).unwrap(),
            ff3_1_ciphertext
        );
        assert_eq!(
            cipher.encrypt(&ff3_tweak, plaintext).unwrap(),
            ff3_ciphertext
        );
    }
}
