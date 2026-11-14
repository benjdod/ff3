//! Fixed-modulus Barrett-style reduction used by the FF3 round function.

/// Reciprocal reducer for 128-bit values and a fixed modulus.
#[derive(Clone, Copy)]
pub(super) struct ModReducer {
    modulus: u128,
    reciprocal: u128,
}

impl ModReducer {
    pub(super) fn new(modulus: u128) -> Self {
        debug_assert!(modulus >= 2);
        // floor(2^128 / modulus), using MAX + 1 without representing 2^128.
        let max = u128::MAX;
        let q = max / modulus;
        let rem = max - q * modulus;
        let reciprocal = q + u128::from(rem == modulus - 1);
        Self {
            modulus,
            reciprocal,
        }
    }

    pub(super) fn modulus(&self) -> u128 {
        self.modulus
    }

    #[inline]
    pub(super) fn reduce(self, value: u128) -> u128 {
        let quotient = mul_high_u128(value, self.reciprocal);
        let remainder = value - quotient * self.modulus;
        conditional_subtract(remainder, self.modulus)
    }
}

#[inline]
pub(super) fn conditional_subtract(value: u128, modulus: u128) -> u128 {
    let (difference, borrow) = value.overflowing_sub(modulus);
    let keep_difference = 0u128.wrapping_sub((!borrow) as u128);
    (difference & keep_difference) | (value & !keep_difference)
}

/// Upper 128 bits of the full 256-bit product.
#[inline]
fn mul_high_u128(a: u128, b: u128) -> u128 {
    let (a0, a1) = (a as u64 as u128, (a >> 64) as u64 as u128);
    let (b0, b1) = (b as u64 as u128, (b >> 64) as u64 as u128);
    let p00 = a0 * b0;
    let p01 = a0 * b1;
    let p10 = a1 * b0;
    let p11 = a1 * b1;

    let middle = (p00 >> 64) + (p01 as u64 as u128) + (p10 as u64 as u128);
    let upper = (p01 >> 64) + (p10 >> 64) + (p11 as u64 as u128) + (middle >> 64);
    let high = (p11 >> 64) + (upper >> 64);
    ((high as u64 as u128) << 64) | upper as u64 as u128
}

#[cfg(test)]
mod tests {
    use super::ModReducer;

    #[test]
    fn exhaustive_small_values() {
        for modulus in 2u128..=256 {
            let reducer = ModReducer::new(modulus);
            for value in 0u128..=u16::MAX as u128 {
                assert_eq!(
                    reducer.reduce(value),
                    value % modulus,
                    "m={modulus}, x={value}"
                );
            }
        }
    }

    #[test]
    fn matches_remainder_for_all_ff3_moduli() {
        let mut state = 0x8a5c_23d1_792b_e40fu128;
        let limit = 1u128 << 96;
        for radix in 2u128..=256 {
            let mut modulus = radix;
            while modulus <= limit {
                let reducer = ModReducer::new(modulus);
                let largest_multiple = (u128::MAX / modulus) * modulus;
                for value in [
                    0,
                    1,
                    modulus - 1,
                    modulus,
                    modulus.saturating_add(1),
                    largest_multiple.saturating_sub(1),
                    largest_multiple,
                    u128::MAX - 1,
                    u128::MAX,
                ] {
                    assert_eq!(
                        reducer.reduce(value),
                        value % modulus,
                        "r={radix}, m={modulus}, x={value}"
                    );
                }
                for _ in 0..64 {
                    state ^= state << 23;
                    state ^= state >> 17;
                    state ^= state << 26;
                    assert_eq!(
                        reducer.reduce(state),
                        state % modulus,
                        "r={radix}, m={modulus}"
                    );
                }
                match modulus.checked_mul(radix) {
                    Some(next) => modulus = next,
                    None => break,
                }
            }
        }
    }
}
