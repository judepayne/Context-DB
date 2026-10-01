use crate::{Error, ErrorKind, Result};
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{One, Signed, Zero};
use std::{cmp::Ordering, str::FromStr};

/// Exact normalized decimal; numeric-v1 limits are not operational precision switches.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ExactNumber {
    coefficient: BigInt,
    exponent: i32,
}
impl ExactNumber {
    fn normalized(mut coefficient: BigInt, mut exponent: i32) -> Result<Self> {
        if coefficient.is_zero() {
            return Ok(Self {
                coefficient,
                exponent: 0,
            });
        }
        while (&coefficient % 10u8).is_zero() {
            coefficient /= 10u8;
            exponent = exponent.checked_add(1).ok_or_else(Self::range)?;
        }
        let digits = coefficient.abs().to_str_radix(10).len();
        let adjusted = i64::from(exponent) + digits as i64 - 1;
        if digits > 128 || !(-1024..=1024).contains(&adjusted) {
            return Err(Self::range());
        }
        Ok(Self {
            coefficient,
            exponent,
        })
    }
    fn range() -> Error {
        Error::new(ErrorKind::Range, "numeric-v1 range/precision exceeded")
    }
    pub fn parse(s: &str) -> Result<Self> {
        if s.len() > 8192 {
            return Err(Error::limit());
        }
        let b = s.as_bytes();
        let mut i = usize::from(b.first() == Some(&b'-'));
        let start = i;
        if b.get(i) == Some(&b'0') {
            i += 1;
        } else {
            if !b.get(i).is_some_and(|c| (b'1'..=b'9').contains(c)) {
                return Err(Error::invalid("JSON number"));
            }
            while b.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
        }
        let mut fraction = 0;
        if b.get(i) == Some(&b'.') {
            i += 1;
            let f = i;
            while b.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
            fraction = i - f;
            if fraction == 0 {
                return Err(Error::invalid("empty fraction"));
            }
        }
        let mantissa_end = i;
        let mut exp: i64 = 0;
        if matches!(b.get(i), Some(b'e' | b'E')) {
            i += 1;
            let negative = b.get(i) == Some(&b'-');
            if matches!(b.get(i), Some(b'+' | b'-')) {
                i += 1;
            }
            let e = i;
            while b.get(i).is_some_and(u8::is_ascii_digit) {
                exp = exp
                    .saturating_mul(10)
                    .saturating_add(i64::from(b[i] - b'0'));
                i += 1;
            }
            if i == e {
                return Err(Error::invalid("empty exponent"));
            }
            if negative {
                exp = -exp;
            }
        }
        if i != b.len() || start == b.len() {
            return Err(Error::invalid("JSON number"));
        }
        let mut digits: String = s[start..mantissa_end]
            .chars()
            .filter(|c| *c != '.')
            .collect();
        if digits.bytes().all(|c| c == b'0') {
            return Self::normalized(BigInt::zero(), 0);
        }
        let trim = digits.len() - digits.trim_end_matches('0').len();
        digits.truncate(digits.len() - trim);
        let digits = digits.trim_start_matches('0');
        if digits.len() > 128 {
            return Err(Self::range());
        }
        let exponent = exp
            .saturating_sub(fraction as i64)
            .saturating_add(trim as i64);
        let exponent = i32::try_from(exponent).map_err(|_| Self::range())?;
        let mut c = BigInt::from_str(digits).map_err(|_| Error::invalid("coefficient"))?;
        if start == 1 {
            c = -c;
        }
        Self::normalized(c, exponent)
    }
    pub fn from_u64(value: u64) -> Self {
        Self::normalized(BigInt::from(value), 0).expect("u64 fits numeric-v1")
    }
    pub fn is_integer(&self) -> bool {
        self.exponent >= 0
    }
    pub fn is_zero(&self) -> bool {
        self.coefficient.is_zero()
    }
    pub fn is_negative(&self) -> bool {
        self.coefficient.is_negative()
    }
    pub fn to_u64(&self) -> Result<u64> {
        use num_traits::ToPrimitive;
        if !self.is_integer() || self.exponent > 19 {
            return Err(Self::range());
        }
        (&self.coefficient * Self::pow10(self.exponent as u32)?)
            .to_u64()
            .ok_or_else(Self::range)
    }
    fn pow10(n: u32) -> Result<BigInt> {
        if n > 2304 {
            return Err(Error::limit());
        }
        Ok(BigInt::from(10u8).pow(n))
    }
    fn aligned(&self, other: &Self) -> Result<(BigInt, BigInt, i32)> {
        let e = self.exponent.min(other.exponent);
        Ok((
            &self.coefficient * Self::pow10((self.exponent - e) as u32)?,
            &other.coefficient * Self::pow10((other.exponent - e) as u32)?,
            e,
        ))
    }
    pub fn checked_cmp(&self, other: &Self) -> Result<Ordering> {
        let (a, b, _) = self.aligned(other)?;
        Ok(a.cmp(&b))
    }
    pub fn checked_add(&self, other: &Self) -> Result<Self> {
        let (a, b, e) = self.aligned(other)?;
        Self::normalized(a + b, e)
    }
    pub fn checked_sub(&self, other: &Self) -> Result<Self> {
        let (a, b, e) = self.aligned(other)?;
        Self::normalized(a - b, e)
    }
    pub fn checked_mul(&self, other: &Self) -> Result<Self> {
        Self::normalized(
            &self.coefficient * &other.coefficient,
            self.exponent + other.exponent,
        )
    }
    pub fn checked_div(&self, other: &Self) -> Result<Self> {
        if other.is_zero() {
            return Err(Error::new(ErrorKind::Arithmetic, "division by zero"));
        }
        let gcd = self.coefficient.gcd(&other.coefficient);
        let mut n = &self.coefficient / &gcd;
        let mut d = &other.coefficient / gcd;
        if d.is_negative() {
            n = -n;
            d = -d;
        }
        let mut twos = 0u32;
        let mut fives = 0u32;
        while (&d % 2u8).is_zero() {
            d /= 2u8;
            twos += 1;
        }
        while (&d % 5u8).is_zero() {
            d /= 5u8;
            fives += 1;
        }
        if d != BigInt::one() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "nonterminating exact division",
            ));
        }
        let k = twos.max(fives);
        n *= BigInt::from(2u8).pow(k - twos) * BigInt::from(5u8).pow(k - fives);
        Self::normalized(n, self.exponent - other.exponent - k as i32)
    }
    pub fn from_binary32(bits: u32) -> Result<Self> {
        Self::binary(u64::from(bits), 23, 8, 127)
    }
    pub fn from_binary64(bits: u64) -> Result<Self> {
        Self::binary(bits, 52, 11, 1023)
    }
    fn binary(bits: u64, mantissa: u32, expbits: u32, bias: i32) -> Result<Self> {
        let mask = (1u64 << expbits) - 1;
        let exp = (bits >> mantissa) & mask;
        if exp == mask {
            return Err(Error::invalid("nonfinite binary float"));
        }
        let frac = bits & ((1u64 << mantissa) - 1);
        let sig = if exp == 0 {
            frac
        } else {
            frac | (1u64 << mantissa)
        };
        let e = if exp == 0 {
            1 - bias
        } else {
            exp as i32 - bias
        } - mantissa as i32;
        let mut c = BigInt::from(sig);
        if bits >> (mantissa + expbits) != 0 {
            c = -c;
        }
        if e >= 0 {
            Self::normalized(c << e as usize, 0)
        } else {
            Self::normalized(c * BigInt::from(5u8).pow((-e) as u32), e)
        }
    }
    pub fn token(&self) -> String {
        if self.is_zero() {
            return "0".into();
        }
        let digits = self.coefficient.abs().to_str_radix(10);
        let mut s = if self.is_negative() {
            "-".to_owned()
        } else {
            String::new()
        };
        if self.exponent >= 0 {
            s.push_str(&digits);
            s.extend(std::iter::repeat_n('0', self.exponent as usize));
        } else {
            let point = digits.len() as i32 + self.exponent;
            if point > 0 {
                s.push_str(&digits[..point as usize]);
                s.push('.');
                s.push_str(&digits[point as usize..]);
            } else {
                s.push_str("0.");
                s.extend(std::iter::repeat_n('0', (-point) as usize));
                s.push_str(&digits);
            }
        }
        s
    }
}
impl FromStr for ExactNumber {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}
