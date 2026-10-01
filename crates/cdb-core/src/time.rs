use crate::{Error, ErrorKind, Result};
use chrono::{DateTime, Datelike, SecondsFormat, Utc};
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Timestamp(i64);
impl Timestamp {
    pub fn parse(s: &str) -> Result<Self> {
        // RFC3339 accepts leap seconds; reject them and any nonzero submilliseconds explicitly.
        if let Some(dot) = s.find('.') {
            let fraction: String = s[dot + 1..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            if fraction.len() > 3 && fraction.as_bytes()[3..].iter().any(|b| *b != b'0') {
                return Err(Error::invalid("nonzero submilliseconds"));
            }
        }
        let dt =
            DateTime::parse_from_rfc3339(s).map_err(|_| Error::invalid("RFC3339 timestamp"))?;
        if dt.timestamp_subsec_nanos() >= 1_000_000_000
            || dt.timestamp_subsec_nanos() % 1_000_000 != 0
        {
            return Err(Error::invalid(
                "timestamp must be exact milliseconds, no leap seconds",
            ));
        }
        Self::from_millis(dt.timestamp_millis())
    }
    pub fn from_millis(ms: i64) -> Result<Self> {
        let d = DateTime::<Utc>::from_timestamp_millis(ms)
            .ok_or_else(|| Error::new(ErrorKind::Range, "timestamp"))?;
        if !(1..=9999).contains(&d.year()) {
            return Err(Error::new(ErrorKind::Range, "UTC year outside 0001..9999"));
        }
        Ok(Self(ms))
    }
    pub fn millis(self) -> i64 {
        self.0
    }
    pub fn checked_add_millis(self, n: i64) -> Result<Self> {
        Self::from_millis(
            self.0
                .checked_add(n)
                .ok_or_else(|| Error::new(ErrorKind::Range, "timestamp overflow"))?,
        )
    }
    pub fn canonical(self) -> String {
        DateTime::<Utc>::from_timestamp_millis(self.0)
            .expect("validated timestamp")
            .to_rfc3339_opts(SecondsFormat::Millis, true)
    }
}
