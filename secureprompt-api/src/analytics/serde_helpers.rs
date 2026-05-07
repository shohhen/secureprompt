//! Dual-format serde adapters for chrono types.
//!
//! Why this exists: `clickhouse::serde::chrono::date` (and `::datetime`) are
//! built for ClickHouse's RowBinary protocol — `date` writes a `u16` of
//! days-since-1970, `datetime` writes a `u32` of seconds-since-epoch. When
//! a struct decorated with `#[serde(with = "clickhouse::serde::chrono::date")]`
//! is then serialized with `serde_json` (e.g. an Axum `Json<...>` response),
//! the same `serialize` impl runs and the JSON output gets the raw integer.
//! That's how `usage_date` ended up rendering as `20579` on the dashboard
//! x-axis instead of `2026-05-06`.
//!
//! These adapters branch on `Serializer::is_human_readable()` (true for
//! JSON, false for ClickHouse RowBinary) and dispatch to the correct
//! representation:
//!   - JSON: chrono's default ISO 8601 string.
//!   - RowBinary: the ClickHouse-native integer encoding.
//!
//! `Deserialize` mirrors the branch so round-trip from either side works.

pub mod date {
    use chrono::NaiveDate;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(d: &NaiveDate, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            d.serialize(s)
        } else {
            clickhouse::serde::chrono::date::serialize(d, s)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<NaiveDate, D::Error> {
        if d.is_human_readable() {
            NaiveDate::deserialize(d)
        } else {
            clickhouse::serde::chrono::date::deserialize(d)
        }
    }
}

pub mod datetime {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(dt: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            dt.serialize(s)
        } else {
            clickhouse::serde::chrono::datetime::serialize(dt, s)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DateTime<Utc>, D::Error> {
        if d.is_human_readable() {
            DateTime::<Utc>::deserialize(d)
        } else {
            clickhouse::serde::chrono::datetime::deserialize(d)
        }
    }
}
