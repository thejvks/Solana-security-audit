//! Report serialization. Currently JSON; other formats can plug in here.

pub mod json;

pub use json::{to_json, write_json};

/// Current UTC time as an RFC 3339 / ISO 8601 timestamp (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn now_timestamp() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}
