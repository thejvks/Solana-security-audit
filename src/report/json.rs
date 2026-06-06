use std::path::Path;

use crate::errors::{AuditError, Result};
use crate::risk::RiskReport;

/// Serialize a report to pretty-printed JSON.
pub fn to_json(report: &RiskReport) -> Result<String> {
    serde_json::to_string_pretty(report).map_err(|e| AuditError::Serialization(e.to_string()))
}

/// Write a report to a file as pretty-printed JSON.
pub fn write_json(report: &RiskReport, path: impl AsRef<Path>) -> Result<()> {
    let json = to_json(report)?;
    std::fs::write(path, json)?;
    Ok(())
}
