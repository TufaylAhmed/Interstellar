//! Vendor config parsers → [`interstellar_ir::PolicyDocument`].

mod checkpoint;
mod cisco;
mod fortinet;
mod junos;
mod panos;
mod util;

use anyhow::{bail, Context, Result};
use interstellar_ir::{PolicyDocument, Vendor};
use std::path::Path;

pub use checkpoint::parse_checkpoint;
pub use cisco::parse_cisco;
pub use fortinet::parse_fortinet;
pub use junos::parse_junos;
pub use panos::parse_panos;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedVendor {
    Fortinet,
    Cisco,
    Checkpoint,
    Panos,
    Juniper,
}

impl From<DetectedVendor> for Vendor {
    fn from(v: DetectedVendor) -> Self {
        match v {
            DetectedVendor::Fortinet => Vendor::Fortinet,
            DetectedVendor::Cisco => Vendor::Cisco,
            DetectedVendor::Checkpoint => Vendor::Checkpoint,
            DetectedVendor::Panos => Vendor::Panos,
            DetectedVendor::Juniper => Vendor::Juniper,
        }
    }
}

pub fn detect_vendor(text: &str) -> DetectedVendor {
    let head = text.chars().take(4000).collect::<String>();
    let lower = head.to_ascii_lowercase();

    if lower.contains("<config")
        && (lower.contains("urldb") || lower.contains("<devices>") || lower.contains("<shared>"))
    {
        return DetectedVendor::Panos;
    }
    if lower.contains("config system global")
        || lower.contains("config firewall address")
        || lower.contains("config firewall policy")
        || lower.contains("#config-version=")
    {
        return DetectedVendor::Fortinet;
    }
    if lower.contains("asa version")
        || lower.contains("pix version")
        || lower.contains("object network")
        || lower.contains("access-list ")
        || lower.contains("object-group network")
    {
        return DetectedVendor::Cisco;
    }
    if lower.contains("security address-book")
        || lower.contains("security policies from-zone")
        || lower.contains("applications application")
        || (lower.contains("set system host-name") && lower.contains("security"))
        || lower.contains("junos")
    {
        return DetectedVendor::Juniper;
    }
    if lower.trim_start().starts_with('{')
        || lower.contains("\"uid\"")
        || lower.contains("checkpoint")
        || lower.contains("set access-rule")
        || lower.contains("set host name")
    {
        return DetectedVendor::Checkpoint;
    }
    if lower.contains("edit \"") && lower.contains("set subnet") {
        return DetectedVendor::Fortinet;
    }
    DetectedVendor::Cisco
}

pub fn parse_text(text: &str, vendor: Option<DetectedVendor>) -> Result<PolicyDocument> {
    let vendor = vendor.unwrap_or_else(|| detect_vendor(text));
    match vendor {
        DetectedVendor::Fortinet => parse_fortinet(text),
        DetectedVendor::Cisco => parse_cisco(text),
        DetectedVendor::Checkpoint => parse_checkpoint(text),
        DetectedVendor::Panos => parse_panos(text),
        DetectedVendor::Juniper => parse_junos(text),
    }
}

pub fn parse_file(path: &Path, vendor: Option<DetectedVendor>) -> Result<PolicyDocument> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let mut doc = parse_text(&text, vendor)?;
    if doc.source_name.is_none() {
        doc.source_name = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned());
    }
    Ok(doc)
}

pub fn parse_vendor_str(s: &str) -> Result<Option<DetectedVendor>> {
    match s.trim().to_ascii_lowercase().as_str() {
        "" | "auto" => Ok(None),
        "fortinet" | "fortigate" | "fg" => Ok(Some(DetectedVendor::Fortinet)),
        "cisco" | "asa" | "ios" => Ok(Some(DetectedVendor::Cisco)),
        "checkpoint" | "cp" | "r80" | "r81" => Ok(Some(DetectedVendor::Checkpoint)),
        "panos" | "paloalto" | "palo-alto" | "pa" => Ok(Some(DetectedVendor::Panos)),
        "juniper" | "junos" | "srx" => Ok(Some(DetectedVendor::Juniper)),
        other => bail!(
            "unknown vendor '{other}' (auto|fortinet|cisco|checkpoint|panos|juniper)"
        ),
    }
}
