//! Vendor-neutral intermediate representation for firewall policy conversion.

pub mod project;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Vendor {
    Fortinet,
    Cisco,
    Checkpoint,
    Panos,
    Juniper,
    Unknown,
}

impl Vendor {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fortinet => "fortinet",
            Self::Cisco => "cisco",
            Self::Checkpoint => "checkpoint",
            Self::Panos => "panos",
            Self::Juniper => "juniper",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AddressValue {
    IpNetmask { value: String },
    IpRange { from: String, to: String },
    Fqdn { value: String },
    IpWildcard { ip: String, mask: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressObject {
    pub name: String,
    pub value: AddressValue,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressGroup {
    pub name: String,
    pub members: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ServiceValue {
    Tcp { port: String },
    Udp { port: String },
    TcpUdp { port: String },
    Protocol { protocol: u8 },
    Any,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceObject {
    pub name: String,
    pub value: ServiceValue,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceGroup {
    pub name: String,
    pub members: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Allow,
    Deny,
    Drop,
    ResetClient,
    ResetServer,
    ResetBoth,
}

impl RuleAction {
    pub fn as_panos(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Drop => "drop",
            Self::ResetClient => "reset-client",
            Self::ResetServer => "reset-server",
            Self::ResetBoth => "reset-both",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityRule {
    pub name: String,
    #[serde(default = "default_any")]
    pub from_zones: Vec<String>,
    #[serde(default = "default_any")]
    pub to_zones: Vec<String>,
    #[serde(default = "default_any")]
    pub source: Vec<String>,
    #[serde(default = "default_any")]
    pub destination: Vec<String>,
    #[serde(default = "default_any_app")]
    pub application: Vec<String>,
    #[serde(default = "default_any")]
    pub service: Vec<String>,
    pub action: RuleAction,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub log_start: bool,
    #[serde(default = "default_true")]
    pub log_end: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_group: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profiles: BTreeMap<String, String>,
}

fn default_any() -> Vec<String> {
    vec!["any".into()]
}
fn default_any_app() -> Vec<String> {
    vec!["any".into()]
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NatType {
    Source,
    Destination,
    Static,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatRule {
    pub name: String,
    pub nat_type: NatType,
    #[serde(default = "default_any")]
    pub from_zones: Vec<String>,
    #[serde(default = "default_any")]
    pub to_zones: Vec<String>,
    #[serde(default = "default_any")]
    pub source: Vec<String>,
    #[serde(default = "default_any")]
    pub destination: Vec<String>,
    #[serde(default = "default_any")]
    pub service: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub translated_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub translated_destination: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub translated_service: Option<String>,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IkeGateway {
    pub name: String,
    pub peer_ip: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_shared_key: Option<String>,
    #[serde(default = "default_ike_version")]
    pub ike_version: String,
}

fn default_ike_version() -> String {
    "ikev2".into()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpsecTunnel {
    pub name: String,
    pub ike_gateway: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_interface: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxy_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityProfileGroup {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub virus: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spyware: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vulnerability: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_filtering: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_blocking: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wildfire: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDocument {
    pub vendor: Vendor,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_version: Option<String>,
    #[serde(default)]
    pub addresses: Vec<AddressObject>,
    #[serde(default)]
    pub address_groups: Vec<AddressGroup>,
    #[serde(default)]
    pub services: Vec<ServiceObject>,
    #[serde(default)]
    pub service_groups: Vec<ServiceGroup>,
    #[serde(default)]
    pub security_rules: Vec<SecurityRule>,
    #[serde(default)]
    pub nat_rules: Vec<NatRule>,
    #[serde(default)]
    pub ike_gateways: Vec<IkeGateway>,
    #[serde(default)]
    pub ipsec_tunnels: Vec<IpsecTunnel>,
    #[serde(default)]
    pub profile_groups: Vec<SecurityProfileGroup>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl Default for Vendor {
    fn default() -> Self {
        Self::Unknown
    }
}

impl PolicyDocument {
    pub fn new(vendor: Vendor) -> Self {
        Self {
            vendor,
            ..Default::default()
        }
    }

    pub fn sanitize_name(name: &str) -> String {
        let mut out = String::with_capacity(name.len());
        for ch in name.chars() {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.' {
                out.push(ch);
            } else if ch == ' ' || ch == '/' {
                out.push('_');
            }
        }
        if out.is_empty() {
            "unnamed".into()
        } else if out
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
        {
            format!("n_{out}")
        } else {
            out
        }
    }

    pub fn merge(&mut self, other: PolicyDocument) {
        self.addresses.extend(other.addresses);
        self.address_groups.extend(other.address_groups);
        self.services.extend(other.services);
        self.service_groups.extend(other.service_groups);
        self.security_rules.extend(other.security_rules);
        self.nat_rules.extend(other.nat_rules);
        self.ike_gateways.extend(other.ike_gateways);
        self.ipsec_tunnels.extend(other.ipsec_tunnels);
        self.profile_groups.extend(other.profile_groups);
        self.warnings.extend(other.warnings);
        if self.source_name.is_none() {
            self.source_name = other.source_name;
        }
        if self.source_version.is_none() {
            self.source_version = other.source_version;
        }
    }

    pub fn summary(&self) -> DocumentSummary {
        DocumentSummary {
            vendor: self.vendor,
            addresses: self.addresses.len(),
            address_groups: self.address_groups.len(),
            services: self.services.len(),
            service_groups: self.service_groups.len(),
            security_rules: self.security_rules.len(),
            nat_rules: self.nat_rules.len(),
            ike_gateways: self.ike_gateways.len(),
            ipsec_tunnels: self.ipsec_tunnels.len(),
            profile_groups: self.profile_groups.len(),
            warnings: self.warnings.len(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentSummary {
    pub vendor: Vendor,
    pub addresses: usize,
    pub address_groups: usize,
    pub services: usize,
    pub service_groups: usize,
    pub security_rules: usize,
    pub nat_rules: usize,
    pub ike_gateways: usize,
    pub ipsec_tunnels: usize,
    pub profile_groups: usize,
    pub warnings: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationIssue {
    pub severity: Severity,
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ValidationReport {
    pub issues: Vec<ValidationIssue>,
}

impl ValidationReport {
    pub fn error_count(&self) -> usize {
        self.issues
            .iter()
            .filter(|i| i.severity == Severity::Error)
            .count()
    }

    pub fn ok(&self) -> bool {
        self.error_count() == 0
    }
}
