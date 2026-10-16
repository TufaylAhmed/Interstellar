//! Structural diff between two policy documents.

use interstellar_ir::PolicyDocument;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffReport {
    pub left_name: String,
    pub right_name: String,
    pub addresses_only_left: Vec<String>,
    pub addresses_only_right: Vec<String>,
    pub services_only_left: Vec<String>,
    pub services_only_right: Vec<String>,
    pub rules_only_left: Vec<String>,
    pub rules_only_right: Vec<String>,
    pub rules_changed: Vec<RuleChange>,
    pub nat_only_left: Vec<String>,
    pub nat_only_right: Vec<String>,
    pub summary: DiffSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleChange {
    pub name: String,
    pub changes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffSummary {
    pub address_delta: i64,
    pub service_delta: i64,
    pub rule_delta: i64,
    pub nat_delta: i64,
    pub changed_rules: usize,
}

pub fn diff_documents(
    left: &PolicyDocument,
    right: &PolicyDocument,
    left_name: impl Into<String>,
    right_name: impl Into<String>,
) -> DiffReport {
    let la: BTreeSet<_> = left.addresses.iter().map(|a| a.name.as_str()).collect();
    let ra: BTreeSet<_> = right.addresses.iter().map(|a| a.name.as_str()).collect();
    let ls: BTreeSet<_> = left.services.iter().map(|s| s.name.as_str()).collect();
    let rs: BTreeSet<_> = right.services.iter().map(|s| s.name.as_str()).collect();
    let lr: BTreeSet<_> = left.security_rules.iter().map(|r| r.name.as_str()).collect();
    let rr: BTreeSet<_> = right.security_rules.iter().map(|r| r.name.as_str()).collect();
    let ln: BTreeSet<_> = left.nat_rules.iter().map(|n| n.name.as_str()).collect();
    let rn: BTreeSet<_> = right.nat_rules.iter().map(|n| n.name.as_str()).collect();

    let mut rules_changed = Vec::new();
    for name in lr.intersection(&rr) {
        let l = left.security_rules.iter().find(|r| r.name == *name).unwrap();
        let r = right.security_rules.iter().find(|r| r.name == *name).unwrap();
        let mut changes = Vec::new();
        if l.action != r.action {
            changes.push(format!("action {:?} → {:?}", l.action, r.action));
        }
        if l.source != r.source {
            changes.push(format!("source {:?} → {:?}", l.source, r.source));
        }
        if l.destination != r.destination {
            changes.push(format!("destination {:?} → {:?}", l.destination, r.destination));
        }
        if l.service != r.service {
            changes.push(format!("service {:?} → {:?}", l.service, r.service));
        }
        if l.from_zones != r.from_zones || l.to_zones != r.to_zones {
            changes.push(format!(
                "zones {:?}/{:?} → {:?}/{:?}",
                l.from_zones, l.to_zones, r.from_zones, r.to_zones
            ));
        }
        if l.disabled != r.disabled {
            changes.push(format!("disabled {} → {}", l.disabled, r.disabled));
        }
        if !changes.is_empty() {
            rules_changed.push(RuleChange {
                name: (*name).to_string(),
                changes,
            });
        }
    }

    let addresses_only_left = set_diff(&la, &ra);
    let addresses_only_right = set_diff(&ra, &la);
    let services_only_left = set_diff(&ls, &rs);
    let services_only_right = set_diff(&rs, &ls);
    let rules_only_left = set_diff(&lr, &rr);
    let rules_only_right = set_diff(&rr, &lr);
    let nat_only_left = set_diff(&ln, &rn);
    let nat_only_right = set_diff(&rn, &ln);

    DiffReport {
        left_name: left_name.into(),
        right_name: right_name.into(),
        summary: DiffSummary {
            address_delta: ra.len() as i64 - la.len() as i64,
            service_delta: rs.len() as i64 - ls.len() as i64,
            rule_delta: rr.len() as i64 - lr.len() as i64,
            nat_delta: rn.len() as i64 - ln.len() as i64,
            changed_rules: rules_changed.len(),
        },
        addresses_only_left,
        addresses_only_right,
        services_only_left,
        services_only_right,
        rules_only_left,
        rules_only_right,
        rules_changed,
        nat_only_left,
        nat_only_right,
    }
}

fn set_diff(a: &BTreeSet<&str>, b: &BTreeSet<&str>) -> Vec<String> {
    a.difference(b).map(|s| (*s).to_string()).collect()
}
