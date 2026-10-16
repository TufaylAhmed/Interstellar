//! Policy analysis: unused objects, shadowing hints, broad allows.

use interstellar_ir::{PolicyDocument, RuleAction};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub unused_addresses: Vec<String>,
    pub unused_services: Vec<String>,
    pub unused_address_groups: Vec<String>,
    pub unused_service_groups: Vec<String>,
    pub shadowed_rules: Vec<ShadowHint>,
    pub broad_allows: Vec<String>,
    pub duplicate_rules: Vec<(String, String)>,
    pub stats: AnalysisStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowHint {
    pub earlier: String,
    pub later: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisStats {
    pub total_rules: usize,
    pub allow_rules: usize,
    pub deny_rules: usize,
    pub disabled_rules: usize,
    pub nat_rules: usize,
    pub address_objects: usize,
    pub service_objects: usize,
}

pub fn analyze(doc: &PolicyDocument) -> AnalysisReport {
    let used_addr = collect_used_addresses(doc);
    let used_svc = collect_used_services(doc);

    let unused_addresses = doc
        .addresses
        .iter()
        .map(|a| a.name.clone())
        .filter(|n| !used_addr.contains(n.as_str()))
        .collect();
    let unused_address_groups = doc
        .address_groups
        .iter()
        .map(|g| g.name.clone())
        .filter(|n| !used_addr.contains(n.as_str()))
        .collect();
    let unused_services = doc
        .services
        .iter()
        .map(|s| s.name.clone())
        .filter(|n| !used_svc.contains(n.as_str()))
        .collect();
    let unused_service_groups = doc
        .service_groups
        .iter()
        .map(|g| g.name.clone())
        .filter(|n| !used_svc.contains(n.as_str()))
        .collect();

    let shadowed_rules = find_shadow_hints(doc);
    let broad_allows = doc
        .security_rules
        .iter()
        .filter(|r| {
            !r.disabled
                && r.action == RuleAction::Allow
                && is_any(&r.source)
                && is_any(&r.destination)
                && is_any(&r.service)
                && is_any(&r.application)
        })
        .map(|r| r.name.clone())
        .collect();

    let duplicate_rules = find_duplicate_rules(doc);

    let allow_rules = doc
        .security_rules
        .iter()
        .filter(|r| r.action == RuleAction::Allow)
        .count();
    let deny_rules = doc.security_rules.len().saturating_sub(allow_rules);
    let disabled_rules = doc.security_rules.iter().filter(|r| r.disabled).count();

    AnalysisReport {
        unused_addresses,
        unused_services,
        unused_address_groups,
        unused_service_groups,
        shadowed_rules,
        broad_allows,
        duplicate_rules,
        stats: AnalysisStats {
            total_rules: doc.security_rules.len(),
            allow_rules,
            deny_rules,
            disabled_rules,
            nat_rules: doc.nat_rules.len(),
            address_objects: doc.addresses.len(),
            service_objects: doc.services.len(),
        },
    }
}

fn is_any(v: &[String]) -> bool {
    v.iter().any(|s| s.eq_ignore_ascii_case("any") || s.eq_ignore_ascii_case("all"))
}

fn collect_used_addresses(doc: &PolicyDocument) -> BTreeSet<&str> {
    let mut used = BTreeSet::new();
    for r in &doc.security_rules {
        for s in r.source.iter().chain(r.destination.iter()) {
            used.insert(s.as_str());
        }
    }
    for n in &doc.nat_rules {
        for s in n
            .source
            .iter()
            .chain(n.destination.iter())
            .chain(n.translated_source.iter())
            .chain(n.translated_destination.iter())
        {
            used.insert(s.as_str());
        }
    }
    // group members count as used if group is used
    let mut changed = true;
    while changed {
        changed = false;
        for g in &doc.address_groups {
            if used.contains(g.name.as_str()) {
                for m in &g.members {
                    if used.insert(m.as_str()) {
                        changed = true;
                    }
                }
            }
        }
    }
    used
}

fn collect_used_services(doc: &PolicyDocument) -> BTreeSet<&str> {
    let mut used = BTreeSet::new();
    for r in &doc.security_rules {
        for s in &r.service {
            used.insert(s.as_str());
        }
    }
    for n in &doc.nat_rules {
        for s in &n.service {
            used.insert(s.as_str());
        }
        if let Some(s) = &n.translated_service {
            used.insert(s.as_str());
        }
    }
    let mut changed = true;
    while changed {
        changed = false;
        for g in &doc.service_groups {
            if used.contains(g.name.as_str()) {
                for m in &g.members {
                    if used.insert(m.as_str()) {
                        changed = true;
                    }
                }
            }
        }
    }
    used
}

fn find_shadow_hints(doc: &PolicyDocument) -> Vec<ShadowHint> {
    let mut hints = Vec::new();
    let rules: Vec<_> = doc
        .security_rules
        .iter()
        .filter(|r| !r.disabled)
        .collect();
    for i in 0..rules.len() {
        for j in (i + 1)..rules.len() {
            let a = rules[i];
            let b = rules[j];
            if supersets(a, b) {
                hints.push(ShadowHint {
                    earlier: a.name.clone(),
                    later: b.name.clone(),
                    reason: format!(
                        "'{}' may shadow '{}' (same/wider zones, src, dst, service, action={:?})",
                        a.name, b.name, a.action
                    ),
                });
            }
        }
    }
    hints
}

fn supersets(earlier: &interstellar_ir::SecurityRule, later: &interstellar_ir::SecurityRule) -> bool {
    if earlier.action != later.action {
        // allow before deny can still shadow for matching traffic; keep simple: only same action
        return false;
    }
    covers(&earlier.from_zones, &later.from_zones)
        && covers(&earlier.to_zones, &later.to_zones)
        && covers(&earlier.source, &later.source)
        && covers(&earlier.destination, &later.destination)
        && covers(&earlier.service, &later.service)
        && covers(&earlier.application, &later.application)
}

fn covers(wider: &[String], narrower: &[String]) -> bool {
    if is_any(wider) {
        return true;
    }
    narrower.iter().all(|n| wider.iter().any(|w| w == n))
}

fn find_duplicate_rules(doc: &PolicyDocument) -> Vec<(String, String)> {
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    let mut dups = Vec::new();
    for r in &doc.security_rules {
        let key = format!(
            "{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}",
            r.from_zones,
            r.to_zones,
            r.source,
            r.destination,
            r.service,
            r.application,
            r.action
        );
        if let Some(prev) = seen.get(&key) {
            dups.push((prev.clone(), r.name.clone()));
        } else {
            seen.insert(key, r.name.clone());
        }
    }
    dups
}

#[cfg(test)]
mod tests {
    use super::*;
    use interstellar_ir::{AddressObject, AddressValue, SecurityRule, Vendor};

    #[test]
    fn finds_unused_and_broad() {
        let mut doc = PolicyDocument::new(Vendor::Fortinet);
        doc.addresses.push(AddressObject {
            name: "used".into(),
            value: AddressValue::IpNetmask {
                value: "10.0.0.1/32".into(),
            },
            description: None,
            tags: vec![],
        });
        doc.addresses.push(AddressObject {
            name: "unused".into(),
            value: AddressValue::IpNetmask {
                value: "10.0.0.2/32".into(),
            },
            description: None,
            tags: vec![],
        });
        doc.security_rules.push(SecurityRule {
            name: "wide".into(),
            from_zones: vec!["any".into()],
            to_zones: vec!["any".into()],
            source: vec!["any".into()],
            destination: vec!["any".into()],
            application: vec!["any".into()],
            service: vec!["any".into()],
            action: RuleAction::Allow,
            disabled: false,
            log_start: false,
            log_end: true,
            description: None,
            tags: vec![],
            profile_group: None,
            profiles: Default::default(),
        });
        doc.security_rules.push(SecurityRule {
            name: "specific".into(),
            from_zones: vec!["any".into()],
            to_zones: vec!["any".into()],
            source: vec!["used".into()],
            destination: vec!["used".into()],
            application: vec!["any".into()],
            service: vec!["any".into()],
            action: RuleAction::Allow,
            disabled: false,
            log_start: false,
            log_end: true,
            description: None,
            tags: vec![],
            profile_group: None,
            profiles: Default::default(),
        });
        let report = analyze(&doc);
        assert!(report.unused_addresses.iter().any(|n| n == "unused"));
        assert!(report.broad_allows.iter().any(|n| n == "wide"));
        assert!(!report.shadowed_rules.is_empty());
    }
}
