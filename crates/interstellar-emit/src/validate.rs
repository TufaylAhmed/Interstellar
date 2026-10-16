use interstellar_ir::{
    PolicyDocument, Severity, ValidationIssue, ValidationReport,
};
use std::collections::BTreeSet;

pub fn validate_document(doc: &PolicyDocument) -> ValidationReport {
    let mut issues = Vec::new();
    let mut addr_names: BTreeSet<&str> = BTreeSet::new();
    let mut svc_names: BTreeSet<&str> = BTreeSet::new();

    for a in &doc.addresses {
        if !addr_names.insert(a.name.as_str()) {
            issues.push(ValidationIssue {
                severity: Severity::Error,
                code: "DUP_ADDRESS".into(),
                message: format!("duplicate address object '{}'", a.name),
                object: Some(a.name.clone()),
            });
        }
    }
    for g in &doc.address_groups {
        if !addr_names.insert(g.name.as_str()) {
            issues.push(ValidationIssue {
                severity: Severity::Error,
                code: "DUP_ADDRESS_GROUP".into(),
                message: format!("address group name collides: '{}'", g.name),
                object: Some(g.name.clone()),
            });
        }
        for m in &g.members {
            if !matches!(m.to_ascii_lowercase().as_str(), "any" | "all")
                && !addr_names.contains(m.as_str())
                && !doc.address_groups.iter().any(|x| x.name == *m)
            {
                issues.push(ValidationIssue {
                    severity: Severity::Warning,
                    code: "MISSING_ADDR_MEMBER".into(),
                    message: format!("address-group '{}' member '{}' not defined", g.name, m),
                    object: Some(g.name.clone()),
                });
            }
        }
    }

    for s in &doc.services {
        if !svc_names.insert(s.name.as_str()) {
            issues.push(ValidationIssue {
                severity: Severity::Error,
                code: "DUP_SERVICE".into(),
                message: format!("duplicate service '{}'", s.name),
                object: Some(s.name.clone()),
            });
        }
    }
    for g in &doc.service_groups {
        svc_names.insert(g.name.as_str());
    }

    let mut rule_names = BTreeSet::new();
    for r in &doc.security_rules {
        if !rule_names.insert(r.name.as_str()) {
            issues.push(ValidationIssue {
                severity: Severity::Error,
                code: "DUP_RULE".into(),
                message: format!("duplicate security rule '{}'", r.name),
                object: Some(r.name.clone()),
            });
        }
        for s in &r.source {
            check_addr_ref(&mut issues, &addr_names, doc, s, &r.name, "source");
        }
        for d in &r.destination {
            check_addr_ref(&mut issues, &addr_names, doc, d, &r.name, "destination");
        }
        for s in &r.service {
            let sl = s.to_ascii_lowercase();
            if matches!(sl.as_str(), "any" | "all" | "application-default") {
                continue;
            }
            if !svc_names.contains(s.as_str())
                && !doc.service_groups.iter().any(|g| g.name == *s)
            {
                issues.push(ValidationIssue {
                    severity: Severity::Warning,
                    code: "MISSING_SERVICE_REF".into(),
                    message: format!("rule '{}' service '{}' not defined", r.name, s),
                    object: Some(r.name.clone()),
                });
            }
        }
        if r.from_zones.is_empty() || r.to_zones.is_empty() {
            issues.push(ValidationIssue {
                severity: Severity::Error,
                code: "EMPTY_ZONE".into(),
                message: format!("rule '{}' has empty zone list", r.name),
                object: Some(r.name.clone()),
            });
        }
    }

    for n in &doc.nat_rules {
        if n.translated_source.is_none() && n.translated_destination.is_none() {
            issues.push(ValidationIssue {
                severity: Severity::Warning,
                code: "NAT_NO_TRANSLATION".into(),
                message: format!("NAT rule '{}' has no translation", n.name),
                object: Some(n.name.clone()),
            });
        }
    }

    if doc.security_rules.is_empty()
        && doc.addresses.is_empty()
        && doc.nat_rules.is_empty()
    {
        issues.push(ValidationIssue {
            severity: Severity::Error,
            code: "EMPTY_DOCUMENT".into(),
            message: "parsed document contains no addresses, rules, or NAT".into(),
            object: None,
        });
    }

    ValidationReport { issues }
}

fn check_addr_ref(
    issues: &mut Vec<ValidationIssue>,
    addr_names: &BTreeSet<&str>,
    doc: &PolicyDocument,
    name: &str,
    rule: &str,
    field: &str,
) {
    if matches!(
        name.to_ascii_lowercase().as_str(),
        "any" | "all" | "any4" | "any6"
    ) {
        return;
    }
    if addr_names.contains(name) || doc.address_groups.iter().any(|g| g.name == name) {
        return;
    }
    issues.push(ValidationIssue {
        severity: Severity::Warning,
        code: "MISSING_ADDR_REF".into(),
        message: format!("rule '{rule}' {field} '{name}' not defined"),
        object: Some(rule.into()),
    });
}
