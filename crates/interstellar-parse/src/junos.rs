//! Juniper SRX `set` / hierarchical config parser (common subset).

use crate::util::{tokenize, unquote};
use anyhow::Result;
use interstellar_ir::{
    AddressGroup, AddressObject, AddressValue, NatRule, NatType, PolicyDocument, RuleAction,
    SecurityRule, ServiceObject, ServiceValue, Vendor,
};

pub fn parse_junos(text: &str) -> Result<PolicyDocument> {
    let mut doc = PolicyDocument::new(Vendor::Juniper);
    // Flatten hierarchical braces into logical set-lines where possible,
    // but also accept native `set ...` lines.
    let flat = flatten_hierarchy(text);
    for raw in flat.lines().chain(text.lines()) {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("/*") {
            continue;
        }
        let line = line.strip_prefix("set ").unwrap_or(line);
        let toks = tokenize(line);
        if toks.len() < 3 {
            continue;
        }

        // security zones security-zone TRUST interfaces ge-0/0/0.0
        // security policies from-zone TRUST to-zone UNTRUST policy ALLOW-WEB match source-address HOST
        // security address-book global address WEB 10.1.1.10/32
        // applications application HTTP-ALT protocol tcp destination-port 8080
        // security nat source rule-set RS rule R1 then source-nat interface

        if toks[0] == "system" && toks.get(1).map(|s| s.as_str()) == Some("host-name") {
            if let Some(n) = toks.get(2) {
                doc.source_name = Some(unquote(n));
            }
            continue;
        }

        if toks[0] == "security" && toks.get(1).map(|s| s.as_str()) == Some("address-book") {
            // security address-book global address NAME VALUE
            // security address-book global address-set NAME address MEM
            if toks.len() >= 6 && toks[3] == "address" && toks[2] != "address-set" {
                let name = PolicyDocument::sanitize_name(&unquote(&toks[4]));
                let value = unquote(&toks[5]);
                let addr = if value.contains('-') && !value.contains('/') {
                    let mut parts = value.split('-');
                    AddressValue::IpRange {
                        from: parts.next().unwrap_or("0.0.0.0").into(),
                        to: parts.next().unwrap_or("0.0.0.0").into(),
                    }
                } else if value.contains('/') {
                    AddressValue::IpNetmask { value }
                } else {
                    AddressValue::IpNetmask {
                        value: format!("{value}/32"),
                    }
                };
                doc.addresses.push(AddressObject {
                    name,
                    value: addr,
                    description: None,
                    tags: vec!["junos".into()],
                });
            } else if toks.len() >= 6 && toks[3] == "address-set" {
                // security address-book global address-set SET address MEMBER
                let gname = PolicyDocument::sanitize_name(&unquote(&toks[4]));
                if toks.get(5).map(|s| s.as_str()) == Some("address") {
                    if let Some(m) = toks.get(6) {
                        let member = PolicyDocument::sanitize_name(&unquote(m));
                        if let Some(g) = doc.address_groups.iter_mut().find(|g| g.name == gname) {
                            g.members.push(member);
                        } else {
                            doc.address_groups.push(AddressGroup {
                                name: gname,
                                members: vec![member],
                                description: None,
                            });
                        }
                    }
                }
            }
            continue;
        }

        if toks[0] == "applications" && toks.get(1).map(|s| s.as_str()) == Some("application") {
            // applications application NAME protocol tcp destination-port 443
            let name = PolicyDocument::sanitize_name(&unquote(&toks[2]));
            let mut proto = "tcp".to_string();
            let mut port = "any".to_string();
            let mut i = 3;
            while i < toks.len() {
                match toks[i].as_str() {
                    "protocol" => {
                        if let Some(p) = toks.get(i + 1) {
                            proto = p.to_ascii_lowercase();
                            i += 2;
                            continue;
                        }
                    }
                    "destination-port" => {
                        if let Some(p) = toks.get(i + 1) {
                            port = unquote(p);
                            i += 2;
                            continue;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            if !doc.services.iter().any(|s| s.name == name) {
                doc.services.push(ServiceObject {
                    name,
                    value: match proto.as_str() {
                        "udp" => ServiceValue::Udp { port },
                        _ => ServiceValue::Tcp { port },
                    },
                    description: None,
                });
            }
            continue;
        }

        if toks[0] == "security" && toks.get(1).map(|s| s.as_str()) == Some("policies") {
            // security policies from-zone A to-zone B policy NAME match source-address X
            // security policies from-zone A to-zone B policy NAME then permit
            if toks.len() < 8 || toks[2] != "from-zone" || toks[4] != "to-zone" || toks[6] != "policy"
            {
                continue;
            }
            let from = PolicyDocument::sanitize_name(&unquote(&toks[3]));
            let to = PolicyDocument::sanitize_name(&unquote(&toks[5]));
            let pname = PolicyDocument::sanitize_name(&unquote(&toks[7]));
            if !doc.security_rules.iter().any(|r| r.name == pname) {
                doc.security_rules.push(SecurityRule {
                    name: pname.clone(),
                    from_zones: vec![from],
                    to_zones: vec![to],
                    source: vec!["any".into()],
                    destination: vec!["any".into()],
                    application: vec!["any".into()],
                    service: vec!["any".into()],
                    action: RuleAction::Drop,
                    disabled: false,
                    log_start: false,
                    log_end: true,
                    description: Some("junos policy".into()),
                    tags: vec!["junos".into()],
                    profile_group: None,
                    profiles: Default::default(),
                });
            }
            let r = doc
                .security_rules
                .iter_mut()
                .find(|r| r.name == pname)
                .expect("rule just ensured");
            if toks.get(8).map(|s| s.as_str()) == Some("match") {
                match toks.get(9).map(|s| s.as_str()) {
                    Some("source-address") => {
                        if let Some(v) = toks.get(10) {
                            let v = normalize(v);
                            if r.source == ["any".to_string()] {
                                r.source = vec![v];
                            } else if !r.source.contains(&v) {
                                r.source.push(v);
                            }
                        }
                    }
                    Some("destination-address") => {
                        if let Some(v) = toks.get(10) {
                            let v = normalize(v);
                            if r.destination == ["any".to_string()] {
                                r.destination = vec![v];
                            } else if !r.destination.contains(&v) {
                                r.destination.push(v);
                            }
                        }
                    }
                    Some("application") => {
                        if let Some(v) = toks.get(10) {
                            let v = normalize(v);
                            // junos applications map to service/app — put in service
                            if r.service == ["any".to_string()] {
                                r.service = vec![v];
                            } else if !r.service.contains(&v) {
                                r.service.push(v);
                            }
                        }
                    }
                    _ => {}
                }
            } else if toks.get(8).map(|s| s.as_str()) == Some("then") {
                match toks.get(9).map(|s| s.as_str()) {
                    Some("permit") => r.action = RuleAction::Allow,
                    Some("deny") => r.action = RuleAction::Deny,
                    Some("reject") => r.action = RuleAction::ResetBoth,
                    _ => {}
                }
            }
            continue;
        }

        if toks[0] == "security" && toks.get(1).map(|s| s.as_str()) == Some("nat") {
            // security nat source rule-set RS rule NAME match source-address-name USERS
            // security nat source rule-set RS rule NAME then source-nat interface
            if toks.get(2).map(|s| s.as_str()) == Some("source")
                && toks.get(3).map(|s| s.as_str()) == Some("rule-set")
                && toks.len() >= 7
                && toks[5] == "rule"
            {
                let name = PolicyDocument::sanitize_name(&unquote(&toks[6]));
                if !doc.nat_rules.iter().any(|n| n.name == name) {
                    doc.nat_rules.push(NatRule {
                        name: name.clone(),
                        nat_type: NatType::Source,
                        from_zones: vec!["any".into()],
                        to_zones: vec!["any".into()],
                        source: vec!["any".into()],
                        destination: vec!["any".into()],
                        service: vec!["any".into()],
                        translated_source: None,
                        translated_destination: None,
                        translated_service: None,
                        disabled: false,
                        description: Some(format!("junos rule-set {}", unquote(&toks[4]))),
                    });
                }
                let n = doc.nat_rules.iter_mut().find(|n| n.name == name).unwrap();
                if toks.get(7).map(|s| s.as_str()) == Some("match")
                    && toks.get(8).map(|s| s.as_str()) == Some("source-address-name")
                {
                    if let Some(v) = toks.get(9) {
                        n.source = vec![normalize(v)];
                    }
                }
                if toks.get(7).map(|s| s.as_str()) == Some("then")
                    && toks.get(8).map(|s| s.as_str()) == Some("source-nat")
                {
                    if toks.get(9).map(|s| s.as_str()) == Some("interface") {
                        n.translated_source = Some("egress_if".into());
                    } else if toks.get(9).map(|s| s.as_str()) == Some("pool") {
                        if let Some(p) = toks.get(10) {
                            n.translated_source = Some(normalize(p));
                        }
                    }
                }
            }
        }
    }

    Ok(doc)
}

fn normalize(s: &str) -> String {
    let u = unquote(s);
    if u.eq_ignore_ascii_case("any") || u.eq_ignore_ascii_case("any-ipv4") {
        "any".into()
    } else {
        PolicyDocument::sanitize_name(&u)
    }
}

/// Very small brace flattener: turns indented hierarchy into `set`-like paths.
fn flatten_hierarchy(text: &str) -> String {
    let mut out = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("set ") {
            continue;
        }
        if line == "}" {
            stack.pop();
            continue;
        }
        if let Some(rest) = line.strip_suffix('{') {
            let name = rest.trim().to_string();
            if !name.is_empty() {
                stack.push(name);
            }
            continue;
        }
        // leaf: word values
        let mut path = stack.clone();
        path.push(line.to_string());
        out.push(path.join(" "));
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_srx_set() {
        let sample = r#"
set system host-name srx-lab
set security address-book global address WEB 10.1.1.10/32
set security address-book global address USERS 10.0.0.0/24
set security address-book global address-set INTERNAL address WEB
set security address-book global address-set INTERNAL address USERS
set applications application HTTP-ALT protocol tcp destination-port 8080
set security policies from-zone TRUST to-zone UNTRUST policy ALLOW-WEB match source-address USERS
set security policies from-zone TRUST to-zone UNTRUST policy ALLOW-WEB match destination-address WEB
set security policies from-zone TRUST to-zone UNTRUST policy ALLOW-WEB match application HTTP-ALT
set security policies from-zone TRUST to-zone UNTRUST policy ALLOW-WEB then permit
set security nat source rule-set EGRESS rule SNAT1 match source-address-name USERS
set security nat source rule-set EGRESS rule SNAT1 then source-nat interface
"#;
        let doc = parse_junos(sample).unwrap();
        assert_eq!(doc.addresses.len(), 2);
        assert_eq!(doc.address_groups.len(), 1);
        assert_eq!(doc.services.len(), 1);
        assert_eq!(doc.security_rules.len(), 1);
        assert_eq!(doc.security_rules[0].action, RuleAction::Allow);
        assert_eq!(doc.nat_rules.len(), 1);
    }
}
