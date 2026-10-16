//! Cisco ASA / IOS-style ACL and object parser.

use crate::util::{tokenize, unquote};
use anyhow::Result;
use interstellar_ir::{
    AddressGroup, AddressObject, AddressValue, NatRule, NatType, PolicyDocument, RuleAction,
    SecurityRule, ServiceGroup, ServiceObject, ServiceValue, Vendor,
};
use std::collections::BTreeMap;

pub fn parse_cisco(text: &str) -> Result<PolicyDocument> {
    let mut doc = PolicyDocument::new(Vendor::Cisco);
    let mut obj_network: Option<AddressObject> = None;
    let mut obj_service: Option<ServiceObject> = None;
    let mut grp_network: Option<AddressGroup> = None;
    let mut grp_service: Option<ServiceGroup> = None;
    let mut acl_counts: BTreeMap<String, usize> = BTreeMap::new();

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('!') {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("asa version") || lower.starts_with("pix version") {
            doc.source_version = Some(line.to_string());
            continue;
        }

        let toks = tokenize(line);
        if toks.is_empty() {
            continue;
        }
        let head = toks[0].to_ascii_lowercase();

        // Close previous object when a new top-level starts
        let is_top = matches!(
            head.as_str(),
            "object" | "object-group" | "access-list" | "nat" | "hostname"
        );

        if is_top {
            flush_cisco(
                &mut doc,
                &mut obj_network,
                &mut obj_service,
                &mut grp_network,
                &mut grp_service,
            );
        }

        match head.as_str() {
            "hostname" => {
                if toks.len() > 1 {
                    doc.source_name = Some(unquote(&toks[1]));
                }
            }
            "object" if toks.len() >= 3 => {
                let kind = toks[1].to_ascii_lowercase();
                let name = PolicyDocument::sanitize_name(&unquote(&toks[2]));
                match kind.as_str() {
                    "network" => {
                        obj_network = Some(AddressObject {
                            name,
                            value: AddressValue::IpNetmask {
                                value: "0.0.0.0/0".into(),
                            },
                            description: None,
                            tags: vec![],
                        });
                    }
                    "service" => {
                        obj_service = Some(ServiceObject {
                            name,
                            value: ServiceValue::Any,
                            description: None,
                        });
                    }
                    _ => {
                        doc.warnings
                            .push(format!("unsupported object kind: {kind}"));
                    }
                }
            }
            "subnet" | "host" | "range" | "fqdn" if obj_network.is_some() => {
                if let Some(a) = obj_network.as_mut() {
                    match head.as_str() {
                        "host" if toks.len() >= 2 => {
                            a.value = AddressValue::IpNetmask {
                                value: format!("{}/32", toks[1]),
                            };
                        }
                        "subnet" if toks.len() >= 3 => {
                            a.value = AddressValue::IpNetmask {
                                value: format!("{}/{}", toks[1], toks[2]),
                            };
                        }
                        "range" if toks.len() >= 3 => {
                            a.value = AddressValue::IpRange {
                                from: toks[1].clone(),
                                to: toks[2].clone(),
                            };
                        }
                        "fqdn" if toks.len() >= 2 => {
                            let v = if toks[1].eq_ignore_ascii_case("v4")
                                || toks[1].eq_ignore_ascii_case("v6")
                            {
                                toks.get(2).cloned().unwrap_or_default()
                            } else {
                                toks[1].clone()
                            };
                            a.value = AddressValue::Fqdn { value: v };
                        }
                        _ => {}
                    }
                }
            }
            "service" if obj_service.is_some() && toks.len() >= 3 => {
                if let Some(s) = obj_service.as_mut() {
                    let proto = toks[1].to_ascii_lowercase();
                    // service tcp destination eq 443
                    let port = toks
                        .iter()
                        .skip(2)
                        .find(|t| t.chars().all(|c| c.is_ascii_digit() || c == '-'))
                        .cloned()
                        .unwrap_or_else(|| "any".into());
                    s.value = match proto.as_str() {
                        "tcp" => ServiceValue::Tcp { port },
                        "udp" => ServiceValue::Udp { port },
                        "tcp-udp" => ServiceValue::TcpUdp { port },
                        _ => ServiceValue::Any,
                    };
                }
            }
            "object-group" if toks.len() >= 3 => {
                let kind = toks[1].to_ascii_lowercase();
                let name = PolicyDocument::sanitize_name(&unquote(&toks[2]));
                match kind.as_str() {
                    "network" => {
                        grp_network = Some(AddressGroup {
                            name,
                            members: vec![],
                            description: None,
                        });
                    }
                    "service" => {
                        grp_service = Some(ServiceGroup {
                            name,
                            members: vec![],
                            description: None,
                        });
                    }
                    _ => {}
                }
            }
            "network-object" if grp_network.is_some() => {
                if let Some(g) = grp_network.as_mut() {
                    if toks.len() >= 3 && toks[1].eq_ignore_ascii_case("object") {
                        g.members
                            .push(PolicyDocument::sanitize_name(&unquote(&toks[2])));
                    } else if toks.len() >= 3 && toks[1].eq_ignore_ascii_case("host") {
                        let host = toks[2].clone();
                        let n = PolicyDocument::sanitize_name(&format!("host_{host}"));
                        doc.addresses.push(AddressObject {
                            name: n.clone(),
                            value: AddressValue::IpNetmask {
                                value: format!("{host}/32"),
                            },
                            description: None,
                            tags: vec![],
                        });
                        g.members.push(n);
                    } else if toks.len() >= 3 {
                        let n = PolicyDocument::sanitize_name(&format!(
                            "net_{}_{}",
                            toks[1].replace('.', "_"),
                            toks[2].replace('.', "_")
                        ));
                        doc.addresses.push(AddressObject {
                            name: n.clone(),
                            value: AddressValue::IpNetmask {
                                value: format!("{}/{}", toks[1], toks[2]),
                            },
                            description: None,
                            tags: vec![],
                        });
                        g.members.push(n);
                    }
                }
            }
            "service-object" | "port-object" if grp_service.is_some() => {
                if let Some(g) = grp_service.as_mut() {
                    if toks.len() >= 3 && toks[1].eq_ignore_ascii_case("object") {
                        g.members
                            .push(PolicyDocument::sanitize_name(&unquote(&toks[2])));
                    } else if toks.len() >= 3 {
                        let proto = toks[1].to_ascii_lowercase();
                        let port = toks.last().cloned().unwrap_or_else(|| "any".into());
                        let n = PolicyDocument::sanitize_name(&format!("{proto}_{port}"));
                        doc.services.push(ServiceObject {
                            name: n.clone(),
                            value: match proto.as_str() {
                                "udp" => ServiceValue::Udp { port },
                                "tcp-udp" => ServiceValue::TcpUdp { port },
                                _ => ServiceValue::Tcp { port },
                            },
                            description: None,
                        });
                        g.members.push(n);
                    }
                }
            }
            "group-object" => {
                if toks.len() >= 2 {
                    let member = PolicyDocument::sanitize_name(&unquote(&toks[1]));
                    if let Some(g) = grp_network.as_mut() {
                        g.members.push(member);
                    } else if let Some(g) = grp_service.as_mut() {
                        g.members.push(member);
                    }
                }
            }
            "access-list" if toks.len() >= 4 => {
                // access-list OUT extended permit tcp object A object B eq 443
                let acl_name = PolicyDocument::sanitize_name(&toks[1]);
                let idx = acl_counts.entry(acl_name.clone()).or_insert(0);
                *idx += 1;
                let n = *idx;

                let mut i = 2usize;
                let mut extended = false;
                if toks[i].eq_ignore_ascii_case("extended") {
                    extended = true;
                    i += 1;
                } else if toks[i].eq_ignore_ascii_case("standard") {
                    i += 1;
                }
                if i >= toks.len() {
                    continue;
                }
                let action = match toks[i].to_ascii_lowercase().as_str() {
                    "permit" => RuleAction::Allow,
                    "deny" => RuleAction::Deny,
                    _ => continue,
                };
                i += 1;

                let mut service = vec!["any".into()];
                let mut source = vec!["any".into()];
                let mut destination = vec!["any".into()];

                if extended && i < toks.len() {
                    let proto = toks[i].to_ascii_lowercase();
                    i += 1;
                    if proto != "ip" && proto != "any" {
                        if proto == "object" && i < toks.len() {
                            service = vec![PolicyDocument::sanitize_name(&toks[i])];
                            i += 1;
                        } else if proto == "object-group" && i < toks.len() {
                            service = vec![PolicyDocument::sanitize_name(&toks[i])];
                            i += 1;
                        } else if proto == "tcp" || proto == "udp" {
                            // will attach port later if eq present
                            service = vec![proto.clone()];
                        } else {
                            service = vec![proto];
                        }
                    }
                    if let Some((s, ni)) = parse_acl_addr(&toks, i) {
                        source = s;
                        i = ni;
                    }
                    if let Some((d, ni)) = parse_acl_addr(&toks, i) {
                        destination = d;
                        i = ni;
                    }
                    // eq PORT at end
                    if i < toks.len() && toks[i].eq_ignore_ascii_case("eq") && i + 1 < toks.len() {
                        let port = toks[i + 1].clone();
                        if service.len() == 1 && (service[0] == "tcp" || service[0] == "udp") {
                            let proto = service[0].clone();
                            let svc_name =
                                PolicyDocument::sanitize_name(&format!("{proto}_{port}"));
                            doc.services.push(ServiceObject {
                                name: svc_name.clone(),
                                value: if proto == "udp" {
                                    ServiceValue::Udp { port }
                                } else {
                                    ServiceValue::Tcp { port }
                                },
                                description: None,
                            });
                            service = vec![svc_name];
                        }
                    }
                } else if i < toks.len() {
                    // standard ACL
                    if let Some((s, _)) = parse_acl_addr(&toks, i) {
                        source = s;
                    }
                }

                doc.security_rules.push(SecurityRule {
                    name: format!("{acl_name}_{n}"),
                    from_zones: vec!["any".into()],
                    to_zones: vec!["any".into()],
                    source,
                    destination,
                    application: vec!["any".into()],
                    service,
                    action,
                    disabled: false,
                    log_start: false,
                    log_end: true,
                    description: Some(format!("from ACL {acl_name}")),
                    tags: vec!["cisco-acl".into()],
                    profile_group: None,
                    profiles: Default::default(),
                });
            }
            "nat" if toks.len() >= 3 => {
                // nat (inside,outside) source static obj1 obj2
                let name = format!("nat_{}", doc.nat_rules.len() + 1);
                let mut nat = NatRule {
                    name,
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
                    description: Some(line.to_string()),
                };
                if let Some(paren) = toks.iter().find(|t| t.starts_with('(')) {
                    let zones = paren.trim_matches(|c| c == '(' || c == ')');
                    let parts: Vec<_> = zones.split(',').map(|s| s.trim().to_string()).collect();
                    if parts.len() == 2 {
                        nat.from_zones = vec![PolicyDocument::sanitize_name(&parts[0])];
                        nat.to_zones = vec![PolicyDocument::sanitize_name(&parts[1])];
                    }
                }
                if lower.contains("destination") {
                    nat.nat_type = NatType::Destination;
                } else if lower.contains("static") {
                    nat.nat_type = NatType::Static;
                }
                // crude object capture
                if let Some(pos) = toks.iter().position(|t| t.eq_ignore_ascii_case("static")) {
                    if toks.len() > pos + 2 {
                        nat.source = vec![PolicyDocument::sanitize_name(&toks[pos + 1])];
                        nat.translated_source =
                            Some(PolicyDocument::sanitize_name(&toks[pos + 2]));
                    }
                } else if let Some(pos) = toks.iter().position(|t| t.eq_ignore_ascii_case("dynamic"))
                {
                    if toks.len() > pos + 2 {
                        nat.source = vec![PolicyDocument::sanitize_name(&toks[pos + 1])];
                        nat.translated_source =
                            Some(PolicyDocument::sanitize_name(&toks[pos + 2]));
                    }
                }
                doc.nat_rules.push(nat);
            }
            _ => {
                // continuation lines for object-group already handled via network-object
            }
        }
    }

    flush_cisco(
        &mut doc,
        &mut obj_network,
        &mut obj_service,
        &mut grp_network,
        &mut grp_service,
    );
    Ok(doc)
}

fn flush_cisco(
    doc: &mut PolicyDocument,
    obj_network: &mut Option<AddressObject>,
    obj_service: &mut Option<ServiceObject>,
    grp_network: &mut Option<AddressGroup>,
    grp_service: &mut Option<ServiceGroup>,
) {
    if let Some(a) = obj_network.take() {
        doc.addresses.push(a);
    }
    if let Some(s) = obj_service.take() {
        doc.services.push(s);
    }
    if let Some(g) = grp_network.take() {
        doc.address_groups.push(g);
    }
    if let Some(g) = grp_service.take() {
        doc.service_groups.push(g);
    }
}

fn parse_acl_addr(toks: &[String], i: usize) -> Option<(Vec<String>, usize)> {
    if i >= toks.len() {
        return None;
    }
    let t = toks[i].to_ascii_lowercase();
    match t.as_str() {
        "any" | "any4" | "any6" => Some((vec!["any".into()], i + 1)),
        "host" if i + 1 < toks.len() => {
            let host = &toks[i + 1];
            Some((
                vec![PolicyDocument::sanitize_name(&format!("host_{host}"))],
                i + 2,
            ))
        }
        "object" | "object-group" if i + 1 < toks.len() => Some((
            vec![PolicyDocument::sanitize_name(&toks[i + 1])],
            i + 2,
        )),
        _ if t.contains('.') => {
            // ip mask
            if i + 1 < toks.len() {
                Some((
                    vec![PolicyDocument::sanitize_name(&format!(
                        "net_{}",
                        toks[i].replace('.', "_")
                    ))],
                    i + 2,
                ))
            } else {
                Some((vec![PolicyDocument::sanitize_name(&toks[i])], i + 1))
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_asa_objects_and_acl() {
        let sample = r#"
ASA Version 9.12(4)
hostname fw1
object network WEB
 host 10.1.1.10
object network USERS
 subnet 10.0.0.0 255.255.255.0
object-group network INTERNAL
 network-object object USERS
 network-object object WEB
object service HTTPS
 service tcp destination eq 443
access-list OUTSIDE_IN extended permit tcp object USERS object WEB eq 443
access-list OUTSIDE_IN extended deny ip any any
nat (inside,outside) source static USERS USERS
"#;
        let doc = parse_cisco(sample).unwrap();
        assert!(doc.addresses.len() >= 2);
        assert_eq!(doc.address_groups.len(), 1);
        assert!(!doc.security_rules.is_empty());
        assert_eq!(doc.security_rules[0].action, RuleAction::Allow);
        assert!(!doc.nat_rules.is_empty());
    }
}
