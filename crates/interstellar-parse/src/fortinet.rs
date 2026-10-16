//! FortiGate `config ...` / `edit` / `set` / `next` / `end` parser.

use crate::util::{tokenize, unquote};
use anyhow::Result;
use interstellar_ir::{
    AddressGroup, AddressObject, AddressValue, IkeGateway, IpsecTunnel, NatRule, NatType,
    PolicyDocument, RuleAction, SecurityProfileGroup, SecurityRule, ServiceGroup, ServiceObject,
    ServiceValue, Vendor,
};

#[derive(Debug, Clone)]
enum Block {
    Address,
    AddrGrp,
    Service,
    ServiceGrp,
    Policy,
    Vip,
    IpPool,
    VpnIpsecPhase1,
    VpnIpsecPhase2,
    ProfileGroup,
    Other,
}

fn normalize_forti_any(s: &str) -> String {
    if s.eq_ignore_ascii_case("all") || s.eq_ignore_ascii_case("any") {
        "any".into()
    } else {
        PolicyDocument::sanitize_name(s)
    }
}

pub fn parse_fortinet(text: &str) -> Result<PolicyDocument> {
    let mut doc = PolicyDocument::new(Vendor::Fortinet);
    let mut stack: Vec<Block> = Vec::new();
    let mut current_name: Option<String> = None;

    // Staging objects
    let mut addr: Option<AddressObject> = None;
    let mut agrp: Option<AddressGroup> = None;
    let mut svc: Option<ServiceObject> = None;
    let mut sgrp: Option<ServiceGroup> = None;
    let mut rule: Option<SecurityRule> = None;
    let mut nat: Option<NatRule> = None;
    let mut ike: Option<IkeGateway> = None;
    let mut ipsec: Option<IpsecTunnel> = None;
    let mut pgrp: Option<SecurityProfileGroup> = None;
    let mut svc_proto: Option<String> = None;
    let mut svc_tcp: Option<String> = None;
    let mut svc_udp: Option<String> = None;

    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            if line.starts_with("#config-version=") {
                doc.source_version = Some(line.trim_start_matches("#config-version=").to_string());
            }
            continue;
        }
        let toks = tokenize(line);
        if toks.is_empty() {
            continue;
        }

        match toks[0].as_str() {
            "config" => {
                let path = toks[1..].join(" ").to_ascii_lowercase();
                let block = match path.as_str() {
                    "firewall address" => Block::Address,
                    "firewall addrgrp" => Block::AddrGrp,
                    "firewall service custom" => Block::Service,
                    "firewall service group" => Block::ServiceGrp,
                    "firewall policy" => Block::Policy,
                    "firewall vip" => Block::Vip,
                    "firewall ippool" => Block::IpPool,
                    "vpn ipsec phase1-interface" | "vpn ipsec phase1" => Block::VpnIpsecPhase1,
                    "vpn ipsec phase2-interface" | "vpn ipsec phase2" => Block::VpnIpsecPhase2,
                    "firewall profile-group" | "firewall profile group" => Block::ProfileGroup,
                    _ => Block::Other,
                };
                stack.push(block);
            }
            "edit" => {
                let name = PolicyDocument::sanitize_name(&unquote(
                    &toks.get(1).cloned().unwrap_or_else(|| format!("obj_{lineno}")),
                ));
                current_name = Some(name.clone());
                match stack.last() {
                    Some(Block::Address) => {
                        addr = Some(AddressObject {
                            name,
                            value: AddressValue::IpNetmask {
                                value: "0.0.0.0/0".into(),
                            },
                            description: None,
                            tags: vec![],
                        });
                    }
                    Some(Block::AddrGrp) => {
                        agrp = Some(AddressGroup {
                            name,
                            members: vec![],
                            description: None,
                        });
                    }
                    Some(Block::Service) => {
                        svc_proto = None;
                        svc_tcp = None;
                        svc_udp = None;
                        svc = Some(ServiceObject {
                            name,
                            value: ServiceValue::Any,
                            description: None,
                        });
                    }
                    Some(Block::ServiceGrp) => {
                        sgrp = Some(ServiceGroup {
                            name,
                            members: vec![],
                            description: None,
                        });
                    }
                    Some(Block::Policy) => {
                        rule = Some(SecurityRule {
                            name: format!("rule_{name}"),
                            from_zones: vec!["any".into()],
                            to_zones: vec!["any".into()],
                            source: vec!["any".into()],
                            destination: vec!["any".into()],
                            application: vec!["any".into()],
                            service: vec!["any".into()],
                            action: RuleAction::Deny,
                            disabled: false,
                            log_start: false,
                            log_end: true,
                            description: None,
                            tags: vec![],
                            profile_group: None,
                            profiles: Default::default(),
                        });
                    }
                    Some(Block::Vip) => {
                        nat = Some(NatRule {
                            name: format!("vip_{name}"),
                            nat_type: NatType::Destination,
                            from_zones: vec!["any".into()],
                            to_zones: vec!["any".into()],
                            source: vec!["any".into()],
                            destination: vec![name.clone()],
                            service: vec!["any".into()],
                            translated_source: None,
                            translated_destination: None,
                            translated_service: None,
                            disabled: false,
                            description: None,
                        });
                        // Also create address for the VIP external IP later via set
                        addr = Some(AddressObject {
                            name,
                            value: AddressValue::IpNetmask {
                                value: "0.0.0.0/32".into(),
                            },
                            description: Some("fortinet vip".into()),
                            tags: vec!["vip".into()],
                        });
                    }
                    Some(Block::IpPool) => {
                        addr = Some(AddressObject {
                            name: format!("ippool_{name}"),
                            value: AddressValue::IpNetmask {
                                value: "0.0.0.0/32".into(),
                            },
                            description: Some("fortinet ippool".into()),
                            tags: vec!["ippool".into()],
                        });
                        nat = Some(NatRule {
                            name: format!("snat_{name}"),
                            nat_type: NatType::Source,
                            from_zones: vec!["any".into()],
                            to_zones: vec!["any".into()],
                            source: vec!["any".into()],
                            destination: vec!["any".into()],
                            service: vec!["any".into()],
                            translated_source: Some(format!("ippool_{name}")),
                            translated_destination: None,
                            translated_service: None,
                            disabled: false,
                            description: None,
                        });
                    }
                    Some(Block::VpnIpsecPhase1) => {
                        ike = Some(IkeGateway {
                            name,
                            peer_ip: "0.0.0.0".into(),
                            local_ip: None,
                            pre_shared_key: None,
                            ike_version: "ikev1".into(),
                        });
                    }
                    Some(Block::VpnIpsecPhase2) => {
                        ipsec = Some(IpsecTunnel {
                            name,
                            ike_gateway: String::new(),
                            tunnel_interface: None,
                            proxy_ids: vec![],
                        });
                    }
                    Some(Block::ProfileGroup) => {
                        pgrp = Some(SecurityProfileGroup {
                            name,
                            virus: None,
                            spyware: None,
                            vulnerability: None,
                            url_filtering: None,
                            file_blocking: None,
                            wildfire: None,
                        });
                    }
                    _ => {}
                }
            }
            "set" => {
                if toks.len() < 2 {
                    continue;
                }
                let key = toks[1].as_str();
                let vals: Vec<String> = toks[2..].iter().map(|s| unquote(s)).collect();
                let joined = vals.join(" ");
                let j = || joined.clone();
                let vs = || vals.clone();

                if let Some(a) = addr.as_mut() {
                    match key {
                        "subnet" => {
                            if vals.len() >= 2 {
                                a.value = AddressValue::IpNetmask {
                                    value: format!("{}/{}", vals[0], vals[1]),
                                };
                            } else if vals.len() == 1 {
                                a.value = AddressValue::IpNetmask {
                                    value: vals[0].clone(),
                                };
                            }
                        }
                        "type" if joined == "fqdn" => {}
                        "fqdn" => {
                            a.value = AddressValue::Fqdn { value: j() };
                        }
                        "start-ip" | "end-ip" => {
                            // range handled in pairs — stash in description then fix on next
                            if key == "start-ip" {
                                a.value = AddressValue::IpRange {
                                    from: j(),
                                    to: String::new(),
                                };
                            } else if let AddressValue::IpRange { from, to } = &mut a.value {
                                *to = j();
                                let _ = from;
                            }
                        }
                        "extip" => {
                            a.value = AddressValue::IpNetmask {
                                value: if joined.contains('/') {
                                    j()
                                } else {
                                    format!("{}/32", joined)
                                },
                            };
                        }
                        "mappedip" | "mapped-addr" => {
                            if let Some(n) = nat.as_mut() {
                                n.translated_destination = Some(PolicyDocument::sanitize_name(&joined));
                            }
                        }
                        "comment" | "description" => a.description = Some(j()),
                        "startip" => {
                            a.value = AddressValue::IpRange {
                                from: j(),
                                to: String::new(),
                            };
                        }
                        "endip" => {
                            if let AddressValue::IpRange { to, .. } = &mut a.value {
                                *to = j();
                            }
                        }
                        _ => {}
                    }
                }
                if let Some(g) = agrp.as_mut() {
                    if key == "member" {
                        g.members = vs()
                            .into_iter()
                            .map(|m| PolicyDocument::sanitize_name(&m))
                            .collect();
                    } else if key == "comment" {
                        g.description = Some(j());
                    }
                }
                if let Some(s) = svc.as_mut() {
                    match key {
                        "protocol" => svc_proto = Some(j().to_ascii_lowercase()),
                        "tcp-portrange" => svc_tcp = Some(j().replace(' ', ",")),
                        "udp-portrange" => svc_udp = Some(j().replace(' ', ",")),
                        "comment" => s.description = Some(j()),
                        _ => {}
                    }
                }
                if let Some(g) = sgrp.as_mut() {
                    if key == "member" {
                        g.members = vs()
                            .into_iter()
                            .map(|m| PolicyDocument::sanitize_name(&m))
                            .collect();
                    }
                }
                if let Some(r) = rule.as_mut() {
                    match key {
                        "name" => r.name = PolicyDocument::sanitize_name(&joined),
                        "srcintf" => {
                            r.from_zones = vals
                                .iter()
                                .map(|z| PolicyDocument::sanitize_name(z))
                                .collect()
                        }
                        "dstintf" => {
                            r.to_zones = vals
                                .iter()
                                .map(|z| PolicyDocument::sanitize_name(z))
                                .collect()
                        }
                        "srcaddr" => {
                            r.source = vals.iter().map(|z| normalize_forti_any(z)).collect()
                        }
                        "dstaddr" => {
                            r.destination = vals.iter().map(|z| normalize_forti_any(z)).collect()
                        }
                        "service" => {
                            r.service = vals.iter().map(|z| normalize_forti_any(z)).collect()
                        }
                        "action" => {
                            r.action = match joined.to_ascii_lowercase().as_str() {
                                "accept" => RuleAction::Allow,
                                "deny" => RuleAction::Deny,
                                _ => RuleAction::Drop,
                            }
                        }
                        "status" => r.disabled = joined.eq_ignore_ascii_case("disable"),
                        "comments" | "comment" => r.description = Some(j()),
                        "utm-status" if joined.eq_ignore_ascii_case("enable") => {}
                        "profile-group" => {
                            r.profile_group = Some(PolicyDocument::sanitize_name(&joined))
                        }
                        "av-profile" => {
                            r.profiles.insert("virus".into(), j());
                        }
                        "ips-sensor" => {
                            r.profiles.insert("vulnerability".into(), j());
                        }
                        "webfilter-profile" => {
                            r.profiles.insert("url-filtering".into(), j());
                        }
                        _ => {}
                    }
                }
                if let Some(n) = nat.as_mut() {
                    match key {
                        "extintf" => {
                            n.to_zones = vec![PolicyDocument::sanitize_name(&joined)];
                        }
                        "comment" => n.description = Some(j()),
                        _ => {}
                    }
                }
                if let Some(g) = ike.as_mut() {
                    match key {
                        "remote-gw" | "peertype" => {
                            if key == "remote-gw" {
                                g.peer_ip = j();
                            }
                        }
                        "psksecret" => g.pre_shared_key = Some(j()),
                        "ike-version" => g.ike_version = format!("ikev{joined}"),
                        "interface" => g.local_ip = Some(j()),
                        _ => {}
                    }
                }
                if let Some(t) = ipsec.as_mut() {
                    match key {
                        "phase1name" => t.ike_gateway = PolicyDocument::sanitize_name(&joined),
                        "src-subnet" | "dst-subnet" => t.proxy_ids.push(j()),
                        _ => {}
                    }
                }
                if let Some(p) = pgrp.as_mut() {
                    match key {
                        "av-profile" => p.virus = Some(j()),
                        "ips-sensor" => p.vulnerability = Some(j()),
                        "webfilter-profile" => p.url_filtering = Some(j()),
                        "dnsfilter-profile" => {}
                        "application-list" => {}
                        "ssl-ssh-profile" => {}
                        _ => {}
                    }
                }
            }
            "next" | "end" => {
                // finalize current edit on next; end pops config
                if toks[0] == "next" || (toks[0] == "end" && current_name.is_some()) {
                    if let Some(mut s) = svc.take() {
                        s.value = match (
                            svc_proto.as_deref(),
                            svc_tcp.as_ref(),
                            svc_udp.as_ref(),
                        ) {
                            (_, Some(t), Some(u)) if t == u => ServiceValue::TcpUdp {
                                port: t.clone(),
                            },
                            (_, Some(t), Some(_)) => {
                                doc.warnings.push(format!(
                                    "service {} has both tcp/udp ranges; emitting TCP",
                                    s.name
                                ));
                                ServiceValue::Tcp { port: t.clone() }
                            }
                            (_, Some(t), None) => ServiceValue::Tcp { port: t.clone() },
                            (_, None, Some(u)) => ServiceValue::Udp { port: u.clone() },
                            (Some("ip"), _, _) => ServiceValue::Any,
                            _ => ServiceValue::Any,
                        };
                        doc.services.push(s);
                    }
                    if let Some(a) = addr.take() {
                        doc.addresses.push(a);
                    }
                    if let Some(g) = agrp.take() {
                        doc.address_groups.push(g);
                    }
                    if let Some(g) = sgrp.take() {
                        doc.service_groups.push(g);
                    }
                    if let Some(r) = rule.take() {
                        doc.security_rules.push(r);
                    }
                    if let Some(n) = nat.take() {
                        doc.nat_rules.push(n);
                    }
                    if let Some(g) = ike.take() {
                        doc.ike_gateways.push(g);
                    }
                    if let Some(t) = ipsec.take() {
                        doc.ipsec_tunnels.push(t);
                    }
                    if let Some(p) = pgrp.take() {
                        doc.profile_groups.push(p);
                    }
                    current_name = None;
                    svc_proto = None;
                    svc_tcp = None;
                    svc_udp = None;
                }
                if toks[0] == "end" {
                    stack.pop();
                }
            }
            _ => {}
        }
    }

    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_fortigate() {
        let sample = r#"
#config-version=FG100F-7.4.4-FW-build2662-240514:opmode=0:vdom=0
config firewall address
    edit "Web_Server"
        set subnet 10.1.1.10 255.255.255.255
    next
    edit "Corp_Users"
        set subnet 10.0.0.0 255.255.255.0
    next
end
config firewall addrgrp
    edit "Internal"
        set member "Corp_Users" "Web_Server"
    next
end
config firewall service custom
    edit "HTTP_ALT"
        set tcp-portrange 8080
    next
end
config firewall policy
    edit 1
        set name "Allow_Web"
        set srcintf "internal"
        set dstintf "wan1"
        set srcaddr "Corp_Users"
        set dstaddr "Web_Server"
        set action accept
        set service "HTTP_ALT" "ALL"
        set schedule "always"
    next
end
"#;
        let doc = parse_fortinet(sample).unwrap();
        assert_eq!(doc.addresses.len(), 2);
        assert_eq!(doc.address_groups.len(), 1);
        assert_eq!(doc.services.len(), 1);
        assert_eq!(doc.security_rules.len(), 1);
        assert_eq!(doc.security_rules[0].action, RuleAction::Allow);
    }
}
