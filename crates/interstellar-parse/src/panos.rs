//! PAN-OS `running-config.xml` / candidate config reader → IR.

use anyhow::{Context, Result};
use interstellar_ir::{
    AddressGroup, AddressObject, AddressValue, IkeGateway, IpsecTunnel, NatRule, NatType,
    PolicyDocument, RuleAction, SecurityProfileGroup, SecurityRule, ServiceGroup, ServiceObject,
    ServiceValue, Vendor,
};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use std::collections::BTreeMap;

pub fn parse_panos(text: &str) -> Result<PolicyDocument> {
    let mut doc = PolicyDocument::new(Vendor::Panos);
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(true);

    let mut stack: Vec<String> = Vec::new();
    let mut buf = Vec::new();

    // Current object builders
    let mut entry_name = String::new();
    let mut text_buf = String::new();
    let mut members: Vec<String> = Vec::new();
    let mut in_member = false;
    let mut in_list_tag: Option<String> = None;

    // Address staging
    let mut addr_ip: Option<String> = None;
    let mut addr_fqdn: Option<String> = None;
    let mut addr_from: Option<String> = None;
    let mut addr_to: Option<String> = None;
    let mut addr_desc: Option<String> = None;

    // Service staging
    let mut svc_proto: Option<String> = None;
    let mut svc_port: Option<String> = None;
    let mut svc_desc: Option<String> = None;

    // Rule staging
    let mut rule_from: Vec<String> = Vec::new();
    let mut rule_to: Vec<String> = Vec::new();
    let mut rule_src: Vec<String> = Vec::new();
    let mut rule_dst: Vec<String> = Vec::new();
    let mut rule_app: Vec<String> = Vec::new();
    let mut rule_svc: Vec<String> = Vec::new();
    let mut rule_action: Option<String> = None;
    let mut rule_disabled = false;
    let mut rule_desc: Option<String> = None;
    let mut rule_profile_group: Option<String> = None;

    // NAT staging
    let mut nat_from: Vec<String> = Vec::new();
    let mut nat_to: Vec<String> = Vec::new();
    let mut nat_src: Vec<String> = Vec::new();
    let mut nat_dst: Vec<String> = Vec::new();
    let mut nat_svc: Vec<String> = Vec::new();
    let mut nat_tsrc: Option<String> = None;
    let mut nat_tdst: Option<String> = None;
    let mut nat_disabled = false;

    // VPN / profiles
    let mut ike_peer: Option<String> = None;
    let mut ipsec_gw: Option<String> = None;
    let mut pgrp: BTreeMap<String, String> = BTreeMap::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                let attrs: BTreeMap<String, String> = e
                    .attributes()
                    .flatten()
                    .filter_map(|a| {
                        let k = String::from_utf8_lossy(a.key.as_ref()).into_owned();
                        let v = String::from_utf8_lossy(&a.value).into_owned();
                        Some((k, v))
                    })
                    .collect();
                if name == "entry" {
                    if let Some(n) = attrs.get("name") {
                        entry_name = n.clone();
                    }
                    // reset staging depending on parent
                    let parent = stack.last().map(|s| s.as_str()).unwrap_or("");
                    match parent {
                        "address" => {
                            addr_ip = None;
                            addr_fqdn = None;
                            addr_from = None;
                            addr_to = None;
                            addr_desc = None;
                        }
                        "service" => {
                            svc_proto = None;
                            svc_port = None;
                            svc_desc = None;
                        }
                        "address-group" | "service-group" => {
                            members.clear();
                        }
                        "rules" => {
                            // distinguish security vs nat by deeper stack
                            if stack.iter().any(|s| s == "nat") {
                                nat_from.clear();
                                nat_to.clear();
                                nat_src.clear();
                                nat_dst.clear();
                                nat_svc.clear();
                                nat_tsrc = None;
                                nat_tdst = None;
                                nat_disabled = false;
                            } else {
                                rule_from.clear();
                                rule_to.clear();
                                rule_src.clear();
                                rule_dst.clear();
                                rule_app.clear();
                                rule_svc.clear();
                                rule_action = None;
                                rule_disabled = false;
                                rule_desc = None;
                                rule_profile_group = None;
                            }
                        }
                        "gateway" | "ike-gateway" => {
                            ike_peer = None;
                        }
                        "tunnel" | "ipsec-tunnel" => {
                            ipsec_gw = None;
                        }
                        "profile-group" => {
                            pgrp.clear();
                        }
                        _ => {}
                    }
                }
                if name == "member" {
                    in_member = true;
                    text_buf.clear();
                } else if matches!(name.as_str(), "tcp" | "udp")
                    && stack.iter().any(|s| s == "protocol" || s == "service")
                {
                    svc_proto = Some(name.clone());
                } else if matches!(
                    name.as_str(),
                    "ip-netmask"
                        | "fqdn"
                        | "ip-range"
                        | "description"
                        | "port"
                        | "action"
                        | "disabled"
                        | "translated-address"
                        | "ip"
                        | "gateway"
                        | "virus"
                        | "spyware"
                        | "vulnerability"
                        | "url-filtering"
                        | "file-blocking"
                        | "wildfire-analysis"
                ) {
                    text_buf.clear();
                    in_list_tag = Some(name.clone());
                }
                if name == "config" {
                    if let Some(v) = attrs.get("version") {
                        doc.source_version = Some(v.clone());
                    }
                }
                stack.push(name);
            }
            Ok(Event::End(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                if name == "member" && in_member {
                    let m = text_buf.trim().to_string();
                    if !m.is_empty() {
                        // attach to the nearest list context
                        let path = stack.join("/");
                        if path.contains("/from/") || path.ends_with("/from") {
                            // handled below via parent peek — use recent open lists
                        }
                        // Determine list by looking at parent before member was pushed
                        // stack currently ends with "member"
                        let parent = stack.get(stack.len().saturating_sub(2)).map(|s| s.as_str());
                        match parent {
                            Some("from") => {
                                if stack.iter().any(|s| s == "nat") {
                                    nat_from.push(m);
                                } else {
                                    rule_from.push(m);
                                }
                            }
                            Some("to") => {
                                if stack.iter().any(|s| s == "nat") {
                                    nat_to.push(m);
                                } else {
                                    rule_to.push(m);
                                }
                            }
                            Some("source") => {
                                if stack.iter().any(|s| s == "nat") {
                                    nat_src.push(m);
                                } else {
                                    rule_src.push(m);
                                }
                            }
                            Some("destination") => {
                                if stack.iter().any(|s| s == "nat") {
                                    nat_dst.push(m);
                                } else {
                                    rule_dst.push(m);
                                }
                            }
                            Some("service") => {
                                if stack.iter().any(|s| s == "nat") {
                                    nat_svc.push(m);
                                } else {
                                    rule_svc.push(m);
                                }
                            }
                            Some("application") => rule_app.push(m),
                            Some("translated-address") => {
                                if stack.iter().any(|s| s == "source-translation") {
                                    nat_tsrc = Some(m);
                                } else if stack.iter().any(|s| s == "destination-translation") {
                                    nat_tdst = Some(m);
                                } else {
                                    members.push(m);
                                }
                            }
                            Some("static") | Some("members") | Some("address-group")
                            | Some("service-group") => members.push(m),
                            Some("virus") | Some("spyware") | Some("vulnerability")
                            | Some("url-filtering") | Some("file-blocking")
                            | Some("wildfire-analysis") => {
                                let key = parent.unwrap_or("").to_string();
                                pgrp.insert(key, m);
                            }
                            Some("ike-gateway") => ipsec_gw = Some(m),
                            _ => members.push(m),
                        }
                    }
                    in_member = false;
                }

                if let Some(tag) = in_list_tag.clone() {
                    if name == tag {
                        let val = text_buf.trim().to_string();
                        match tag.as_str() {
                            "ip-netmask" => addr_ip = Some(val),
                            "fqdn" => addr_fqdn = Some(val),
                            "ip-range" => {
                                if let Some((a, b)) = val.split_once('-') {
                                    addr_from = Some(a.to_string());
                                    addr_to = Some(b.to_string());
                                }
                            }
                            "description" => {
                                if stack.iter().any(|s| s == "service") {
                                    svc_desc = Some(val);
                                } else if stack.iter().any(|s| s == "rules") {
                                    rule_desc = Some(val);
                                } else {
                                    addr_desc = Some(val);
                                }
                            }
                            "protocol" => svc_proto = Some(val),
                            "port" => svc_port = Some(val),
                            "action" => rule_action = Some(val),
                            "disabled" => {
                                let d = val.eq_ignore_ascii_case("yes");
                                if stack.iter().any(|s| s == "nat") {
                                    nat_disabled = d;
                                } else {
                                    rule_disabled = d;
                                }
                            }
                            "translated-address" => {
                                if stack.iter().any(|s| s == "source-translation") {
                                    nat_tsrc = Some(val);
                                } else {
                                    nat_tdst = Some(val);
                                }
                            }
                            "ip" => ike_peer = Some(val),
                            "gateway" => ipsec_gw = Some(val),
                            "virus" => {
                                pgrp.insert("virus".into(), val);
                            }
                            "spyware" => {
                                pgrp.insert("spyware".into(), val);
                            }
                            "vulnerability" => {
                                pgrp.insert("vulnerability".into(), val);
                            }
                            "url-filtering" => {
                                pgrp.insert("url-filtering".into(), val);
                            }
                            "file-blocking" => {
                                pgrp.insert("file-blocking".into(), val);
                            }
                            "wildfire-analysis" => {
                                pgrp.insert("wildfire".into(), val);
                            }
                            _ => {}
                        }
                        in_list_tag = None;
                    }
                }

                if name == "entry" && !entry_name.is_empty() {
                    let in_nat = stack.iter().any(|s| s == "nat");
                    let in_sec_rules = stack.iter().any(|s| s == "security")
                        || (stack.iter().any(|s| s == "rules") && !in_nat);
                    let parent_idx = stack.len().saturating_sub(2);
                    let parent = stack.get(parent_idx).map(|s| s.as_str()).unwrap_or("");

                    if parent == "address" || stack.iter().rev().nth(1) == Some(&"address".into()) {
                        let value = if let Some(fqdn) = addr_fqdn.take() {
                            AddressValue::Fqdn { value: fqdn }
                        } else if let (Some(from), Some(to)) = (addr_from.take(), addr_to.take()) {
                            AddressValue::IpRange { from, to }
                        } else {
                            AddressValue::IpNetmask {
                                value: addr_ip.take().unwrap_or_else(|| "0.0.0.0/0".into()),
                            }
                        };
                        doc.addresses.push(AddressObject {
                            name: PolicyDocument::sanitize_name(&entry_name),
                            value,
                            description: addr_desc.take(),
                            tags: vec![],
                        });
                    } else if parent == "address-group"
                        || stack.iter().rev().any(|s| s == "address-group")
                            && stack.iter().rev().take(3).any(|s| s == "address-group")
                    {
                        // Only commit when closing address-group entry
                        if stack.iter().filter(|s| s.as_str() == "address-group").count() >= 1
                            && !stack.iter().any(|s| s == "service-group")
                            && !in_sec_rules
                            && !in_nat
                            && parent == "address-group"
                        {
                            doc.address_groups.push(AddressGroup {
                                name: PolicyDocument::sanitize_name(&entry_name),
                                members: std::mem::take(&mut members),
                                description: None,
                            });
                        }
                    } else if parent == "service" {
                        let proto = svc_proto.take().unwrap_or_else(|| "tcp".into());
                        let port = svc_port.take().unwrap_or_else(|| "any".into());
                        let value = match proto.as_str() {
                            "udp" => ServiceValue::Udp { port },
                            "tcp" => ServiceValue::Tcp { port },
                            _ => ServiceValue::Tcp { port },
                        };
                        doc.services.push(ServiceObject {
                            name: PolicyDocument::sanitize_name(&entry_name),
                            value,
                            description: svc_desc.take(),
                        });
                    } else if parent == "service-group" {
                        doc.service_groups.push(ServiceGroup {
                            name: PolicyDocument::sanitize_name(&entry_name),
                            members: std::mem::take(&mut members),
                            description: None,
                        });
                    } else if parent == "rules" && in_nat {
                        doc.nat_rules.push(NatRule {
                            name: PolicyDocument::sanitize_name(&entry_name),
                            nat_type: if nat_tdst.is_some() {
                                NatType::Destination
                            } else if nat_tsrc.is_some() {
                                NatType::Source
                            } else {
                                NatType::Source
                            },
                            from_zones: nonempty(std::mem::take(&mut nat_from)),
                            to_zones: nonempty(std::mem::take(&mut nat_to)),
                            source: nonempty(std::mem::take(&mut nat_src)),
                            destination: nonempty(std::mem::take(&mut nat_dst)),
                            service: nonempty(std::mem::take(&mut nat_svc)),
                            translated_source: nat_tsrc.take(),
                            translated_destination: nat_tdst.take(),
                            translated_service: None,
                            disabled: nat_disabled,
                            description: None,
                        });
                    } else if parent == "rules" && !in_nat {
                        let action = match rule_action
                            .take()
                            .unwrap_or_else(|| "allow".into())
                            .to_ascii_lowercase()
                            .as_str()
                        {
                            "deny" => RuleAction::Deny,
                            "drop" => RuleAction::Drop,
                            "reset-client" => RuleAction::ResetClient,
                            "reset-server" => RuleAction::ResetServer,
                            "reset-both" => RuleAction::ResetBoth,
                            _ => RuleAction::Allow,
                        };
                        doc.security_rules.push(SecurityRule {
                            name: PolicyDocument::sanitize_name(&entry_name),
                            from_zones: nonempty(std::mem::take(&mut rule_from)),
                            to_zones: nonempty(std::mem::take(&mut rule_to)),
                            source: nonempty(std::mem::take(&mut rule_src)),
                            destination: nonempty(std::mem::take(&mut rule_dst)),
                            application: nonempty_app(std::mem::take(&mut rule_app)),
                            service: nonempty(std::mem::take(&mut rule_svc)),
                            action,
                            disabled: rule_disabled,
                            log_start: false,
                            log_end: true,
                            description: rule_desc.take(),
                            tags: vec![],
                            profile_group: rule_profile_group.take(),
                            profiles: Default::default(),
                        });
                    } else if parent == "gateway" || parent == "ike-gateway" {
                        doc.ike_gateways.push(IkeGateway {
                            name: PolicyDocument::sanitize_name(&entry_name),
                            peer_ip: ike_peer.take().unwrap_or_else(|| "0.0.0.0".into()),
                            local_ip: None,
                            pre_shared_key: None,
                            ike_version: "ikev2".into(),
                        });
                    } else if parent == "tunnel" || parent == "ipsec-tunnel" {
                        doc.ipsec_tunnels.push(IpsecTunnel {
                            name: PolicyDocument::sanitize_name(&entry_name),
                            ike_gateway: ipsec_gw
                                .take()
                                .map(|s| PolicyDocument::sanitize_name(&s))
                                .unwrap_or_default(),
                            tunnel_interface: None,
                            proxy_ids: vec![],
                        });
                    } else if parent == "profile-group" {
                        doc.profile_groups.push(SecurityProfileGroup {
                            name: PolicyDocument::sanitize_name(&entry_name),
                            virus: pgrp.remove("virus"),
                            spyware: pgrp.remove("spyware"),
                            vulnerability: pgrp.remove("vulnerability"),
                            url_filtering: pgrp.remove("url-filtering"),
                            file_blocking: pgrp.remove("file-blocking"),
                            wildfire: pgrp.remove("wildfire"),
                        });
                    }
                    entry_name.clear();
                }

                if stack.last().map(|s| s.as_str()) == Some(name.as_str()) {
                    stack.pop();
                } else if let Some(pos) = stack.iter().rposition(|s| s == &name) {
                    stack.truncate(pos);
                }
            }
            Ok(Event::Text(t)) => {
                let t = t
                    .unescape()
                    .map(|c| c.into_owned())
                    .unwrap_or_else(|_| String::from_utf8_lossy(t.as_ref()).into_owned());
                if in_member || in_list_tag.is_some() {
                    text_buf.push_str(&t);
                }
            }
            Ok(Event::Empty(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                if name == "member" {
                    // unlikely
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(e).context("panos xml"),
            _ => {}
        }
        buf.clear();
    }

    Ok(doc)
}

fn nonempty(v: Vec<String>) -> Vec<String> {
    if v.is_empty() {
        vec!["any".into()]
    } else {
        v
    }
}

fn nonempty_app(v: Vec<String>) -> Vec<String> {
    if v.is_empty() {
        vec!["any".into()]
    } else {
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_panos() {
        let sample = r#"<?xml version="1.0"?>
<config version="11.1.0">
  <shared>
    <address>
      <entry name="web">
        <ip-netmask>10.1.1.10/32</ip-netmask>
      </entry>
    </address>
    <service>
      <entry name="tcp-8080">
        <protocol><tcp><port>8080</port></tcp></protocol>
      </entry>
    </service>
    <address-group>
      <entry name="webs">
        <static><member>web</member></static>
      </entry>
    </address-group>
  </shared>
  <devices>
    <entry name="localhost.localdomain">
      <vsys>
        <entry name="vsys1">
          <rulebase>
            <security>
              <rules>
                <entry name="allow-web">
                  <from><member>any</member></from>
                  <to><member>any</member></to>
                  <source><member>any</member></source>
                  <destination><member>web</member></destination>
                  <application><member>any</member></application>
                  <service><member>tcp-8080</member></service>
                  <action>allow</action>
                </entry>
              </rules>
            </security>
          </rulebase>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>"#;
        let doc = parse_panos(sample).unwrap();
        assert_eq!(doc.addresses.len(), 1);
        assert_eq!(doc.security_rules.len(), 1);
        assert_eq!(doc.security_rules[0].action, RuleAction::Allow);
    }
}
