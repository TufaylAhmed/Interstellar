//! Check Point parser — JSON management export and simple `set` style text.

use crate::util::{tokenize, unquote};
use anyhow::{Context, Result};
use interstellar_ir::{
    AddressGroup, AddressObject, AddressValue, NatRule, NatType, PolicyDocument, RuleAction,
    SecurityRule, ServiceGroup, ServiceObject, ServiceValue, Vendor,
};
use serde_json::Value;

pub fn parse_checkpoint(text: &str) -> Result<PolicyDocument> {
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        parse_checkpoint_json(trimmed)
    } else {
        parse_checkpoint_set(text)
    }
}

fn parse_checkpoint_json(text: &str) -> Result<PolicyDocument> {
    let mut doc = PolicyDocument::new(Vendor::Checkpoint);
    let v: Value = serde_json::from_str(text).context("checkpoint JSON")?;
    ingest_json_value(&mut doc, &v);
    Ok(doc)
}

fn ingest_json_value(doc: &mut PolicyDocument, v: &Value) {
    match v {
        Value::Array(items) => {
            for item in items {
                ingest_json_value(doc, item);
            }
        }
        Value::Object(map) => {
            // show-objects / show-access-rulebase style
            if let Some(objects) = map.get("objects").and_then(|x| x.as_array()) {
                for o in objects {
                    ingest_object(doc, o);
                }
            }
            if let Some(rulebase) = map.get("rulebase").and_then(|x| x.as_array()) {
                for (i, r) in rulebase.iter().enumerate() {
                    ingest_rule(doc, r, i + 1);
                }
            }
            if let Some(rules) = map.get("rules").and_then(|x| x.as_array()) {
                for (i, r) in rules.iter().enumerate() {
                    ingest_rule(doc, r, i + 1);
                }
            }
            // single object
            if map.contains_key("type") || map.contains_key("uid") {
                let t = map
                    .get("type")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if t.contains("access-rule") || t == "rule" {
                    ingest_rule(doc, v, doc.security_rules.len() + 1);
                } else if !t.is_empty() {
                    ingest_object(doc, v);
                }
            }
            // nested packages
            for (k, child) in map {
                if matches!(k.as_str(), "objects" | "rulebase" | "rules") {
                    continue;
                }
                if child.is_array() || child.is_object() {
                    ingest_json_value(doc, child);
                }
            }
        }
        _ => {}
    }
}

fn name_of(v: &Value) -> String {
    v.get("name")
        .and_then(|x| x.as_str())
        .or_else(|| v.get("uid").and_then(|x| x.as_str()))
        .map(PolicyDocument::sanitize_name)
        .unwrap_or_else(|| "unnamed".into())
}

fn members_of(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .map(|x| match x {
            Value::Array(arr) => arr
                .iter()
                .filter_map(|m| {
                    if let Some(s) = m.as_str() {
                        Some(normalize_any(s))
                    } else {
                        m.get("name")
                            .and_then(|n| n.as_str())
                            .map(normalize_any)
                    }
                })
                .collect(),
            Value::String(s) => vec![normalize_any(s)],
            _ => vec![],
        })
        .unwrap_or_default()
}

fn normalize_any(s: &str) -> String {
    if s.eq_ignore_ascii_case("any") || s.eq_ignore_ascii_case("all") {
        "any".into()
    } else {
        PolicyDocument::sanitize_name(s)
    }
}

fn ingest_object(doc: &mut PolicyDocument, v: &Value) {
    let t = v
        .get("type")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let name = name_of(v);

    if t.contains("host") || t == "host" {
        let ip = v
            .get("ipv4-address")
            .or_else(|| v.get("ip-address"))
            .and_then(|x| x.as_str())
            .unwrap_or("0.0.0.0");
        doc.addresses.push(AddressObject {
            name,
            value: AddressValue::IpNetmask {
                value: format!("{ip}/32"),
            },
            description: v.get("comments").and_then(|x| x.as_str()).map(str::to_string),
            tags: vec![],
        });
    } else if t.contains("network") && !t.contains("group") {
        let ip = v
            .get("subnet4")
            .or_else(|| v.get("subnet"))
            .and_then(|x| x.as_str())
            .unwrap_or("0.0.0.0");
        let mask = v
            .get("mask-length4")
            .or_else(|| v.get("subnet-mask"))
            .map(|x| {
                if let Some(n) = x.as_u64() {
                    format!("{ip}/{n}")
                } else if let Some(s) = x.as_str() {
                    if s.contains('.') {
                        format!("{ip}/{s}")
                    } else {
                        format!("{ip}/{s}")
                    }
                } else {
                    format!("{ip}/24")
                }
            })
            .unwrap_or_else(|| format!("{ip}/24"));
        doc.addresses.push(AddressObject {
            name,
            value: AddressValue::IpNetmask { value: mask },
            description: None,
            tags: vec![],
        });
    } else if t.contains("address-range") || t.contains("range") {
        let from = v
            .get("ipv4-address-first")
            .and_then(|x| x.as_str())
            .unwrap_or("0.0.0.0");
        let to = v
            .get("ipv4-address-last")
            .and_then(|x| x.as_str())
            .unwrap_or("0.0.0.0");
        doc.addresses.push(AddressObject {
            name,
            value: AddressValue::IpRange {
                from: from.into(),
                to: to.into(),
            },
            description: None,
            tags: vec![],
        });
    } else if t.contains("group") && (t.contains("network") || t.contains("address") || t == "group")
    {
        doc.address_groups.push(AddressGroup {
            name,
            members: members_of(v, "members"),
            description: None,
        });
    } else if t.contains("service-tcp") || t == "service-tcp" {
        let port = v
            .get("port")
            .and_then(|x| x.as_str().map(|s| s.to_string()).or_else(|| x.as_u64().map(|n| n.to_string())))
            .unwrap_or_else(|| "any".into());
        doc.services.push(ServiceObject {
            name,
            value: ServiceValue::Tcp { port },
            description: None,
        });
    } else if t.contains("service-udp") {
        let port = v
            .get("port")
            .and_then(|x| x.as_str().map(|s| s.to_string()).or_else(|| x.as_u64().map(|n| n.to_string())))
            .unwrap_or_else(|| "any".into());
        doc.services.push(ServiceObject {
            name,
            value: ServiceValue::Udp { port },
            description: None,
        });
    } else if t.contains("service-group") {
        doc.service_groups.push(ServiceGroup {
            name,
            members: members_of(v, "members"),
            description: None,
        });
    } else if t.contains("nat-rule") {
        let i = doc.nat_rules.len() + 1;
        doc.nat_rules.push(NatRule {
            name: format!("cp_nat_{i}"),
            nat_type: NatType::Source,
            from_zones: vec!["any".into()],
            to_zones: vec!["any".into()],
            source: members_of(v, "original-source"),
            destination: members_of(v, "original-destination"),
            service: members_of(v, "original-service"),
            translated_source: members_of(v, "translated-source").into_iter().next(),
            translated_destination: members_of(v, "translated-destination").into_iter().next(),
            translated_service: members_of(v, "translated-service").into_iter().next(),
            disabled: v.get("enabled").and_then(|x| x.as_bool()) == Some(false),
            description: None,
        });
    }
}

fn ingest_rule(doc: &mut PolicyDocument, v: &Value, idx: usize) {
    let t = v
        .get("type")
        .and_then(|x| x.as_str())
        .unwrap_or("access-rule")
        .to_ascii_lowercase();
    if t.contains("section") || t.contains("place-holder") {
        return;
    }
    let name = v
        .get("name")
        .and_then(|x| x.as_str())
        .map(PolicyDocument::sanitize_name)
        .unwrap_or_else(|| format!("cp_rule_{idx}"));
    let action = v
        .get("action")
        .and_then(|a| {
            a.get("name")
                .and_then(|n| n.as_str())
                .or_else(|| a.as_str())
        })
        .unwrap_or("Drop");
    let action = match action.to_ascii_lowercase().as_str() {
        "accept" | "allow" => RuleAction::Allow,
        "reject" => RuleAction::ResetBoth,
        _ => RuleAction::Drop,
    };
    let mut source = members_of(v, "source");
    let mut destination = members_of(v, "destination");
    let mut service = members_of(v, "service");
    if source.is_empty() {
        source = vec!["any".into()];
    }
    if destination.is_empty() {
        destination = vec!["any".into()];
    }
    if service.is_empty() {
        service = vec!["any".into()];
    }
    doc.security_rules.push(SecurityRule {
        name,
        from_zones: vec!["any".into()],
        to_zones: vec!["any".into()],
        source,
        destination,
        application: vec!["any".into()],
        service,
        action,
        disabled: v.get("enabled").and_then(|x| x.as_bool()) == Some(false),
        log_start: false,
        log_end: true,
        description: v.get("comments").and_then(|x| x.as_str()).map(str::to_string),
        tags: vec!["checkpoint".into()],
        profile_group: None,
        profiles: Default::default(),
    });
}

fn parse_checkpoint_set(text: &str) -> Result<PolicyDocument> {
    let mut doc = PolicyDocument::new(Vendor::Checkpoint);
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let toks = tokenize(line);
        if toks.len() < 3 || !toks[0].eq_ignore_ascii_case("set") {
            continue;
        }
        let kind = toks[1].to_ascii_lowercase();
        match kind.as_str() {
            "host" if toks.len() >= 5 && toks[2].eq_ignore_ascii_case("name") => {
                let name = PolicyDocument::sanitize_name(&unquote(&toks[3]));
                // set host name X ip-address Y
                if let Some(pos) = toks.iter().position(|t| t.eq_ignore_ascii_case("ip-address")) {
                    if let Some(ip) = toks.get(pos + 1) {
                        doc.addresses.push(AddressObject {
                            name,
                            value: AddressValue::IpNetmask {
                                value: format!("{}/32", unquote(ip)),
                            },
                            description: None,
                            tags: vec![],
                        });
                    }
                }
            }
            "network" if toks.len() >= 5 && toks[2].eq_ignore_ascii_case("name") => {
                let name = PolicyDocument::sanitize_name(&unquote(&toks[3]));
                let mut subnet = "0.0.0.0".to_string();
                let mut mask = "24".to_string();
                if let Some(pos) = toks.iter().position(|t| t.eq_ignore_ascii_case("subnet")) {
                    if let Some(s) = toks.get(pos + 1) {
                        subnet = unquote(s);
                    }
                }
                if let Some(pos) = toks
                    .iter()
                    .position(|t| t.eq_ignore_ascii_case("mask-length") || t.eq_ignore_ascii_case("subnet-mask"))
                {
                    if let Some(s) = toks.get(pos + 1) {
                        mask = unquote(s);
                    }
                }
                doc.addresses.push(AddressObject {
                    name,
                    value: AddressValue::IpNetmask {
                        value: format!("{subnet}/{mask}"),
                    },
                    description: None,
                    tags: vec![],
                });
            }
            "access-rule" => {
                // set access-rule layer Network rule 1 action accept source ... destination ...
                let mut rule = SecurityRule {
                    name: format!("cp_rule_{}", doc.security_rules.len() + 1),
                    from_zones: vec!["any".into()],
                    to_zones: vec!["any".into()],
                    source: vec!["any".into()],
                    destination: vec!["any".into()],
                    application: vec!["any".into()],
                    service: vec!["any".into()],
                    action: RuleAction::Drop,
                    disabled: false,
                    log_start: false,
                    log_end: true,
                    description: None,
                    tags: vec!["checkpoint".into()],
                    profile_group: None,
                    profiles: Default::default(),
                };
                if let Some(pos) = toks.iter().position(|t| t.eq_ignore_ascii_case("action")) {
                    if let Some(a) = toks.get(pos + 1) {
                        rule.action = match a.to_ascii_lowercase().as_str() {
                            "accept" | "allow" => RuleAction::Allow,
                            "reject" => RuleAction::ResetBoth,
                            _ => RuleAction::Drop,
                        };
                    }
                }
                if let Some(pos) = toks.iter().position(|t| t.eq_ignore_ascii_case("source")) {
                    let mut members = Vec::new();
                    for t in toks.iter().skip(pos + 1) {
                        let l = t.to_ascii_lowercase();
                        if matches!(l.as_str(), "destination" | "service" | "action" | "layer" | "rule") {
                            break;
                        }
                        members.push(PolicyDocument::sanitize_name(&unquote(t)));
                    }
                    if !members.is_empty() {
                        rule.source = members;
                    }
                }
                if let Some(pos) = toks.iter().position(|t| t.eq_ignore_ascii_case("destination")) {
                    let mut members = Vec::new();
                    for t in toks.iter().skip(pos + 1) {
                        let l = t.to_ascii_lowercase();
                        if matches!(l.as_str(), "source" | "service" | "action" | "layer" | "rule") {
                            break;
                        }
                        members.push(PolicyDocument::sanitize_name(&unquote(t)));
                    }
                    if !members.is_empty() {
                        rule.destination = members;
                    }
                }
                if let Some(pos) = toks.iter().position(|t| t.eq_ignore_ascii_case("service")) {
                    let mut members = Vec::new();
                    for t in toks.iter().skip(pos + 1) {
                        let l = t.to_ascii_lowercase();
                        if matches!(l.as_str(), "source" | "destination" | "action" | "layer" | "rule") {
                            break;
                        }
                        members.push(PolicyDocument::sanitize_name(&unquote(t)));
                    }
                    if !members.is_empty() {
                        rule.service = members;
                    }
                }
                doc.security_rules.push(rule);
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
    fn parses_json_export() {
        let sample = r#"{
          "objects": [
            {"type":"host","name":"web","ipv4-address":"10.1.1.10"},
            {"type":"service-tcp","name":"https","port":"443"},
            {"type":"group","name":"web_grp","members":[{"name":"web"}]}
          ],
          "rulebase": [
            {"type":"access-rule","name":"allow-web","action":{"name":"Accept"},
             "source":[{"name":"Any"}],"destination":[{"name":"web"}],"service":[{"name":"https"}]}
          ]
        }"#;
        let doc = parse_checkpoint(sample).unwrap();
        assert_eq!(doc.addresses.len(), 1);
        assert_eq!(doc.services.len(), 1);
        assert_eq!(doc.address_groups.len(), 1);
        assert_eq!(doc.security_rules.len(), 1);
        assert_eq!(doc.security_rules[0].action, RuleAction::Allow);
    }
}
