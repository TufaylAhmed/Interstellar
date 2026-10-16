//! IR transforms: zone mapping and object deduplication.

use interstellar_ir::{AddressValue, PolicyDocument, ServiceValue};
use std::collections::{BTreeMap, BTreeSet};

/// Apply `from=to` zone/interface renames across rules and NAT.
pub fn apply_zone_map(doc: &mut PolicyDocument, map: &BTreeMap<String, String>) {
    if map.is_empty() {
        return;
    }
    let map_one = |z: &str| -> String {
        map.get(z)
            .cloned()
            .or_else(|| {
                map.iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(z))
                    .map(|(_, v)| v.clone())
            })
            .unwrap_or_else(|| z.to_string())
    };
    let map_list = |list: &mut Vec<String>| {
        for z in list.iter_mut() {
            *z = map_one(z);
        }
    };
    for r in &mut doc.security_rules {
        map_list(&mut r.from_zones);
        map_list(&mut r.to_zones);
    }
    for n in &mut doc.nat_rules {
        map_list(&mut n.from_zones);
        map_list(&mut n.to_zones);
    }
}

/// Parse `a=b,c=d` or newline/space separated pairs.
pub fn parse_zone_map(spec: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for part in spec.split(|c: char| c == ',' || c == '\n' || c == ';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((k, v)) = part.split_once('=') {
            let k = k.trim();
            let v = v.trim();
            if !k.is_empty() && !v.is_empty() {
                map.insert(k.to_string(), v.to_string());
            }
        }
    }
    map
}

#[derive(Debug, Clone, Default)]
pub struct DedupReport {
    pub removed_addresses: usize,
    pub removed_services: usize,
    pub renamed: Vec<(String, String)>,
}

/// Merge address/service objects that share identical values; rewrite references.
pub fn dedup_objects(doc: &mut PolicyDocument) -> DedupReport {
    let mut report = DedupReport::default();

    // addresses
    let mut value_to_name: BTreeMap<String, String> = BTreeMap::new();
    let mut rename: BTreeMap<String, String> = BTreeMap::new();
    let mut keep_addr = Vec::new();
    for a in &doc.addresses {
        let key = addr_key(&a.value);
        if let Some(canonical) = value_to_name.get(&key) {
            if canonical != &a.name {
                rename.insert(a.name.clone(), canonical.clone());
                report.removed_addresses += 1;
                report
                    .renamed
                    .push((a.name.clone(), canonical.clone()));
            }
        } else {
            value_to_name.insert(key, a.name.clone());
            keep_addr.push(a.clone());
        }
    }
    doc.addresses = keep_addr;

    // services
    let mut svc_to_name: BTreeMap<String, String> = BTreeMap::new();
    let mut keep_svc = Vec::new();
    for s in &doc.services {
        let key = svc_key(&s.value);
        if let Some(canonical) = svc_to_name.get(&key) {
            if canonical != &s.name {
                rename.insert(s.name.clone(), canonical.clone());
                report.removed_services += 1;
                report
                    .renamed
                    .push((s.name.clone(), canonical.clone()));
            }
        } else {
            svc_to_name.insert(key, s.name.clone());
            keep_svc.push(s.clone());
        }
    }
    doc.services = keep_svc;

    if rename.is_empty() {
        return report;
    }

    let rewrite = |list: &mut Vec<String>| {
        for n in list.iter_mut() {
            if let Some(r) = rename.get(n) {
                *n = r.clone();
            }
        }
        // dedupe list members
        let mut seen = BTreeSet::new();
        list.retain(|x| seen.insert(x.clone()));
    };

    for g in &mut doc.address_groups {
        rewrite(&mut g.members);
    }
    for g in &mut doc.service_groups {
        rewrite(&mut g.members);
    }
    for r in &mut doc.security_rules {
        rewrite(&mut r.source);
        rewrite(&mut r.destination);
        rewrite(&mut r.service);
    }
    for n in &mut doc.nat_rules {
        rewrite(&mut n.source);
        rewrite(&mut n.destination);
        rewrite(&mut n.service);
        if let Some(ref mut t) = n.translated_source {
            if let Some(r) = rename.get(t) {
                *t = r.clone();
            }
        }
        if let Some(ref mut t) = n.translated_destination {
            if let Some(r) = rename.get(t) {
                *t = r.clone();
            }
        }
    }

    report
}

fn addr_key(v: &AddressValue) -> String {
    match v {
        AddressValue::IpNetmask { value } => format!("net:{value}"),
        AddressValue::IpRange { from, to } => format!("range:{from}-{to}"),
        AddressValue::Fqdn { value } => format!("fqdn:{}", value.to_ascii_lowercase()),
        AddressValue::IpWildcard { ip, mask } => format!("wild:{ip}/{mask}"),
    }
}

fn svc_key(v: &ServiceValue) -> String {
    match v {
        ServiceValue::Tcp { port } => format!("tcp:{port}"),
        ServiceValue::Udp { port } => format!("udp:{port}"),
        ServiceValue::TcpUdp { port } => format!("tcpudp:{port}"),
        ServiceValue::Protocol { protocol } => format!("proto:{protocol}"),
        ServiceValue::Any => "any".into(),
    }
}
