use interstellar_ir::{
    AddressValue, NatType, PolicyDocument, ServiceValue,
};

pub fn emit_panos_xml(doc: &PolicyDocument) -> String {
    let mut out = String::new();
    out.push_str(r#"<?xml version="1.0"?>"#);
    out.push('\n');
    let ver = doc
        .source_version
        .as_deref()
        .filter(|v| v.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false))
        .unwrap_or("10.2.0");
    out.push_str(&format!(
        r#"<config version="{ver}" urldb="paloaltonetworks">"#
    ));
    out.push('\n');
    out.push_str("  <shared>\n");

    // addresses
    out.push_str("    <address>\n");
    for a in &doc.addresses {
        out.push_str(&format!("      <entry name=\"{}\">\n", esc(&a.name)));
        match &a.value {
            AddressValue::IpNetmask { value } => {
                out.push_str(&format!("        <ip-netmask>{}</ip-netmask>\n", esc(value)));
            }
            AddressValue::IpRange { from, to } => {
                out.push_str(&format!(
                    "        <ip-range>{}-{}</ip-range>\n",
                    esc(from),
                    esc(to)
                ));
            }
            AddressValue::Fqdn { value } => {
                out.push_str(&format!("        <fqdn>{}</fqdn>\n", esc(value)));
            }
            AddressValue::IpWildcard { ip, mask } => {
                out.push_str(&format!(
                    "        <ip-wildcard>{}</ip-wildcard>\n",
                    esc(&format!("{ip}/{mask}"))
                ));
            }
        }
        if let Some(d) = &a.description {
            out.push_str(&format!("        <description>{}</description>\n", esc(d)));
        }
        out.push_str("      </entry>\n");
    }
    out.push_str("    </address>\n");

    out.push_str("    <address-group>\n");
    for g in &doc.address_groups {
        out.push_str(&format!("      <entry name=\"{}\">\n", esc(&g.name)));
        out.push_str("        <static>\n");
        for m in &g.members {
            out.push_str(&format!("          <member>{}</member>\n", esc(m)));
        }
        out.push_str("        </static>\n");
        out.push_str("      </entry>\n");
    }
    out.push_str("    </address-group>\n");

    out.push_str("    <service>\n");
    for s in &doc.services {
        out.push_str(&format!("      <entry name=\"{}\">\n", esc(&s.name)));
        out.push_str("        <protocol>\n");
        match &s.value {
            ServiceValue::Tcp { port } => {
                out.push_str("          <tcp>\n");
                out.push_str(&format!("            <port>{}</port>\n", esc(port)));
                out.push_str("          </tcp>\n");
            }
            ServiceValue::Udp { port } => {
                out.push_str("          <udp>\n");
                out.push_str(&format!("            <port>{}</port>\n", esc(port)));
                out.push_str("          </udp>\n");
            }
            ServiceValue::TcpUdp { port } => {
                out.push_str("          <tcp>\n");
                out.push_str(&format!("            <port>{}</port>\n", esc(port)));
                out.push_str("          </tcp>\n");
            }
            ServiceValue::Protocol { protocol } => {
                out.push_str(&format!(
                    "          <other><number>{protocol}</number></other>\n"
                ));
            }
            ServiceValue::Any => {
                out.push_str("          <tcp>\n");
                out.push_str("            <port>0-65535</port>\n");
                out.push_str("          </tcp>\n");
            }
        }
        out.push_str("        </protocol>\n");
        out.push_str("      </entry>\n");
    }
    out.push_str("    </service>\n");

    out.push_str("    <service-group>\n");
    for g in &doc.service_groups {
        out.push_str(&format!("      <entry name=\"{}\">\n", esc(&g.name)));
        out.push_str("        <members>\n");
        for m in &g.members {
            out.push_str(&format!("          <member>{}</member>\n", esc(m)));
        }
        out.push_str("        </members>\n");
        out.push_str("      </entry>\n");
    }
    out.push_str("    </service-group>\n");

    if !doc.profile_groups.is_empty() {
        out.push_str("    <profile-group>\n");
        for p in &doc.profile_groups {
            out.push_str(&format!("      <entry name=\"{}\">\n", esc(&p.name)));
            if let Some(v) = &p.virus {
                out.push_str(&format!("        <virus><member>{}</member></virus>\n", esc(v)));
            }
            if let Some(v) = &p.spyware {
                out.push_str(&format!(
                    "        <spyware><member>{}</member></spyware>\n",
                    esc(v)
                ));
            }
            if let Some(v) = &p.vulnerability {
                out.push_str(&format!(
                    "        <vulnerability><member>{}</member></vulnerability>\n",
                    esc(v)
                ));
            }
            if let Some(v) = &p.url_filtering {
                out.push_str(&format!(
                    "        <url-filtering><member>{}</member></url-filtering>\n",
                    esc(v)
                ));
            }
            if let Some(v) = &p.file_blocking {
                out.push_str(&format!(
                    "        <file-blocking><member>{}</member></file-blocking>\n",
                    esc(v)
                ));
            }
            if let Some(v) = &p.wildfire {
                out.push_str(&format!(
                    "        <wildfire-analysis><member>{}</member></wildfire-analysis>\n",
                    esc(v)
                ));
            }
            out.push_str("      </entry>\n");
        }
        out.push_str("    </profile-group>\n");
    }

    out.push_str("  </shared>\n");

    // Device vsys rulebase
    out.push_str("  <devices>\n");
    out.push_str("    <entry name=\"localhost.localdomain\">\n");
    out.push_str("      <vsys>\n");
    out.push_str("        <entry name=\"vsys1\">\n");
    out.push_str("          <rulebase>\n");

    out.push_str("            <security>\n");
    out.push_str("              <rules>\n");
    for r in &doc.security_rules {
        out.push_str(&format!("                <entry name=\"{}\">\n", esc(&r.name)));
        write_members(&mut out, "from", &r.from_zones, 18);
        write_members(&mut out, "to", &r.to_zones, 18);
        write_members(&mut out, "source", &r.source, 18);
        write_members(&mut out, "destination", &r.destination, 18);
        write_members(&mut out, "application", &r.application, 18);
        write_members(&mut out, "service", &r.service, 18);
        out.push_str(&format!(
            "                  <action>{}</action>\n",
            r.action.as_panos()
        ));
        if r.log_end {
            out.push_str("                  <log-end>yes</log-end>\n");
        }
        if r.log_start {
            out.push_str("                  <log-start>yes</log-start>\n");
        }
        if r.disabled {
            out.push_str("                  <disabled>yes</disabled>\n");
        }
        if let Some(d) = &r.description {
            out.push_str(&format!(
                "                  <description>{}</description>\n",
                esc(d)
            ));
        }
        if let Some(pg) = &r.profile_group {
            out.push_str("                  <profile-setting>\n");
            out.push_str(&format!("                    <group><member>{}</member></group>\n", esc(pg)));
            out.push_str("                  </profile-setting>\n");
        } else if !r.profiles.is_empty() {
            out.push_str("                  <profile-setting>\n");
            out.push_str("                    <profiles>\n");
            for (k, v) in &r.profiles {
                out.push_str(&format!(
                    "                      <{k}><member>{}</member></{k}>\n",
                    esc(v)
                ));
            }
            out.push_str("                    </profiles>\n");
            out.push_str("                  </profile-setting>\n");
        }
        out.push_str("                </entry>\n");
    }
    out.push_str("              </rules>\n");
    out.push_str("            </security>\n");

    if !doc.nat_rules.is_empty() {
        out.push_str("            <nat>\n");
        out.push_str("              <rules>\n");
        for n in &doc.nat_rules {
            out.push_str(&format!("                <entry name=\"{}\">\n", esc(&n.name)));
            write_members(&mut out, "from", &n.from_zones, 18);
            write_members(&mut out, "to", &n.to_zones, 18);
            write_members(&mut out, "source", &n.source, 18);
            write_members(&mut out, "destination", &n.destination, 18);
            write_members(&mut out, "service", &n.service, 18);
            match n.nat_type {
                NatType::Source | NatType::Static => {
                    if let Some(ts) = &n.translated_source {
                        out.push_str("                  <source-translation>\n");
                        if n.nat_type == NatType::Static {
                            out.push_str("                    <static-ip>\n");
                            out.push_str(&format!(
                                "                      <translated-address>{}</translated-address>\n",
                                esc(ts)
                            ));
                            out.push_str("                    </static-ip>\n");
                        } else {
                            out.push_str("                    <dynamic-ip-and-port>\n");
                            out.push_str("                      <translated-address>\n");
                            out.push_str(&format!(
                                "                        <member>{}</member>\n",
                                esc(ts)
                            ));
                            out.push_str("                      </translated-address>\n");
                            out.push_str("                    </dynamic-ip-and-port>\n");
                        }
                        out.push_str("                  </source-translation>\n");
                    }
                }
                NatType::Destination => {
                    if let Some(td) = &n.translated_destination {
                        out.push_str("                  <destination-translation>\n");
                        out.push_str(&format!(
                            "                    <translated-address>{}</translated-address>\n",
                            esc(td)
                        ));
                        if let Some(tsvc) = &n.translated_service {
                            out.push_str(&format!(
                                "                    <translated-port>{}</translated-port>\n",
                                esc(tsvc)
                            ));
                        }
                        out.push_str("                  </destination-translation>\n");
                    }
                }
            }
            if n.disabled {
                out.push_str("                  <disabled>yes</disabled>\n");
            }
            out.push_str("                </entry>\n");
        }
        out.push_str("              </rules>\n");
        out.push_str("            </nat>\n");
    }

    out.push_str("          </rulebase>\n");
    out.push_str("        </entry>\n");
    out.push_str("      </vsys>\n");

    // Network VPN under deviceconfig-ish simplified under devices
    if !doc.ike_gateways.is_empty() || !doc.ipsec_tunnels.is_empty() {
        out.push_str("      <network>\n");
        out.push_str("        <ike>\n");
        out.push_str("          <gateway>\n");
        for g in &doc.ike_gateways {
            out.push_str(&format!("            <entry name=\"{}\">\n", esc(&g.name)));
            out.push_str("              <peer-address>\n");
            out.push_str(&format!("                <ip>{}</ip>\n", esc(&g.peer_ip)));
            out.push_str("              </peer-address>\n");
            out.push_str("              <protocol>\n");
            out.push_str(&format!(
                "                <version>{}</version>\n",
                esc(&g.ike_version)
            ));
            out.push_str("              </protocol>\n");
            out.push_str("            </entry>\n");
        }
        out.push_str("          </gateway>\n");
        out.push_str("        </ike>\n");
        out.push_str("        <tunnel>\n");
        out.push_str("          <ipsec>\n");
        for t in &doc.ipsec_tunnels {
            out.push_str(&format!("            <entry name=\"{}\">\n", esc(&t.name)));
            out.push_str("              <auto-key>\n");
            out.push_str("                <ike-gateway>\n");
            out.push_str(&format!(
                "                  <entry name=\"{}\"/>\n",
                esc(&t.ike_gateway)
            ));
            out.push_str("                </ike-gateway>\n");
            out.push_str("              </auto-key>\n");
            out.push_str("            </entry>\n");
        }
        out.push_str("          </ipsec>\n");
        out.push_str("        </tunnel>\n");
        out.push_str("      </network>\n");
    }

    out.push_str("    </entry>\n");
    out.push_str("  </devices>\n");
    out.push_str("</config>\n");
    out
}

fn write_members(out: &mut String, tag: &str, members: &[String], indent: usize) {
    let pad = " ".repeat(indent);
    out.push_str(&format!("{pad}<{tag}>\n"));
    for m in members {
        out.push_str(&format!("{pad}  <member>{}</member>\n", esc(m)));
    }
    out.push_str(&format!("{pad}</{tag}>\n"));
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
