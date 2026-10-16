//! Human-readable analysis reports (Markdown / HTML).

use crate::AnalysisReport;
use interstellar_ir::PolicyDocument;

pub fn report_markdown(doc: &PolicyDocument, analysis: &AnalysisReport) -> String {
    let s = doc.summary();
    let mut out = String::new();
    out.push_str("# Interstellar Analysis Report\n\n");
    if let Some(n) = &doc.source_name {
        out.push_str(&format!("**Source:** `{n}`  \n"));
    }
    out.push_str(&format!("**Vendor:** {}  \n\n", s.vendor.as_str()));
    out.push_str("## Summary\n\n");
    out.push_str("| Metric | Count |\n|---|---:|\n");
    out.push_str(&format!("| Addresses | {} |\n", s.addresses));
    out.push_str(&format!("| Address groups | {} |\n", s.address_groups));
    out.push_str(&format!("| Services | {} |\n", s.services));
    out.push_str(&format!("| Security rules | {} |\n", s.security_rules));
    out.push_str(&format!("| NAT rules | {} |\n", s.nat_rules));
    out.push_str(&format!("| Allow rules | {} |\n", analysis.stats.allow_rules));
    out.push_str(&format!("| Deny/other | {} |\n", analysis.stats.deny_rules));
    out.push_str(&format!(
        "| Disabled | {} |\n\n",
        analysis.stats.disabled_rules
    ));

    section_list(&mut out, "Unused addresses", &analysis.unused_addresses);
    section_list(&mut out, "Unused services", &analysis.unused_services);
    section_list(
        &mut out,
        "Unused address groups",
        &analysis.unused_address_groups,
    );
    section_list(&mut out, "Broad allow rules", &analysis.broad_allows);

    out.push_str("## Shadow hints\n\n");
    if analysis.shadowed_rules.is_empty() {
        out.push_str("_None_\n\n");
    } else {
        for h in &analysis.shadowed_rules {
            out.push_str(&format!(
                "- `{}` may shadow `{}` — {}\n",
                h.earlier, h.later, h.reason
            ));
        }
        out.push('\n');
    }

    out.push_str("## Duplicate rules\n\n");
    if analysis.duplicate_rules.is_empty() {
        out.push_str("_None_\n");
    } else {
        for (a, b) in &analysis.duplicate_rules {
            out.push_str(&format!("- `{a}` ≡ `{b}`\n"));
        }
    }
    out
}

pub fn report_html(doc: &PolicyDocument, analysis: &AnalysisReport) -> String {
    let md_like = report_markdown(doc, analysis);
    // Minimal HTML wrap — keep simple, no markdown engine dependency.
    let escaped = html_escape(&md_like);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Interstellar Analysis</title>
<style>
body {{ font-family: ui-sans-serif, system-ui, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; color: #122; background: #f7f9fb; }}
pre {{ white-space: pre-wrap; background: #fff; border: 1px solid #d7dee7; padding: 20px; line-height: 1.45; }}
h1 {{ font-size: 1.6rem; }}
</style>
</head>
<body>
<h1>Interstellar Analysis</h1>
<pre>{escaped}</pre>
</body>
</html>
"#
    )
}

fn section_list(out: &mut String, title: &str, items: &[String]) {
    out.push_str(&format!("## {title}\n\n"));
    if items.is_empty() {
        out.push_str("_None_\n\n");
    } else {
        for i in items {
            out.push_str(&format!("- `{i}`\n"));
        }
        out.push('\n');
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
