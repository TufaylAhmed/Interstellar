use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use interstellar_analyze::{analyze, diff_documents, report_html, report_markdown};
use interstellar_emit::{
    apply_zone_map, dedup_objects, emit_panos_xml, emit_set_commands, parse_zone_map,
    validate_document,
};
use interstellar_ir::project::{
    default_projects_dir, delete_project, list_projects, load_project, save_project,
};
use interstellar_parse::{parse_file, parse_vendor_str};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "interstellar",
    version,
    about = "Interstellar — convert Fortinet / Cisco / Check Point / Juniper / PAN-OS configs to PAN-OS XML"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Convert a vendor config file to PAN-OS XML and/or set-commands
    Convert {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long, default_value = "auto")]
        vendor: String,
        #[arg(long, value_enum, default_value_t = OutFormat::Xml)]
        format: OutFormat,
        #[arg(long)]
        ir: bool,
        #[arg(long, default_value_t = true)]
        validate: bool,
        /// Zone/interface map: wan1=untrust,internal=trust
        #[arg(long)]
        zone_map: Option<String>,
        /// Deduplicate identical address/service objects
        #[arg(long)]
        dedup: bool,
        /// Save as named project under ~/.interstellar/projects
        #[arg(long)]
        save_as: Option<String>,
    },
    /// Convert every config file in a directory
    Batch {
        input_dir: PathBuf,
        #[arg(short, long)]
        output_dir: PathBuf,
        #[arg(long, default_value = "auto")]
        vendor: String,
        #[arg(long, value_enum, default_value_t = OutFormat::Xml)]
        format: OutFormat,
        #[arg(long)]
        zone_map: Option<String>,
        #[arg(long)]
        dedup: bool,
    },
    /// Validate a vendor or PAN-OS config
    Validate {
        input: PathBuf,
        #[arg(long, default_value = "auto")]
        vendor: String,
    },
    /// Analyze policy (unused objects, shadow hints, broad allows)
    Analyze {
        input: PathBuf,
        #[arg(long, default_value = "auto")]
        vendor: String,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = ReportFormat::Json)]
        format: ReportFormat,
    },
    /// Diff two configs (or IR JSON files)
    Diff {
        left: PathBuf,
        right: PathBuf,
        #[arg(long, default_value = "auto")]
        vendor: String,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Deduplicate objects in a config and write IR/XML
    Dedup {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long, default_value = "auto")]
        vendor: String,
        #[arg(long, value_enum, default_value_t = OutFormat::Ir)]
        format: OutFormat,
    },
    /// Apply zone map and emit
    ZoneMap {
        input: PathBuf,
        /// e.g. wan1=untrust,internal=trust
        #[arg(long)]
        map: String,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long, default_value = "auto")]
        vendor: String,
        #[arg(long, value_enum, default_value_t = OutFormat::Xml)]
        format: OutFormat,
    },
    /// Project persistence under ~/.interstellar/projects
    Project {
        #[command(subcommand)]
        cmd: ProjectCmd,
    },
    /// Start local UI + HTTP API (opens browser by default)
    Serve {
        #[arg(long, default_value = "127.0.0.1:8787")]
        bind: String,
        #[arg(long)]
        static_dir: Option<PathBuf>,
        #[arg(long)]
        projects_dir: Option<PathBuf>,
        /// Do not open the default browser
        #[arg(long, default_value_t = false)]
        no_open: bool,
    },
    /// Show parsed summary counts
    Summary {
        input: PathBuf,
        #[arg(long, default_value = "auto")]
        vendor: String,
    },
}

#[derive(Subcommand, Debug)]
enum ProjectCmd {
    List {
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    Save {
        input: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "auto")]
        vendor: String,
        #[arg(long)]
        dir: Option<PathBuf>,
        #[arg(long)]
        id: Option<String>,
    },
    Show {
        id: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    Export {
        id: String,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long, value_enum, default_value_t = OutFormat::Xml)]
        format: OutFormat,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    Delete {
        id: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum OutFormat {
    Xml,
    Set,
    Both,
    Ir,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum ReportFormat {
    Json,
    Markdown,
    Html,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Convert {
            input,
            output,
            vendor,
            format,
            ir,
            validate,
            zone_map,
            dedup,
            save_as,
        } => cmd_convert(
            &input,
            output.as_deref(),
            &vendor,
            format,
            ir,
            validate,
            zone_map.as_deref(),
            dedup,
            save_as.as_deref(),
        )?,
        Commands::Batch {
            input_dir,
            output_dir,
            vendor,
            format,
            zone_map,
            dedup,
        } => cmd_batch(
            &input_dir,
            &output_dir,
            &vendor,
            format,
            zone_map.as_deref(),
            dedup,
        )?,
        Commands::Validate { input, vendor } => cmd_validate(&input, &vendor)?,
        Commands::Analyze {
            input,
            vendor,
            output,
            format,
        } => cmd_analyze(&input, &vendor, output.as_deref(), format)?,
        Commands::Diff {
            left,
            right,
            vendor,
            output,
        } => cmd_diff(&left, &right, &vendor, output.as_deref())?,
        Commands::Dedup {
            input,
            output,
            vendor,
            format,
        } => {
            let mut doc = load_doc(&input, &vendor)?;
            let report = dedup_objects(&mut doc);
            eprintln!(
                "dedup: removed {} addresses, {} services, {} renames",
                report.removed_addresses,
                report.removed_services,
                report.renamed.len()
            );
            emit_doc(&doc, output.as_deref(), format)?;
        }
        Commands::ZoneMap {
            input,
            map,
            output,
            vendor,
            format,
        } => {
            let mut doc = load_doc(&input, &vendor)?;
            apply_zone_map(&mut doc, &parse_zone_map(&map));
            emit_doc(&doc, output.as_deref(), format)?;
        }
        Commands::Project { cmd } => cmd_project(cmd)?,
        Commands::Serve {
            bind,
            static_dir,
            projects_dir,
            no_open,
        } => {
            let addr: SocketAddr = bind.parse().context("invalid --bind address")?;
            let static_dir = resolve_static_dir(static_dir)?;
            let projects_dir = projects_dir.unwrap_or_else(default_projects_dir);
            interstellar_api::serve(addr, static_dir, projects_dir, !no_open).await?;
        }
        Commands::Summary { input, vendor } => {
            let doc = load_doc(&input, &vendor)?;
            println!("{}", serde_json::to_string_pretty(&doc.summary())?);
        }
    }
    Ok(())
}

fn load_doc(input: &Path, vendor: &str) -> Result<interstellar_ir::PolicyDocument> {
    if input
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("json"))
    {
        // Try IR / stored project JSON first
        let text = std::fs::read_to_string(input)?;
        if let Ok(doc) = serde_json::from_str::<interstellar_ir::PolicyDocument>(&text) {
            return Ok(doc);
        }
        if let Ok(p) = serde_json::from_str::<interstellar_ir::project::StoredProject>(&text) {
            return Ok(p.document);
        }
    }
    let forced = parse_vendor_str(vendor)?;
    parse_file(input, forced)
}

fn transform_doc(
    doc: &mut interstellar_ir::PolicyDocument,
    zone_map: Option<&str>,
    dedup: bool,
) {
    if let Some(spec) = zone_map {
        apply_zone_map(doc, &parse_zone_map(spec));
    }
    if dedup {
        let r = dedup_objects(doc);
        if r.removed_addresses + r.removed_services > 0 {
            eprintln!(
                "dedup: -{} addr -{} svc",
                r.removed_addresses, r.removed_services
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_convert(
    input: &Path,
    output: Option<&Path>,
    vendor: &str,
    format: OutFormat,
    write_ir: bool,
    do_validate: bool,
    zone_map: Option<&str>,
    dedup: bool,
    save_as: Option<&str>,
) -> Result<()> {
    let mut doc = load_doc(input, vendor)?;
    transform_doc(&mut doc, zone_map, dedup);

    if do_validate {
        let report = validate_document(&doc);
        eprintln!(
            "validation: {} issue(s), {} error(s)",
            report.issues.len(),
            report.error_count()
        );
        for issue in &report.issues {
            eprintln!(
                "  [{:?}] {}: {}",
                issue.severity, issue.code, issue.message
            );
        }
    }

    emit_doc(&doc, output, format)?;

    if write_ir {
        let ir_path = match output {
            Some(p) => path_with_suffix(p, "ir.json"),
            None => input.with_extension("ir.json"),
        };
        std::fs::write(&ir_path, serde_json::to_string_pretty(&doc)?)?;
        eprintln!("wrote IR {}", ir_path.display());
    }

    if let Some(name) = save_as {
        let dir = default_projects_dir();
        let stored = save_project(&dir, name, doc.clone(), None, None)?;
        eprintln!("saved project {} → {}", stored.id, dir.display());
    }

    let s = doc.summary();
    eprintln!(
        "ok: vendor={:?} addresses={} services={} rules={} nat={}",
        s.vendor, s.addresses, s.services, s.security_rules, s.nat_rules
    );
    Ok(())
}

fn cmd_batch(
    input_dir: &Path,
    output_dir: &Path,
    vendor: &str,
    format: OutFormat,
    zone_map: Option<&str>,
    dedup: bool,
) -> Result<()> {
    std::fs::create_dir_all(output_dir)?;
    let mut count = 0usize;
    let mut stack = vec![input_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if !path.is_file() {
                continue;
            }
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if !matches!(
                ext.as_str(),
                "conf" | "cfg" | "txt" | "xml" | "json" | "set" | "config"
            ) {
                continue;
            }
            let rel = path
                .strip_prefix(input_dir)
                .unwrap_or(&path)
                .with_extension("");
            let stem = rel
                .to_string_lossy()
                .replace(['/', '\\'], "_");
            let out = match format {
                OutFormat::Xml => output_dir.join(format!("{stem}.xml")),
                OutFormat::Set => output_dir.join(format!("{stem}.set.txt")),
                OutFormat::Ir => output_dir.join(format!("{stem}.ir.json")),
                OutFormat::Both => output_dir.join(&stem),
            };
            match cmd_convert(
                &path,
                Some(&out),
                vendor,
                format,
                true,
                true,
                zone_map,
                dedup,
                None,
            ) {
                Ok(()) => count += 1,
                Err(e) => eprintln!("skip {}: {e:#}", path.display()),
            }
        }
    }
    eprintln!("batch: converted {count} file(s) → {}", output_dir.display());
    Ok(())
}

fn cmd_validate(input: &Path, vendor: &str) -> Result<()> {
    let doc = load_doc(input, vendor)?;
    let report = validate_document(&doc);
    println!("{}", serde_json::to_string_pretty(&report)?);
    if !report.ok() {
        std::process::exit(2);
    }
    Ok(())
}

fn cmd_analyze(
    input: &Path,
    vendor: &str,
    output: Option<&Path>,
    format: ReportFormat,
) -> Result<()> {
    let doc = load_doc(input, vendor)?;
    let report = analyze(&doc);
    let body = match format {
        ReportFormat::Json => serde_json::to_string_pretty(&report)?,
        ReportFormat::Markdown => report_markdown(&doc, &report),
        ReportFormat::Html => report_html(&doc, &report),
    };
    write_out(output, &body)?;
    Ok(())
}

fn cmd_diff(left: &Path, right: &Path, vendor: &str, output: Option<&Path>) -> Result<()> {
    let l = load_doc(left, vendor)?;
    let r = load_doc(right, vendor)?;
    let report = diff_documents(
        &l,
        &r,
        left.file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "left".into()),
        right
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "right".into()),
    );
    write_out(output, &serde_json::to_string_pretty(&report)?)?;
    Ok(())
}

fn cmd_project(cmd: ProjectCmd) -> Result<()> {
    match cmd {
        ProjectCmd::List { dir } => {
            let dir = dir.unwrap_or_else(default_projects_dir);
            let items = list_projects(&dir)?;
            println!("{}", serde_json::to_string_pretty(&items)?);
        }
        ProjectCmd::Save {
            input,
            name,
            vendor,
            dir,
            id,
        } => {
            let dir = dir.unwrap_or_else(default_projects_dir);
            let doc = load_doc(&input, &vendor)?;
            let stored = save_project(&dir, name, doc, id, None)?;
            println!("{}", serde_json::to_string_pretty(&stored)?);
            eprintln!("saved {}", stored.id);
        }
        ProjectCmd::Show { id, dir } => {
            let dir = dir.unwrap_or_else(default_projects_dir);
            let p = load_project(&dir, &id)?;
            println!("{}", serde_json::to_string_pretty(&p)?);
        }
        ProjectCmd::Export {
            id,
            output,
            format,
            dir,
        } => {
            let dir = dir.unwrap_or_else(default_projects_dir);
            let p = load_project(&dir, &id)?;
            emit_doc(&p.document, Some(&output), format)?;
        }
        ProjectCmd::Delete { id, dir } => {
            let dir = dir.unwrap_or_else(default_projects_dir);
            delete_project(&dir, &id)?;
            eprintln!("deleted {id}");
        }
    }
    Ok(())
}

fn emit_doc(
    doc: &interstellar_ir::PolicyDocument,
    output: Option<&Path>,
    format: OutFormat,
) -> Result<()> {
    let xml = emit_panos_xml(doc);
    let set = emit_set_commands(doc);
    let ir_json = serde_json::to_string_pretty(doc)?;
    match format {
        OutFormat::Xml => write_out(output, &xml)?,
        OutFormat::Set => write_out(output, &set)?,
        OutFormat::Ir => write_out(output, &ir_json)?,
        OutFormat::Both => {
            if let Some(path) = output {
                let xml_path = path_with_suffix(path, "xml");
                let set_path = path_with_suffix(path, "set.txt");
                std::fs::write(&xml_path, &xml)?;
                std::fs::write(&set_path, &set)?;
                eprintln!("wrote {} and {}", xml_path.display(), set_path.display());
            } else {
                println!("===== XML =====\n{xml}\n===== SET =====\n{set}");
            }
        }
    }
    Ok(())
}

fn write_out(output: Option<&Path>, data: &str) -> Result<()> {
    match output {
        Some(path) => {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            std::fs::write(path, data).with_context(|| format!("write {}", path.display()))?;
            eprintln!("wrote {}", path.display());
        }
        None => print!("{data}"),
    }
    Ok(())
}

fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "out".into());
    path.with_file_name(format!("{stem}.{suffix}"))
}

fn resolve_static_dir(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    let candidates = [
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../web/static"),
        PathBuf::from("web/static"),
        PathBuf::from("../web/static"),
        PathBuf::from("../../web/static"),
    ];
    for c in candidates {
        if c.join("index.html").is_file() {
            return Ok(c.canonicalize().unwrap_or(c));
        }
    }
    let dir = std::env::temp_dir().join("interstellar-ui");
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("index.html"), DEFAULT_UI)?;
    Ok(dir)
}

const DEFAULT_UI: &str = include_str!("../../../web/static/index.html");
