use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use interstellar_analyze::analyze;
use interstellar_emit::{emit_panos_xml, emit_set_commands, validate_document};
use interstellar_parse::{parse_file, parse_vendor_str, DetectedVendor};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "interstellar",
    version,
    about = "Interstellar — convert Fortinet / Cisco / Check Point / PAN-OS configs to PAN-OS XML"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Convert a vendor config file to PAN-OS XML and/or set-commands
    Convert {
        /// Input config file
        input: PathBuf,
        /// Output path (default: stdout for chosen format)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Force vendor (auto|fortinet|cisco|checkpoint|panos)
        #[arg(long, default_value = "auto")]
        vendor: String,
        /// Output format
        #[arg(long, value_enum, default_value_t = OutFormat::Xml)]
        format: OutFormat,
        /// Also write IR JSON next to output (or <input>.ir.json)
        #[arg(long)]
        ir: bool,
        /// Run validation and print report to stderr
        #[arg(long, default_value_t = true)]
        validate: bool,
    },
    /// Validate a vendor or PAN-OS config without writing output
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
    },
    /// Start local UI + HTTP API (macOS / Windows / Linux)
    Serve {
        #[arg(long, default_value = "127.0.0.1:8787")]
        bind: String,
        /// Directory with static UI files
        #[arg(long)]
        static_dir: Option<PathBuf>,
    },
    /// Show parsed summary counts
    Summary {
        input: PathBuf,
        #[arg(long, default_value = "auto")]
        vendor: String,
    },
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum OutFormat {
    Xml,
    Set,
    Both,
    Ir,
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
        } => cmd_convert(&input, output.as_deref(), &vendor, format, ir, validate)?,
        Commands::Validate { input, vendor } => cmd_validate(&input, &vendor)?,
        Commands::Analyze {
            input,
            vendor,
            output,
        } => cmd_analyze(&input, &vendor, output.as_deref())?,
        Commands::Serve { bind, static_dir } => {
            let addr: SocketAddr = bind.parse().context("invalid --bind address")?;
            let static_dir = resolve_static_dir(static_dir)?;
            interstellar_api::serve(addr, static_dir).await?;
        }
        Commands::Summary { input, vendor } => cmd_summary(&input, &vendor)?,
    }
    Ok(())
}

fn parse_input(input: &Path, vendor: &str) -> Result<(interstellar_ir::PolicyDocument, Option<DetectedVendor>)> {
    let forced = parse_vendor_str(vendor)?;
    let doc = parse_file(input, forced)?;
    Ok((doc, forced))
}

fn cmd_convert(
    input: &Path,
    output: Option<&Path>,
    vendor: &str,
    format: OutFormat,
    write_ir: bool,
    do_validate: bool,
) -> Result<()> {
    let (doc, _) = parse_input(input, vendor)?;
    if do_validate {
        let report = validate_document(&doc);
        eprintln!(
            "validation: {} issue(s), {} error(s)",
            report.issues.len(),
            report.error_count()
        );
        for issue in &report.issues {
            eprintln!(
                "  [{:?}] {}: {}{}",
                issue.severity,
                issue.code,
                issue.message,
                issue
                    .object
                    .as_ref()
                    .map(|o| format!(" ({o})"))
                    .unwrap_or_default()
            );
        }
    }

    let xml = emit_panos_xml(&doc);
    let set = emit_set_commands(&doc);
    let ir_json = serde_json::to_string_pretty(&doc)?;

    match format {
        OutFormat::Xml => write_out(output, &xml)?,
        OutFormat::Set => write_out(output, &set)?,
        OutFormat::Ir => write_out(output, &ir_json)?,
        OutFormat::Both => {
            if let Some(path) = output {
                let xml_path = path_with_suffix(path, "xml");
                let set_path = path_with_suffix(path, "set.txt");
                std::fs::write(&xml_path, &xml)
                    .with_context(|| format!("write {}", xml_path.display()))?;
                std::fs::write(&set_path, &set)
                    .with_context(|| format!("write {}", set_path.display()))?;
                eprintln!("wrote {} and {}", xml_path.display(), set_path.display());
            } else {
                println!("===== XML =====\n{xml}\n===== SET =====\n{set}");
            }
        }
    }

    if write_ir {
        let ir_path = match output {
            Some(p) => path_with_suffix(p, "ir.json"),
            None => input.with_extension("ir.json"),
        };
        std::fs::write(&ir_path, ir_json)
            .with_context(|| format!("write {}", ir_path.display()))?;
        eprintln!("wrote IR {}", ir_path.display());
    }

    let s = doc.summary();
    eprintln!(
        "ok: vendor={:?} addresses={} groups={} services={} rules={} nat={}",
        s.vendor,
        s.addresses,
        s.address_groups,
        s.services,
        s.security_rules,
        s.nat_rules
    );
    Ok(())
}

fn cmd_validate(input: &Path, vendor: &str) -> Result<()> {
    let (doc, _) = parse_input(input, vendor)?;
    let report = validate_document(&doc);
    println!("{}", serde_json::to_string_pretty(&report)?);
    if !report.ok() {
        std::process::exit(2);
    }
    Ok(())
}

fn cmd_analyze(input: &Path, vendor: &str, output: Option<&Path>) -> Result<()> {
    let (doc, _) = parse_input(input, vendor)?;
    let report = analyze(&doc);
    let json = serde_json::to_string_pretty(&report)?;
    write_out(output, &json)?;
    Ok(())
}

fn cmd_summary(input: &Path, vendor: &str) -> Result<()> {
    let (doc, _) = parse_input(input, vendor)?;
    println!("{}", serde_json::to_string_pretty(&doc.summary())?);
    Ok(())
}

fn write_out(output: Option<&Path>, data: &str) -> Result<()> {
    match output {
        Some(path) => {
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
    // Prefer repo web/static next to CARGO_MANIFEST_DIR at build time; at runtime walk up.
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
    // Create a temp dir with embedded HTML
    let dir = std::env::temp_dir().join("interstellar-ui");
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("index.html"), DEFAULT_UI)?;
    Ok(dir)
}

const DEFAULT_UI: &str = include_str!("../../../web/static/index.html");
