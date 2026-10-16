# Interstellar

**Interstellar** converts multi-vendor firewall configs to **PAN-OS XML** and **set commands**.

Standalone Rust project — **not** part of PA-Converter / Expedition. No PHP.

| Platform | Binary |
|----------|--------|
| macOS | `interstellar` |
| Windows | `interstellar.exe` |
| Linux | `interstellar` |

## Features (v0.2)

| Area | Commands / API |
|------|----------------|
| Convert | Fortinet · Cisco ASA · Check Point · Juniper SRX · PAN-OS → XML / set / IR |
| Transforms | `--zone-map`, `--dedup` |
| Batch | `interstellar batch <dir> -o <outdir>` |
| Diff | `interstellar diff a.conf b.conf` |
| Analyze | JSON / Markdown / HTML reports |
| Projects | Save/load under `~/.interstellar/projects` |
| UI + API | `interstellar serve` on `127.0.0.1:8787` |

## Install (npm)

```bash
# public npm
npm i -g @sequr3/interstellar

# or one-shot
npx @sequr3/interstellar --help

# or from GitHub
npx --yes github:TufaylAhmed/Interstellar --help
```

On macOS, `postinstall` downloads the matching binary from [GitHub Releases](https://github.com/TufaylAhmed/Interstellar/releases).  
Windows/Linux prebuilds will be added to releases when available; until then build with Cargo (below).

## Build (from source)

```bash
cargo build --release
./target/release/interstellar --help
```

## CLI examples

```bash
# convert + zone map + dedup + save project
interstellar convert fixtures/fortinet/sample.conf \
  --zone-map wan1=untrust,internal=trust --dedup \
  --save-as lab-fg -o /tmp/fg.xml

# juniper
interstellar convert fixtures/junos/sample.set --vendor juniper -o /tmp/srx.xml

# batch a folder
interstellar batch fixtures -o /tmp/batch-out --format both

# analyze as markdown
interstellar analyze fixtures/cisco/sample.cfg --format markdown -o report.md

# diff two configs
interstellar diff fixtures/fortinet/sample.conf fixtures/cisco/sample.cfg

# projects
interstellar project list
interstellar project save fixtures/panos/sample.xml --name pan-lab
interstellar project export <id> -o /tmp/exported.xml

# UI
interstellar serve
```

## API

| Method | Path |
|--------|------|
| GET | `/api/health` |
| POST | `/api/convert` · `/api/upload` · `/api/diff` |
| GET | `/api/projects` · `/api/projects/{id}` · `/xml` · `/set` · `/report` |
| GET/POST/DELETE | `/api/disk/projects` |

Env: `INTERSTELLAR_HOME` overrides `~/.interstellar`.

## Layout

```
Interstellar/
├── crates/interstellar-{ir,parse,emit,analyze,api,cli}
├── fixtures/{fortinet,cisco,checkpoint,junos,panos}
└── web/static/
```

## Relation to PA-Converter

Interstellar is a **separate** native converter. Do not merge into PA-Converter.

## License

UNLICENSED — private / lab use unless otherwise published by the author.
