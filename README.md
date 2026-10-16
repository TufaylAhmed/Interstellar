# Interstellar

**Interstellar** converts multi-vendor firewall configs to **PAN-OS XML** and **set commands**.

Standalone Rust project — **not** part of PA-Converter / Expedition. No PHP.

| Platform | Binary |
|----------|--------|
| macOS | `interstellar` |
| Windows | `interstellar.exe` |
| Linux | `interstellar` |

## Features

1. **Convert** — Fortinet · Cisco ASA · Check Point · PAN-OS → XML / set / IR JSON  
2. **NAT · VPN · profiles** — source/dest NAT, IKE/IPsec stubs, profile groups  
3. **Local UI + API** — `interstellar serve` on `http://127.0.0.1:8787`  
4. **Analyze** — unused objects, shadow hints, broad allows, duplicate rules  
5. **Validate** — missing refs, duplicates, empty docs  

## Build

```bash
# Rust via rustup: https://rustup.rs
cargo build --release
./target/release/interstellar --help
```

Windows (PowerShell):

```powershell
cargo build --release
.\target\release\interstellar.exe --help
```

## CLI

```bash
interstellar convert fixtures/fortinet/sample.conf -o out.xml
interstellar convert fixtures/cisco/sample.cfg --format both --ir -o cisco
interstellar validate fixtures/checkpoint/sample.json
interstellar analyze fixtures/fortinet/sample.conf
interstellar summary fixtures/panos/sample.xml
interstellar serve --bind 127.0.0.1:8787
```

## API

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/health` | liveness |
| POST | `/api/convert` | JSON body `{ vendor?, content, name? }` |
| POST | `/api/upload` | multipart `file` + optional `vendor` |
| GET | `/api/projects` | in-memory project list |
| GET | `/api/projects/{id}/xml` | exported XML |
| GET | `/api/projects/{id}/set` | set commands |

## Layout

```
Interstellar/
├── crates/
│   ├── interstellar-ir
│   ├── interstellar-parse
│   ├── interstellar-emit
│   ├── interstellar-analyze
│   ├── interstellar-api
│   └── interstellar-cli      → binary `interstellar`
├── fixtures/
└── web/static/
```

## Relation to PA-Converter

| | PA-Converter | Interstellar |
|--|--------------|--------------|
| Purpose | Package/run Expedition | Native config conversion |
| Stack | PHP / Podman / WSL | Pure Rust |
| This repo | Separate | **This project** |

Do **not** merge Interstellar into the PA-Converter repository.

## License

UNLICENSED — private / lab use unless otherwise published by the author.
