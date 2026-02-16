# NetPal — Automated Network Pentest Tool

NetPal is a CLI network pentest automation tool and AI copilot for network penetration testers. It automates network reconnaissance, service enumeration, exploit tool execution, and AI-powered guide which also helps with pentest reporting.

## Security Disclaimer

- **Authorization**: Verify you have permission before scanning any target.
- **Exclusions**: Use `--exclude` to protect critical infrastructure — supports IPs and CIDR ranges (e.g. `10.0.10.0/24` or `10.0.0.20`). (Or update `netpal/config/config.json`) Can also exclude ports: `--exclude-ports`
- **Data**: Project files and AI-submitted evidence may contain sensitive information — protect accordingly.

## Requirements

- Linux or macOS
- Python 3.12
- [**uv**](https://docs.astral.sh/uv/) — Python package manager (installed automatically by `install.sh`)
- **nmap** — network discovery and port scanning (sudo required for SYN scans)
- **httpx** — ProjectDiscovery HTTP toolkit for screenshots and responses
- **nuclei** — vulnerability scanning with templates

## Installation

```bash
git clone https://github.com/DefenderGB/NetPal.git
cd NetPal
bash install.sh
source .venv/bin/activate
netpal setup
```

## Uninstallation

```bash
bash uninstall.sh
```

The uninstaller removes the `.venv/` environment, sudoers rules, and optionally cleans up external tools (nmap, httpx, nuclei, Go, uv). All optional prompts default to No.

## Usage

Running `netpal` with no arguments shows the project dashboard and suggests the next step. Every subcommand prints a contextual "next command" suggestion so you always know what to run next.

Each subcommand has its own `--help` — run `netpal <command> --help` for detailed options and examples.

An alternative interactive terminal UI is also available via `netpal interactive` (requires the `textual` package).

The TUI can also be served as a web application in the browser via `netpal website` (uses `textual-serve` on port 7123).

```
usage: netpal [-h] [--sync] [--no-sync] [--project PROJECT] [--verbose]
              [--config CONFIG]
              {init,list,set,assets,recon,auto,ai-review,ai-report-enhance,setup,findings,hosts,pull,delete,interactive,website} ...

NetPal — Automated Network Penetration Testing CLI Tool

positional arguments:
  {init,list,set,assets,recon,auto,ai-review,ai-report-enhance,setup,findings,hosts,pull,delete,interactive,website}
    init                Create a new project and set it as active
    list                List all projects (local and S3)
    set                 Switch the active project by name or UUID prefix
    assets              Create and manage assets (networks, hosts, lists)
    recon               Run reconnaissance and scanning workflows
    auto                Fully automated scan pipeline (project → asset → discovery → recon → hosts)
    ai-review           AI-powered review and analysis of scan results
    ai-report-enhance   AI enhancement of existing findings
    setup               Interactive configuration wizard
    findings            View and manage security findings
    hosts               View discovered hosts, services, and evidence
    pull                Pull projects from AWS S3
    delete              Delete a project and all its resources
    interactive         Launch the interactive terminal UI using Textual
    website             Serve the Textual TUI as a web application

options:
  -h, --help            show this help message and exit
  --sync                Enable AWS S3 sync
  --no-sync             Disable AWS S3 sync
  --project PROJECT     Override active project name
  --verbose             Enable verbose output
  --config CONFIG       Update config.json with JSON string
```

## Workflow

The standard workflow follows this pipeline:

```
setup → init → assets → recon → ai-review → ai-report-enhance → findings / hosts
```

### Quick Start — Fully Automated Pipeline

```bash
# One command does it all: create project, create asset, discover hosts,
# run top-1000 + netsec scans, and display results
netpal auto --project "HTB Prolabs" --range "10.0.0.0/24" --interface "eth0"

# Or Scan a list of hosts/IPs from a file
netpal auto --file bugbounty_targets.txt --interface "eth0" --asset-name "Bounty List"
```

### Step-by-Step Workflow

```bash
# 1. Configure NetPal (first run)
netpal setup

# 2.a (Faster) Use interactive UI to create project, create asset, run recon, generate AI findings, and Enhance findings
netpal interactive        # Terminal TUI
netpal website            # Web UI on http://localhost:7123

# 2.b Create a project
netpal init --name "My Pentest"

# 3. Create a scan target
netpal assets network --name DMZ --range "10.0.0.0/24"

# 4. Discover hosts
netpal recon --asset DMZ --type nmap-discovery

# 5. Scan services (by asset, discovered hosts, or single host)
netpal recon --discovered --type top100 # Recon against every discovered host
netpal recon --asset DMZ --type top100 # Recon against every IP regardless if discovered or not
netpal recon --discovered --asset DMZ --type top100 # Recon against discovered host in a specific asset
netpal recon --host 10.0.0.5 --type top100 # Recon against a specific host/IP

# 5b. Control auto-tool re-run behaviour (default: 2 days)
netpal recon --discovered --type top100 --rerun-autotools 2   # Re-run tools if last run > 2 days ago (default)
netpal recon --discovered --type top100 --rerun-autotools Y   # Always re-run tools
netpal recon --discovered --type top100 --rerun-autotools N   # Never re-run tools
netpal recon --discovered --type top100 --rerun-autotools 7   # Re-run tools if last run > 7 days ago

# 6. Generate AI findings
netpal ai-review

# 7. Enhance findings
netpal ai-report-enhance

# 8. View results
netpal findings
netpal hosts
```

## Scan Types

| Type | Description |
|---|---|
| `nmap-discovery` | Ping sweep to find live hosts |
| `top100` | 100 most common ports |
| `top1000` | 1000 most common ports |
| `http` | Web service ports only |
| `netsec` | Common security assessment ports |
| `allports` | Full 1–65535 scan (auto-chunks large networks) |
| `custom` | Your own nmap options via `--nmap-options` |

## AI Providers

NetPal supports AWS Bedrock, Anthropic, OpenAI, Ollama, Azure OpenAI, and Google Gemini. Configure through `netpal setup` or directly in `config.json`.

## AWS S3 Sync

Enable cloud sync for collaborative testing. Projects sync automatically after each phase.

```bash
# Pull projects from S3
netpal pull --all
netpal pull --id <project-uuid>

# Update config for AWS
netpal --config '{"aws_sync_account": "123456789012", "aws_sync_profile": "netpal-user"}'
```

## Results Structure

```
scan_results/
├── <project_id>.json              # Project data
├── <project_id>_findings.json     # Security findings
├── projects.json                  # Project registry
└── <project_id>/                  # Scan evidence
    └── <asset>/
        ├── scan_*.xml
        └── auto_tools/
            ├── auto_httpx_*.txt
            ├── auto_httpx_*.png
            └── nuclei_*.jsonl
```

## Troubleshooting

```bash
# Nmap Permission errors - Setup Passordless sudo
sudo sh -c "echo '$USER ALL=(ALL) NOPASSWD: $(which nmap), $(which chown)' > /etc/sudoers.d/netpal-$USER"
sudo chmod 0440 /etc/sudoers.d/netpal-$USER

# Tool not found — add Go binaries to PATH
export PATH=$PATH:~/go/bin

# AI not working — verify provider config
netpal setup

# httpx errors — install chromium
sudo apt install chromium-browser
```

## Contributing

See [CONTRIBUTION.md](CONTRIBUTION.md) for project structure, code style, and how to add custom tools.

## Support

- **Issues**: https://github.com/DefenderGB/NetPal/issues
- **Developer Questions**: defender-gb@protonmail.com

## License

MIT License - see LICENSE file for details.

## Credits

NetPal was created by Gustavo Bobbio-Hertog (defendergb)
