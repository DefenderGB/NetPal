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
- **playwright** — headless Chromium browser for HTTP response capture and screenshots (installed as a Python dependency)
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

The uninstaller removes the `.venv/` environment, sudoers rules, and optionally cleans up external tools (nmap, nuclei, Go, uv). All optional prompts default to No.

## Usage

Running `netpal` with no arguments shows the project dashboard and suggests the next step. Every subcommand prints a contextual "next command" suggestion so you always know what to run next.

Each subcommand has its own `--help` — run `netpal <command> --help` for detailed options and examples.

An alternative interactive terminal UI is also available via `netpal interactive` (requires the `textual` package).

The TUI can also be served as a web application in the browser via `netpal website` (uses `textual-serve` on port 7123).

```
usage: netpal [-h] [-s] [-ns] [-p PROJECT] [-v] [-c CONFIG] {init,list,set,rename,assets,recon,ai-review,ai-report-enhance,setup,findings,hosts,pull,delete,interactive,website,auto} ...

NetPal — Automated Network Penetration Testing CLI Tool

positional arguments:
  {init,list,set,rename,assets,recon,ai-review,ai-report-enhance,setup,findings,hosts,pull,delete,interactive,website,auto}
                        Available commands
    init                Create a new project and set it as active
    list                List all projects (local and S3)
    set                 Switch the active project
    rename              Rename an existing project
    assets              Create and manage assets (networks, hosts, credentials)
    recon               Run reconnaissance and scanning workflows
    ai-review           AI-powered review and analysis of scan results
    ai-report-enhance   AI enhancement of existing findings
    setup               Interactive configuration wizard
    findings            View and manage security findings
    hosts               View discovered hosts, services, and evidence
    pull                Pull projects from AWS S3
    delete              Delete a project and all its resources
    interactive         Launch the Textual-based interactive TUI
    website             Serve the Textual TUI as a web application
    auto                Fully automated scan pipeline (project → asset → discovery → recon → hosts)

options:
  -h, --help            show this help message and exit
  -s, --sync            Enable AWS S3 sync
  -ns, --no-sync        Disable AWS S3 sync
  -p PROJECT, --project PROJECT
                        Override active project name
  -v, --verbose         Enable verbose output
  -c CONFIG, --config CONFIG
                        Update config.json with JSON string
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
netpal auto --range "10.0.0.0/24" --interface "eth0"

# Or specify a project name (creates or reuses an existing project)
netpal auto --project "Client Pentest" --range "10.0.0.0/24" --interface "eth0"

# Scan a list of hosts/IPs from a file
netpal auto --file targets.txt --interface "eth0" --asset-name "Server List"

# Both a CIDR range and a file at once
netpal auto --range "10.0.0.0/24" --file extra_hosts.txt --interface "eth0"
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

### Collaborating Workflow

```bash
# 1. Configure AWS netpal-user profile
aws configure set aws_access_key_id \"YOUR_KEY\" --profile netpal-user
aws configure set aws_secret_access_key \"YOUR_SECRET\" --profile netpal-user
ws configure set region us-west-2 --profile netpal-user
netpal --config '{"aws_sync_account": "123456789012", "aws_sync_profile": "netpal-user"}'

# 2. Pull project from S3
netpal pull # To get project name or ID
netpal pull -id "NETP-2002-ABCD"

# 3. Set project as your primary
netpal set "NETP-2002-ABCD"

# 4. View hosts/findings
netpal hosts
netpal findings
netpalui # or use flask app to view hosts and findings
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
            ├── auto_playwright_*.txt
            ├── auto_playwright_*.png
            └── nuclei_*.jsonl
```

## Troubleshooting

```bash
# Permission errors — sudo credentials will be requested automatically for nmap
netpal recon --asset DMZ --type top100

# Tool not found — add Go binaries to PATH
export PATH=$PATH:~/go/bin

# AI not working — verify provider config
netpal setup

# Playwright errors — install Chromium browser for Playwright
playwright install chromium

# Passwordless sudo for nmap — install.sh offers to configure this automatically.
# To set up manually:
sudo sh -c "echo '$USER ALL=(ALL) NOPASSWD: $(which nmap), $(which chown)' > /etc/sudoers.d/netpal-$USER"
sudo chmod 0440 /etc/sudoers.d/netpal-$USER

# If on Mac, screenshots error out with "Call log: navigating to "{url}", waiting until "networkidle"
# This may be caused by Local Network app access
tccutil reset SystemPolicyNetworkVolumes
# Then close app, re-open, try to run, and will get prompt with 'Allow "App" to find devices on local network?'

# If on Mac, nuclei is not running, open "Settings" app > Privacy and Security. Then scroll down under "Security" and select "Allow Anyways" under nuclei
```

## Contributing

See [CONTRIBUTION.md](CONTRIBUTION.md) for project structure, code style, and how to add custom tools.

## Support

- **Contact**: defender-gb@protonmail.com

## License

MIT License - see LICENSE file for details.

## Credits

NetPal was created by Gustavo Bobbio-Hertog (defendergb)
