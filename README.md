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
- **playwright** — headless Chromium browser for HTTP response capture and screenshots (the installer also downloads Chromium)
- **nuclei** — vulnerability scanning with templates

## Installation

### One-Liner Install

```bash
curl -sSL https://raw.githubusercontent.com/DefenderGB/NetPal/refs/heads/main/install.sh | bash
```

This clones the repo into `~/tools/NetPal`, installs all dependencies, and sets up the environment.
If `.venv` already exists, the installer now refreshes dependencies and re-runs the Playwright Chromium install step.

### Manual Install

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

An alternative interactive terminal UI is also available via `netpal interactive` or `netpal tui` (requires the `textual` package, `nmap`, and a working Playwright Chromium install). The current TUI is a dense operator-style dashboard built on Textual; its public entrypoint remains `netpal.tui`, while the internal implementation lives under `netpal/textual_ui/`.

The browser UI is available via `netpal website` and the compatibility alias `netpalui`. Both launch the Flask operator UI on port `5001` and perform the same `nmap`/Playwright startup check as `netpal interactive`.

```text
usage: netpal [-h] [-p PROJECT] [-v] [-c CONFIG] {init,list,set,project-edit,assets,recon,recon-tools,ai-review,ai-report-enhance,setup,findings,hosts,export,delete,interactive,tui,website,auto,ad-scan,testcase} ...

NetPal — Automated Network Penetration Testing CLI Tool

positional arguments:
  {init,list,set,project-edit,assets,recon,recon-tools,ai-review,ai-report-enhance,setup,findings,hosts,export,delete,interactive,tui,website,auto,ad-scan,testcase}
                        Available commands
    init                Create a new project and set it as active
    list                List all local projects
    set                 Switch the active project
    project-edit        Interactively edit the active project
    assets              Create and manage assets (networks, hosts, credentials)
    recon               Run reconnaissance and scanning workflows
    recon-tools         List targets or run exploit tools against discovered hosts
    ai-review           AI-powered review and analysis of scan results
    ai-report-enhance   AI enhancement of existing findings
    setup               Interactive configuration wizard
    findings            View and manage security findings
    hosts               View discovered hosts, services, and evidence
    export              Export project scan results as a zip archive
    delete              Delete a project and all its resources
    interactive         Launch the Textual-based interactive TUI
    tui                 Launch the Textual-based interactive TUI (alias)
    website             Launch the Flask web operator UI
    auto                Fully automated scan pipeline (project → asset → discovery → recon → hosts)
    ad-scan             Run Active Directory LDAP scan (BloodHound output)
    testcase            Manage test case checklists for the active project

options:
  -h, --help            show this help message and exit
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

# 2.a (Faster) Use interactive UI to create project, set AD metadata, optionally seed an asset, run recon, generate AI findings, and Enhance findings
netpal interactive        # Terminal TUI
netpal tui                # Terminal TUI alias
netpal website            # Web UI on http://localhost:5001

# 2.b Create a project
netpal init "My Pentest"

# 3. Create a scan target
netpal assets network --name DMZ --range "10.0.0.0/24"

# 4. Discover hosts
netpal recon --asset DMZ --type nmap-discovery
netpal recon --asset DMZ --type discover

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

# 9. Optional: run a local AD scan
netpal project-edit
netpal ad-scan --username 'CORP\\tester' --password 'P@ssw0rd'
netpal ad-scan --domain HTB.LOCAL --dc-ip 10.10.10.161 --auth-type anonymous --output-types users
netpal ad-scan --domain HTB.LOCAL --dc-ip 10.10.10.161 --auth-type anonymous --filter 'objectClass=*'

# 10. Optional: track testcase status locally
netpal testcase --load --csv-path ./testcases.csv
netpal testcase --set-result enumeration--check-anonymous-access passed --notes "Validated manually"
netpal testcase --results
```

### Managing Local Projects

```bash
# List projects stored on disk
netpal list

# Switch active project
netpal set "My Pentest"

# Update the active project's name, description, external tracking ID, or AD metadata
netpal project-edit

# View hosts/findings
netpal hosts
netpal findings

# Create or update asset descriptions
netpal assets single --name JumpHost --target 10.0.0.20 --description "Operator bastion"
netpal assets --edit-description JumpHost --description "Rotated to new bastion"

# Export a project archive from local scan_results/
netpal export "My Pentest"
```

## Scan Types

| Type | Description |
|---|---|
| `nmap-discovery` | Ping sweep to find live hosts |
| `discover` | Combined ping sweep plus common-port host discovery |
| `top100` | 100 most common ports |
| `top1000` | 1000 most common ports |
| `http` | Web service ports only |
| `netsec` | Common security assessment ports |
| `allports` | Full 1–65535 scan (auto-chunks large networks) |
| `custom` | Your own nmap options via `--nmap-options` |

## AI Providers

NetPal supports AWS Bedrock, Anthropic, OpenAI, Ollama, Azure OpenAI, and Google Gemini. Configure your provider through `netpal setup` or directly in `config.json`.

For AWS Bedrock, use `ai_type: "aws"` plus the Bedrock settings such as `ai_aws_profile`, `ai_aws_region`, and `ai_aws_model`.

## Local-Only Feature Surface

This repo is intentionally local-only.

- Included: local project storage, recon, exploit-tool evidence, AI review/enhancement, manual findings, AD LDAP collection, testcase tracking, TUI/web UI, MCP, and local export.
- Excluded: `upload`, `pull`, `push`, cloud sync, S3-backed storage, and internal-only/Midway workflows.

## Local Storage

NetPal now stores projects, findings, and evidence locally under `scan_results/`. On startup it also removes legacy cloud-sync metadata from existing `config.json`, `scan_results/projects.json`, and local project JSON files.

Additional local data paths:

- Project descriptions live in `metadata.description`.
- Asset descriptions live alongside each asset entry in the project JSON.
- Testcase registries live in `scan_results/<project_id>_testcases.json`.
- AD outputs live in `scan_results/<project_id>/ad_scan/`.

In the web UI, the `Test Cases` page accepts either a direct CSV upload or a local CSV path. Uploaded CSVs are copied into `scan_results/<project_id>/uploads/` before loading.

## Active Directory Scanning

Use `netpal ad-scan` to run local LDAP collection and produce BloodHound-compatible JSON for the active project.

- Recon scans that see `ldap` or `microsoft-ds` banners will auto-fill a missing project `ad_domain` and enrich the matching host with discovered `hostname`, `metadata.product`, and `metadata.ostype` when those fields are still empty.
- Auto tools can reuse that AD metadata via `{domain}`, `{domain_dn}`, or indexed `{domain0}`, `{domain1}`, ... placeholders inside `netpal/config/exploit_tools.json`.
- Set `ad_domain` and `ad_dc_ip` first with `netpal project-edit` or the TUI project editor.
- Dependencies include `ldap3` and `pycryptodome`.
- Anonymous scans are supported. When NetPal detects an anonymous bind, it automatically skips `nTSecurityDescriptor`/ACL collection so user and object enumeration can still complete.
- Anonymous bind is only used when you explicitly select anonymous auth. NTLM and Kerberos modes now fail fast when the required auth material is missing.
- Custom LDAP filters accept either full RFC-style filters like `(sAMAccountName=admin)` or bare expressions like `objectClass=*`.
- Custom LDAP query output is written under `scan_results/<project_id>/ad_scan/ad_queries/`.

## Auto Tool Credentials

Auto tools can optionally pull credentials from a local `netpal/config/creds.json` when a tool command uses `{username}` and/or `{password}`.

- `netpal/config/creds.json.example` is tracked in git as the template.
- `netpal/config/creds.json` is gitignored and auto-created from the example the first time NetPal loads auto-tool credentials.

- Each credential entry uses `username`, `password`, `type`, and `use_in_auto_tools`.
- Supported credential `type` values are `all`, `domain`, and `web`.
- Tool configs may add `cred_type` to restrict which enabled credentials are used. Omit it or set it to an empty string to try all enabled credential types.
- Passwords are masked in MCP config resources and auto-tool command metadata, but remain stored in `creds.json` for execution.
- In the Textual TUI, use the dedicated `Credentials` view to review and add entries instead of editing `creds.json` in `Settings`.

Example `creds.json.example`:

```json
[
  {
    "username": "test",
    "password": "test",
    "type": "domain",
    "use_in_auto_tools": false
  },
  {
    "username": "webtest",
    "password": "test",
    "type": "web",
    "use_in_auto_tools": false
  }
]
```

Example credential-aware auto tool:

```json
{
  "port": [445],
  "service_name": ["microsoft-ds", "smb"],
  "tool_name": "SMB Auth Check",
  "tool_type": "command_custom",
  "cred_type": "domain",
  "command": "crackmapexec smb {ip} -u \"{username}\" -p \"{password}\""
}
```

## Test Case Tracking

Use `netpal testcase` for local checklist management.

- `--load --csv-path` imports test cases from CSV.
- `--set-result ... --notes ...` updates local status and notes.
- `--results` shows grouped status, optionally filtered by `--phase` or `--status`.

CSV is the only testcase import mode in this repo. There is no config-backed testsuite catalog.

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

# Playwright errors — reinstall the bundled Playwright browser runtime
uv run playwright install chromium
# Or rerun the full installer, which now verifies Playwright can launch
bash install.sh

# Privileged nmap execution — install.sh can configure Linux capabilities automatically.
# Fallback: passwordless sudo for nmap + chown.
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
