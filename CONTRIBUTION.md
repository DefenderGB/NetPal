# Contributing to NetPal

This guide covers the project structure and how to extend NetPal.

NetPal is local-only in this repo:

- Do add local project, AD, testcase, TUI, MCP, and evidence features.
- Do not add `upload`, `pull`, `push`, cloud sync, S3 storage, or internal-only/Midway flows back into the codebase.

## Contact

**Developer**: defender-gb@protonmail.com

## Development Setup

### Quick Start (recommended)

The [`install.sh`](install.sh) script handles everything — installs **uv**, external tools (nmap and optionally nuclei), creates a Python 3.12 virtual environment, syncs dependencies (including Playwright), installs NetPal in editable mode, downloads the Chromium browser for Playwright, and verifies that Playwright can actually launch:

```bash
git clone https://github.com/DefenderGB/NetPal.git
cd NetPal
bash install.sh
source .venv/bin/activate
netpal setup
```

### Manual Setup (using uv directly)

If you already have the required external tools installed and prefer to set up the environment yourself:

```bash
git clone https://github.com/DefenderGB/NetPal.git
cd NetPal

# Install uv if not already available (https://docs.astral.sh/uv/)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create virtual environment pinned to Python 3.12
uv venv --python 3.12
source .venv/bin/activate

# Sync dependencies from pyproject.toml and install NetPal in editable mode
uv sync --python 3.12
uv pip install -e .

# Run the interactive configuration wizard
netpal setup
```

### Prerequisites

| Tool | Required | Notes |
|------|----------|-------|
| Python 3.12 | Yes | Managed by uv |
| [uv](https://docs.astral.sh/uv/) | Yes | Installed automatically by `install.sh` |
| nmap | Yes | SYN scans need elevated privileges; `install.sh` now prefers Linux capabilities and falls back to passwordless sudo |
| playwright | Yes | Python dependency; `install.sh` runs `playwright install chromium` automatically |
| Go | Optional | Required to install nuclei |
| nuclei | Yes | Vulnerability scanning with templates |

### Updating an Existing Install

If NetPal is already installed and you need to update in-place:

```bash
source .venv/bin/activate
uv sync --python 3.12
uv pip install -e .
```

To do a clean reinstall:

```bash
rm -rf .venv
bash install.sh
```

## Project Structure

```
netpal/
├── __init__.py
├── __main__.py                    # Entry: calls cli.main()
├── cli.py                         # CLI parser, routing, dashboard, bootstrap
├── tui.py                         # Public TUI shim / entrypoint — netpal interactive
├── textual_ui/                    # Internal Textual operator UI package
│   ├── app.py                     # App, modal, and view implementation
│   ├── components.py              # Shared TUI primitives
│   ├── helpers.py                 # Shared helpers and view constants
│   ├── styles.tcss                # Dense operator theme
│   └── theme.py                   # TCSS loader for exported APP_CSS
├── config/
│   ├── config.json                # Runtime configuration
│   ├── ai_prompts.json            # AI finding prompts
│   ├── creds.json.example         # Auto-tool credential template
│   ├── exploit_tools.json         # Tool automation config
│   └── recon_types.json           # Recon metadata + testcase port mapping
├── models/                        # Data models
│   ├── project.py                 # Project container
│   ├── asset.py                   # Scan target
│   ├── host.py                    # Discovered host
│   ├── service.py                 # Network service
│   ├── finding.py                 # Security finding
│   ├── test_case.py               # Test case entry
│   └── test_case_registry.py      # Project-local testcase registry
├── modes/                         # Subcommand handlers (Template Method)
│   ├── __init__.py                # Exports all handlers
│   ├── base_handler.py            # Abstract ModeHandler base class
│   ├── asset_create_handler.py    # netpal assets
│   ├── auto_handler.py            # netpal auto (fully automated pipeline)
│   ├── recon_cli_handler.py       # netpal recon
│   ├── recon_tools_handler.py     # netpal recon-tools
│   ├── ai_review_handler.py       # netpal ai-review
│   ├── ai_enhance_handler.py      # netpal ai-report-enhance
│   ├── findings_cli_handler.py    # netpal findings
│   ├── hosts_handler.py           # netpal hosts
│   ├── ad_scan_handler.py         # netpal ad-scan
│   ├── testcase_handler.py        # netpal testcase
│   ├── list_handler.py            # netpal list
│   ├── project_edit_handler.py    # netpal project-edit
│   ├── export_handler.py          # netpal export
│   ├── delete_handler.py          # netpal delete
│   └── setup_handler.py           # netpal setup
├── services/                      # Core services
│   ├── nmap_scanner.py            # Multi-threaded nmap (deprecated facade)
│   ├── tool_runner.py             # Tool automation (deprecated facade)
│   ├── xml_parser.py              # Nmap XML parsing + LDAP/microsoft-ds banner enrichment
│   ├── ai_analyzer.py             # AI analysis (deprecated facade)
│   ├── notification_service.py    # Webhook notifications
│   ├── ai/                        # AI provider system
│   │   ├── analyzer.py            # Main AI analyzer
│   │   ├── base_provider.py       # Abstract provider interface
│   │   ├── context_builder.py     # Builds AI context from evidence
│   │   ├── finding_enhancer.py    # AI QA enhancement
│   │   ├── provider_factory.py    # Creates provider instances
│   │   └── providers/             # Provider implementations
│   │       ├── anthropic_provider.py
│   │       ├── azure_provider.py
│   │       ├── bedrock_provider.py
│   │       ├── gemini_provider.py
│   │       ├── ollama_provider.py
│   │       └── openai_provider.py
│   ├── nmap/                      # Nmap subsystem
│   │   ├── command_builder.py     # Builds nmap command strings
│   │   └── scanner.py             # Scanner orchestrator (sequential execution)
│   ├── ad/                        # Local LDAP + BloodHound collection
│   ├── testcase/                  # CSV loading + testcase registry management
│   └── tools/                     # Tool runner subsystem
│       ├── base.py                # Abstract tool runner
│       ├── http_tool_runner.py    # HTTP-based tools
│       ├── playwright_runner.py   # Playwright (headless Chromium) integration
│       ├── nmap_script_runner.py  # Nmap NSE scripts
│       ├── nuclei_runner.py       # Nuclei vulnerability scanning
│       └── tool_orchestrator.py   # Coordinates tool execution
└── utils/                         # Shared utilities
    ├── ai_helpers.py              # AI workflow helpers
    ├── asset_factory.py           # Asset creation factory
    ├── aws/aws_utils.py           # Safe boto3 session helpers for Bedrock
    ├── config_loader.py           # JSON configuration management
    ├── display/                   # Banner, next-command box, formatting
    ├── image_loader.py            # Screenshot loading for AI
    ├── logger.py                  # Centralized logging (get_logger / setup_logging)
    ├── naming_utils.py            # Name sanitization
    ├── network_utils.py           # CIDR validation, subnet splitting
    ├── persistence/               # Local project/registry persistence helpers
    ├── scanning/                  # Recon execution helpers
    ├── setup_wizard.py            # Setup wizard logic
    ├── tool_paths.py              # External tool detection
    └── validation.py              # Input validation
```

## Architecture

### CLI Entry Point (`cli.py`)

The `main()` function in `cli.py` is the single entry point. It uses `argparse` subparsers for the `netpal <verb>` syntax:

```
netpal                          → display_dashboard()
netpal assets …                 → AssetCreateHandler
netpal recon …                  → ReconCLIHandler
netpal recon-tools …            → ReconToolsHandler
netpal auto …                   → AutoHandler
netpal ai-review …              → AIReviewHandler
netpal ai-report-enhance …     → AIEnhanceHandler
netpal findings …               → FindingsCLIHandler
netpal hosts …                  → HostsHandler
netpal ad-scan …                → ADScanHandler
netpal testcase …               → TestcaseHandler
netpal project-edit …           → ProjectEditHandler
netpal export …                 → ExportHandler
netpal setup                    → SetupHandler
netpal interactive              → tui.run_interactive()
```

The `_bootstrap_project(args)` helper loads config and the active local project. All subcommand routes (except `setup`, `list`, and the dashboard) call it first.

### Mode Handlers (`modes/`)

Every subcommand handler extends `ModeHandler` (Template Method pattern):

```python
class ModeHandler(ABC):
    def execute(self) -> int:
        self.display_banner()
        if not self.validate_prerequisites():
            return 1
        context = self.prepare_context()
        if context is None:
            return 1
        result = self.execute_workflow(context)
        if result:
            self.save_results(result)
            self.display_completion(result)
            self.suggest_next_command(result)  # ← next-step hint
        return 0 if result else 1
```

To add a new subcommand:

1. Create `netpal/modes/my_handler.py` extending `ModeHandler`
2. Implement the abstract methods: `display_banner()`, `validate_prerequisites()`, `prepare_context()`, `execute_workflow()`
3. Override `suggest_next_command()` to call `NextCommandSuggester`
4. Add a subparser in `create_argument_parser()` in `cli.py`
5. Add a routing entry in the `handlers` dict in `main()`
6. Export from `netpal/modes/__init__.py`

### AD Scan Notes

- `netpal ad-scan` supports anonymous LDAP enumeration across CLI, TUI, and MCP surfaces.
- Anonymous bind must stay opt-in via the explicit anonymous auth mode; NTLM/Kerberos should fail fast instead of silently falling back.
- Anonymous scans should skip `nTSecurityDescriptor` / ACL collection automatically unless the flow is being intentionally redesigned.
- Custom LDAP filters should continue accepting both full RFC-style filters like `(sAMAccountName=admin)` and bare expressions like `objectClass=*`.

### Next-Command Suggestion Engine (`utils/next_command.py`)

`NextCommandSuggester` prints a contextual "next step" box after each command. It has two modes:

- **Post-command** (`suggest(event, project, args)`): Looks up the event in `COMMAND_FLOW` and fills in template variables from args.
- **State-based** (`suggest_for_project(project, config)`): Inspects project state to determine what's missing.

The state machine:

```
no config       → netpal setup
no assets       → netpal asset-create
no hosts        → netpal recon --type nmap-discovery
no services     → netpal recon --type top100
no findings     → netpal ai-review
not enhanced    → netpal ai-report-enhance
enhanced        → netpal findings
```

### Asset Factory (`utils/asset_factory.py`)

Two factory methods:
- `create_asset(type, name, id, data)` — low-level creation
- `create_from_subcommand_args(args, project)` — subparser args (`--range`, `--targets`, `--target`, `--file`)

## Adding Custom Automated Tools

Tools are configured in `netpal/config/exploit_tools.json` and execute automatically when matching services are discovered.

### Tool Types

| Type | Description |
|---|---|
| `nmap_custom` | Custom nmap NSE scripts |
| `command_custom` | Generic command-based tools |
| `http_custom` | HTTP tools with regex triggers |
| `nuclei` | Nuclei vulnerability templates |

### Configuration Format

```json
{
  "port": [445, 139],
  "service_name": ["microsoft-ds", "netbios-ssn"],
  "tool_name": "SMB Vulnerability Scan",
  "tool_type": "nmap_custom",
  "dup_run": true,
  "command": "nmap -p {port} --script smb-vuln* {ip}"
}
```

### Placeholders

- `{ip}` — target IP
- `{port}` — port number
- `{protocol}` — `http` or `https`
- `{path}` — auto-generated output path
- `{domain}` — AD domain (for example `htb.local`)
- `{domain_dn}` — AD domain split into LDAP DN components (for example `dc=htb,dc=local`)
- `{domain0}`, `{domain1}`, ... — individual AD domain labels split on `.`
- `{username}` — username from local `creds.json`
- `{password}` — password from local `creds.json` (masked in logs/output metadata)

Example LDAP auto tool:

```json
{
  "port": [389],
  "service_name": ["ldap"],
  "tool_name": "LDAP Anonymous Search",
  "tool_type": "command_custom",
  "command": "ldapsearch -x -H ldap://{ip}:{port} -b \"{domain_dn}\""
}
```

### Credential-Aware Auto Tools

Credentials for auto tools are defined by the tracked template `netpal/config/creds.json.example`.
NetPal auto-creates a local, gitignored `netpal/config/creds.json` from that example the first time credentials are loaded.
The file contents are a JSON list:

```json
[
  {
    "username": "test",
    "password": "test",
    "type": "domain",
    "use_in_auto_tools": false
  }
]
```

Rules:

- `type` must be `domain` or `web`
- `use_in_auto_tools: true` is required for the credential to be considered
- If a tool command includes `{username}` or `{password}`, NetPal runs that tool once per matching enabled credential
- Tool configs may add `cred_type: "domain"` or `cred_type: "web"` to limit which credentials are used
- If `cred_type` is omitted or empty, all enabled credentials are eligible

Example:

```json
{
  "port": [445],
  "service_name": ["smb", "microsoft-ds"],
  "tool_name": "SMB Auth Check",
  "tool_type": "command_custom",
  "dup_run": false,
  "cred_type": "domain",
  "command": "crackmapexec smb {ip} -u \"{username}\" -p \"{password}\""
}
```

### Trigger Logic

Tools run when a matching port **or** service name is found. For `http_custom` tools, the HTTP response must also match the `regex_match` pattern.

### Duplicate Host Matches (`dup_run`)

- `dup_run` defaults to `true`
- When `dup_run: true`, the tool can run again on another matched service for the same host (for example `https` on both `443` and `9999`)
- When `dup_run: false`, NetPal skips later matches on the same host once that tool has already run on another matched port/service
- This duplicate-host check is separate from `--rerun-autotools`, which still controls whether a tool re-runs against the same recorded service proof

### Re-run Policy (`--rerun-autotools`)

Auto-tools respect a re-run policy that prevents needless re-execution when a tool has already produced output for a given host/port. The policy is set via `--rerun-autotools` on both the `recon` and `auto` subcommands (default: `2`):

| Value | Behaviour |
|-------|-----------|
| `Y`   | **Always** re-run every tool, even if it already ran |
| `N`   | **Never** re-run — skip any tool that already has a proof recorded |
| `2`   | Re-run only if the tool's last execution was **more than 2 days ago** (default) |
| `7`   | Re-run only if the tool's last execution was **more than 7 days ago** |

The check uses the `utc_ts` timestamp stored in each service proof. Any positive integer is accepted as a day threshold.

In the TUI, a "Re-run auto-tools" dropdown provides the same options (2 days, 7 days, Always, Never).

## Adding a New AI Provider

1. Create `netpal/services/ai/providers/my_provider.py` extending `BaseProvider`
2. Implement `analyze()` and `enhance()` methods
3. Register in `netpal/services/ai/provider_factory.py`
4. Add config keys (e.g., `ai_my_token`, `ai_my_model`)
5. Update the setup wizard in `netpal/utils/setup_wizard.py`

## Interactive TUI (`tui.py` / `textual_ui/`)

The TUI (`netpal interactive`) uses Textual and provides a state-driven, non-linear interface with project editing, assets, recon, tools, hosts, manual findings, AI enhancement, AD scan, testcase tracking, and settings. Views unlock progressively based on project state. Startup now fails fast if required runtime tools (`nmap` or Playwright/Chromium) are unavailable, and the project-creation modal can capture AD metadata plus optionally seed an initial asset from just an asset type and target.

`netpal/tui.py` is the stable public shim for CLI entrypoints, tests, and `python -m netpal.tui`. The actual Textual implementation now lives under `netpal/textual_ui/`.

Important implementation rule: treat the TUI as a presentation layer. Reuse existing CLI modes, handlers, and shared helpers whenever possible. If a TUI workflow needs reusable backend behavior that does not exist yet, add or adjust the shared CLI-side helper or handler interface first, but keep normal CLI behavior and UX unchanged.

To add a new TUI view:

1. Define the new view widget in `netpal/textual_ui/app.py` and prefer the shared primitives from `netpal/textual_ui/components.py`
2. Add a `VIEW_*` constant and entry in `VIEW_LABELS` in `netpal/textual_ui/helpers.py`
3. Mount the widget inside the `ContentSwitcher` in `NetPalApp.compose()`
4. Add a key binding in `BINDINGS`
5. Update `_allowed_views()` with any unlock conditions
6. Add the view class to `_refresh_active_view()`
7. Re-export anything public or test-facing through `netpal/tui.py` if needed

## Adding New Scan Types

1. Add the choice to the `recon` subparser in `create_argument_parser()` in `cli.py`
2. Handle the new type in `ReconCLIHandler.execute_workflow()`
3. Define the nmap options in `netpal/services/nmap/command_builder.py`

## Testing

Before submitting changes:
- Verify `python -m compileall netpal netpalui` passes on modified areas
- Verify `uv run netpal --help`, `uv run netpal interactive --help`, `uv run netpal ad-scan --help`, and `uv run netpal testcase --help`
- Test affected subcommands end-to-end
- Verify `--help` output is correct
- Check next-command suggestions print for relevant transitions
