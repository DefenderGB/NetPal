# Contributing to NetPal

This guide covers the project structure and how to extend NetPal.

## Contact

**Developer**: defender-gb@protonmail.com

## Development Setup

### Quick Start (recommended)

The [`install.sh`](install.sh) script handles everything — installs **uv**, external tools (nmap, nuclei, AWS CLI), creates a Python 3.12 virtual environment, syncs dependencies (including Playwright), installs NetPal in editable mode, and downloads the Chromium browser for Playwright:

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
| nmap | Yes | Sudo required for SYN scans; `install.sh` offers to configure passwordless sudo |
| playwright | Yes | Python dependency; `install.sh` runs `playwright install chromium` automatically |
| Go | Optional | Required to install nuclei |
| nuclei | Yes | Vulnerability scanning with templates |
| AWS CLI | Yes | Only needed for S3 sync |

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
├── tui.py                         # Interactive TUI (Textual) — netpal interactive
├── config/
│   ├── config.json                # Runtime configuration
│   ├── ai_prompts.json            # AI finding prompts
│   └── exploit_tools.json         # Tool automation config
├── models/                        # Data models
│   ├── project.py                 # Project container
│   ├── asset.py                   # Scan target
│   ├── host.py                    # Discovered host
│   ├── service.py                 # Network service
│   └── finding.py                 # Security finding
├── modes/                         # Subcommand handlers (Template Method)
│   ├── __init__.py                # Exports all handlers
│   ├── base_handler.py            # Abstract ModeHandler base class
│   ├── asset_create_handler.py    # netpal asset-create
│   ├── auto_handler.py            # netpal auto (fully automated pipeline)
│   ├── recon_cli_handler.py       # netpal recon
│   ├── ai_review_handler.py       # netpal ai-review
│   ├── ai_enhance_handler.py      # netpal ai-report-enhance
│   ├── findings_cli_handler.py    # netpal findings
│   ├── pull_handler.py            # netpal pull
│   └── setup_handler.py           # netpal setup
├── services/                      # Core services
│   ├── nmap_scanner.py            # Multi-threaded nmap (deprecated facade)
│   ├── tool_runner.py             # Tool automation (deprecated facade)
│   ├── xml_parser.py              # Nmap XML parsing
│   ├── ai_analyzer.py             # AI analysis (deprecated facade)
│   ├── aws_sync.py                # S3 synchronization
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
│   └── tools/                     # Tool runner subsystem
│       ├── base.py                # Abstract tool runner
│       ├── http_tool_runner.py    # HTTP-based tools
│       ├── playwright_runner.py   # Playwright (headless Chromium) integration
│       ├── nmap_script_runner.py  # Nmap NSE scripts
│       ├── nuclei_runner.py       # Nuclei vulnerability scanning
│       └── tool_orchestrator.py   # Coordinates tool execution
└── utils/                         # Shared utilities
    ├── ai_helpers.py              # AI workflow helpers
    ├── ai_validation.py           # AI config validation (deprecated — use ProviderFactory.validate())
    ├── asset_factory.py           # Asset creation factory
    ├── aws_utils.py               # AWS session/sync setup helpers
    ├── config_loader.py           # JSON configuration management
    ├── display_utils.py           # Banner, next-command box, formatting
    ├── file_utils.py              # File I/O operations
    ├── finding_viewer.py          # Finding summary display
    ├── image_loader.py            # Screenshot loading for AI
    ├── logger.py                  # Centralized logging (get_logger / setup_logging)
    ├── naming_utils.py            # Name sanitization
    ├── network_utils.py           # CIDR validation, subnet splitting
    ├── next_command.py            # Next-command suggestion engine
    ├── project_paths.py           # Project path resolution
    ├── project_persistence.py     # Save/sync project data (ProjectPersistence.save_and_sync)
    ├── project_utils.py           # Project load/create helpers
    ├── pull_utils.py              # S3 pull operations
    ├── recon_executor.py          # Recon scan execution
    ├── scan_helpers.py            # Scan phase helpers
    ├── setup_wizard.py            # Setup wizard logic
    ├── tool_paths.py              # External tool detection
    └── validation.py              # Input validation
```

## Architecture

### CLI Entry Point (`cli.py`)

The `main()` function in `cli.py` is the single entry point. It uses `argparse` subparsers for the `netpal <verb>` syntax:

```
netpal                          → display_dashboard()
netpal asset-create …           → AssetCreateHandler
netpal recon …                  → ReconCLIHandler
netpal auto …                   → AutoHandler
netpal ai-review …              → AIReviewHandler
netpal ai-report-enhance …     → AIEnhanceHandler
netpal findings …               → FindingsCLIHandler
netpal setup                    → SetupHandler
netpal pull …                   → PullHandler
netpal interactive              → tui.run_interactive()
```

The `_bootstrap_project(args)` helper loads config, sets up AWS sync, and loads the active project. All subcommand routes (except `setup` and dashboard) call it first.

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
            self.sync_if_enabled()
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
| `http_custom` | HTTP tools with regex triggers |
| `nuclei` | Nuclei vulnerability templates |

### Configuration Format

```json
{
  "port": [445, 139],
  "service_name": ["microsoft-ds", "netbios-ssn"],
  "tool_name": "SMB Vulnerability Scan",
  "tool_type": "nmap_custom",
  "command": "nmap -p {port} --script smb-vuln* {ip}"
}
```

### Placeholders

- `{ip}` — target IP
- `{port}` — port number
- `{protocol}` — `http` or `https`
- `{path/to/upload/file.txt}` — auto-generated output path

### Trigger Logic

Tools run when a matching port **or** service name is found. For `http_custom` tools, the HTTP response must also match the `regex_match` pattern.

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

## Interactive TUI (`tui.py`)

The TUI (`netpal interactive`) uses Textual and provides a state-driven, non-linear interface with five views: Projects, Assets, Recon, Evidence, and Settings. Views unlock progressively based on project state.

To add a new TUI view:

1. Define a new view widget class extending `VerticalScroll` in `netpal/tui.py`
2. Add a `VIEW_*` constant and entry in `VIEW_LABELS`
3. Mount the widget inside the `ContentSwitcher` in `NetPalApp.compose()`
4. Add a key binding in `BINDINGS`
5. Update `_allowed_views()` with any unlock conditions
6. Add the view class to `_refresh_active_view()`

## Adding New Scan Types

1. Add the choice to the `recon` subparser in `create_argument_parser()` in `cli.py`
2. Handle the new type in `ReconCLIHandler.execute_workflow()`
3. Define the nmap options in `netpal/services/nmap/command_builder.py`

## Testing

Before submitting changes:
- Verify `python3 -m py_compile` passes on all modified files
- Test affected subcommands end-to-end
- Verify `--help` output is correct
- Check next-command suggestions print for relevant transitions
