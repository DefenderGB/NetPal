# AGENTS.md

This file explains how to work inside NetPal as a coding agent.

## Mission

NetPal is a network pentest automation tool with:

- CLI workflows
- Textual TUI and web-served TUI
- MCP server tools/resources
- AI-assisted finding generation and enhancement
- Local project, findings, and evidence storage under `scan_results/`


## Core Principles

### KISS

Keep It Simple, Stupid.

- Prefer the smallest change that solves the problem.
- Reuse existing handlers, helpers, and models before adding new layers.
- Avoid clever abstractions unless the code is already duplicated in multiple places.
- Keep data flow obvious: CLI/TUI/MCP -> handler/helper -> model/persistence.
- If a feature is local-only, implement it locally instead of leaving cloud-era compatibility branches around.

### Local-Only Storage

- Projects, findings, and scan evidence live under `scan_results/`.
- Do not reintroduce cloud storage or sync code, config keys, UI, or MCP tools.
- Bedrock support stays valid through the AI provider stack and `boto3`.

### Touch All Surfaces

When a user-facing behavior changes, check all relevant entry points:

- CLI
- TUI
- Web UI
- MCP tools/resources
- Docs

## How To Run NetPal

Preferred commands:

```bash
uv run netpal --help
uv run netpal setup
uv run netpal list
uv run netpal init "My Project"
uv run netpal interactive
uv run netpal website
uv run netpal-mcp
```

`netpal interactive` and `netpal website` should fail fast if required runtime tools (`nmap` or Playwright/Chromium) are unavailable.

Useful verification commands:

```bash
uv run netpal --help
uv run netpal interactive --help
uv run netpal ad-scan --help
uv run netpal testcase --help
uv run python -m compileall netpal netpalui
uv run python -m unittest tests.test_tui_smoke
uv run python -m unittest tests.test_tui_views
```

For TUI/CSS/startup/layout changes, run `uv run python -m unittest tests.test_tui_smoke` before finishing.
That smaller suite parses the Textual stylesheet directly and runs a couple of headless startup checks, so it catches CSS parse/startup regressions much faster.
Use `uv run python -m unittest tests.test_tui_views` for broader TUI interaction changes or focused follow-up coverage.

If the console script is unavailable for some reason, fallback:

```bash
uv run python -m netpal --help
```

## Architecture Map

### Entrypoints

- `netpal/cli.py`: main CLI parser, dashboard, bootstrap, command routing
- `netpal/__main__.py`: module entrypoint
- `netpal/tui.py`: public Textual TUI shim and stable import surface
- `netpal/textual_ui/`: internal Textual operator UI package (app, shared components, helpers, theme)
- `netpal/mcp_server.py`: MCP server startup and tool/resource registration
- `netpalui/app.py`: lightweight web UI app

### Command Handlers

Most CLI behavior lives in `netpal/modes/`.

- `init_handler.py`: create a project
- `list_handler.py`: list local projects
- `set_handler.py`: switch active project
- `project_edit_handler.py`: rename/edit active project metadata
- `asset_create_handler.py`: create/delete/clear assets
- `recon_cli_handler.py`: discovery and recon scans
- `recon_tools_handler.py`: run exploit tools against discovered services
- `ai_review_handler.py`: generate AI findings
- `ai_enhance_handler.py`: enhance existing findings
- `findings_cli_handler.py`: findings view/delete
- `hosts_handler.py`: host/service/evidence view
- `ad_scan_handler.py`: local AD LDAP collection
- `testcase_handler.py`: local testcase attach/load/status workflows
- `export_handler.py`: zip export
- `delete_handler.py`: delete local project data
- `auto_handler.py`: automated pipeline
- `setup_handler.py`: setup wizard entry

### Models

Core data structures live in `netpal/models/`.

- `project.py`: project container and serialization
- `asset.py`: target assets
- `host.py`: discovered hosts
- `service.py`: services and proofs/evidence
- `finding.py`: AI/manual findings
- `test_case.py`: testcase entries
- `test_case_registry.py`: per-project testcase state

### Local Persistence

All local storage logic is in `netpal/utils/persistence/`.

- `project_persistence.py`: save project/findings
- `file_utils.py`: registry/filesystem helpers
- `project_utils.py`: project load/create helpers
- `project_paths.py`: path resolution
- `local_cleanup.py`: removes legacy cloud-sync metadata on startup

Important rule: project storage is local-only.

### Config And Setup

- `netpal/utils/config_loader.py`: config load/update/default creation
- `netpal/utils/setup_wizard.py`: interactive setup flow
- `netpal/config/config.json.example`: example config
- `netpal/config/creds.json.example`: auto-tool credential template
- `netpal/config/ai_prompts.json`: AI prompt templates
- `netpal/config/exploit_tools.json`: auto-tool definitions
- `netpal/config/recon_types.json`: scan metadata + testcase mapping

### Recon And Scanning

- `netpal/utils/scanning/scan_helpers.py`: discovery/recon workflow helpers
- `netpal/utils/scanning/recon_executor.py`: orchestrates recon + tool execution
- `netpal/services/nmap/scanner.py`: nmap execution engine
- `netpal/services/nmap/command_builder.py`: nmap command generation
- `netpal/services/xml_parser.py`: parse nmap XML results and promote LDAP/`microsoft-ds` banner details into host/project metadata when missing
- `netpal/services/ad/`: local LDAP/BloodHound collection
- `netpal/services/testcase/`: CSV testcase loading + registry management

AD scan behavior notes:

- Anonymous LDAP scans are supported across CLI, TUI/web-served TUI, and MCP.
- Anonymous bind must stay opt-in via the explicit anonymous auth mode; NTLM/Kerberos should fail fast instead of silently falling back.
- Anonymous scans should skip `nTSecurityDescriptor` / ACL collection by default so enumeration still succeeds.
- Custom LDAP filters should accept both full filters like `(sAMAccountName=admin)` and bare expressions like `objectClass=*`.

### Tool Automation

- `netpal/services/tools/tool_orchestrator.py`: coordinates auto-tools
- `netpal/services/tools/playwright_runner.py`: screenshots/web capture
- `netpal/services/tools/nuclei_runner.py`: nuclei execution
- `netpal/services/tools/nmap_script_runner.py`: NSE script execution
- `netpal/services/tools/http_tool_runner.py`: HTTP-based tool execution

### AI

- `netpal/services/ai/analyzer.py`: main AI analysis flow
- `netpal/services/ai/finding_enhancer.py`: enhancement flow
- `netpal/services/ai/provider_factory.py`: provider selection/validation
- `netpal/services/ai/providers/`: provider implementations
- `netpal/utils/ai_helpers.py`: high-level AI workflow helpers
- `netpal/utils/aws/aws_utils.py`: safe boto3 session creation for Bedrock

Bedrock note:

- Bedrock is configured through `ai_type: "aws"` and related `ai_aws_*` config keys.
- Keep `boto3`.
- Do not add S3-related AWS logic.

### MCP

- `netpal/mcp_context.py`: shared MCP runtime context
- `netpal/mcp_tools/project_tools.py`: project operations
- `netpal/mcp_tools/asset_tools.py`: asset operations
- `netpal/mcp_tools/scan_tools.py`: recon/tool execution
- `netpal/mcp_tools/ai_tools.py`: AI operations
- `netpal/mcp_tools/finding_tools.py`: finding operations
- `netpal/mcp_tools/config_tools.py`: config/setup operations
- `netpal/mcp_resources/`: read-only resources for projects, hosts, config

Important rule: MCP should not expose cloud-storage tools.

### TUI And Web UI

- `netpal/tui.py`: primary interactive UI shim / module entrypoint
- `netpal/textual_ui/app.py`: Textual app, screens, views
- `netpal/textual_ui/components.py`: shared TUI primitives
- `netpal/textual_ui/helpers.py`: shared TUI helper logic and view constants
- `netpal/textual_ui/styles.tcss`: TUI theme
- `netpalui/templates/`: HTML templates
- `netpalui/static/style.css`: styling

If project metadata changes, make sure badges/columns/forms stay in sync across TUI and web output.
Important rule: TUI actions should reuse CLI modes/handlers/shared helpers whenever possible. Do not add parallel TUI-only backend logic if the CLI path can be reused or lightly generalized without changing normal CLI behavior.

### Display And UX Helpers

- `netpal/utils/display/display_utils.py`: banners and formatting
- `netpal/utils/display/next_command.py`: next-command suggestions
- `netpal/utils/display/finding_viewer.py`: findings display helpers

### Notifications And Validation

- `netpal/services/notification_service.py`: webhook notifications
- `netpal/utils/validation.py`: prerequisites and validation
- `netpal/utils/tool_paths.py`: external tool detection

## Safe Change Workflow

When making changes:

1. Find the user-facing entrypoint first.
2. Identify the handler/helper/model/persistence chain behind it.
3. Make the smallest coherent change.
4. Update all other surfaces that expose the same behavior.
5. Run quick verification commands with `uv run`.

## What To Avoid

- Do not add S3/cloud sync back.
- Do not create parallel implementations when an existing handler/helper can be extended.
- Do not hide important behavior in side effects if a direct call is clearer.
- Do not update only the CLI if the TUI/MCP/web surface is also affected.

## Good First Checks Before Editing

```bash
uv run netpal --help
rg -n "feature_name|config_key|command_name" netpal netpalui README.md CONTRIBUTION.md
python3 -m compileall netpal netpalui
```

## Docs To Keep In Sync

- `README.md`
- `CONTRIBUTION.md`
- `AGENTS.md`
