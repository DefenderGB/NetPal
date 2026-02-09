GO REINSTAL IN UBUNTU

# NetPal - Network Penetration Testing CLI Tool

NetPal is a command-line tool for network penetration testing, focusing on automated reconnaissance, enumeration, exploitability testing, and AI-powered reporting.

## Security Disclaimer

- **Authorization**: Always verify you have permission to scan targets
- **Exclusions**: Use `exclude` to prevent scanning critical infrastructure
- **Rate Limiting**: Adjust timing templates if causing network issues
- **Data Storage**: Project files may contain sensitive information - protect accordingly
- **AI Data**: Evidence sent to AI providers (if enabled) - review data handling policies

## Features

- **Multi-threaded Scanning**: Up to 5 concurrent nmap scans with automatic network chunking
- **Smart Network Chunking**: Automatically breaks down large networks (/16 → multiple /24 subnets)
- **Automated Tool Execution**: Runs security tools automatically based on discovered services
- **Evidence Collection**: Captures screenshots, HTTP responses, and tool outputs with proof tracking
- **AI-Powered Reporting**: Generate security findings using multiple AI providers (AWS Bedrock, Anthropic, OpenAI, Ollama, Azure, Gemini)
- **Vision-Capable Analysis**: AI analyzes screenshots alongside scan data for enhanced findings
- **AWS S3 Sync**: Bidirectional cloud synchronization for collaborative testing
- **Webhook Notifications**: Slack/Discord notifications for scan completion
- **Project Management**: Organized project structure with JSON-based storage
- **Interactive & CLI Modes**: Both interactive prompts and non-interactive command-line operation
- **Multiple Scan Types**: Top 100 ports, HTTP-only, all ports, custom, and NetSec presets
- **Finding Management**: View, enhance, and delete security findings with AI QA enhancement

## Requirements

### System Requirements
- Linux/macOS (requires sudo for network scanning)
- Python 3.8 or higher
- sudo privileges (for raw socket access in nmap)

### Required Tools
- **nmap**: Network discovery and port scanning
- **httpx**: ProjectDiscovery's HTTP toolkit for screenshots and response capture

### Optional Tools
- **nuclei**: Vulnerability scanning with templates (highly recommended)
- **AWS CLI**: For S3 sync functionality (if using cloud features)

## Installation

### Fast Install
```bash
git clone https://github.com/DefenderGB/NetPal.git
cd NetPal
bash install.sh
sudo netpal --mode setup
```

### Part 1: Install NetPal

```bash
# Clone the repository
git clone https://github.com/DefenderGB/NetPal.git
cd NetPal

# Install the package and dependencies
pip install -e .
```

### Part 2: Install external tools

```bash
# Install nmap
sudo apt-get install nmap  # Ubuntu/Debian
brew install nmap          # macOS

# Install httpx (Go tool)
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Install nuclei (optional but recommended)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Ensure GO binaries are in PATH
export PATH=$PATH:~/go/bin
```

### Part 3: Configuration

```bash
# Option 1: Interactive setup wizard
sudo netpal --mode setup

# Option 2: Manual configuration
# Edit netpal/config/config.json with your settings
```

## Quick Start

### Interactive Mode (Recommended)

```bash
# Run with session persistence (recommended for long scans)
sudo tmux new -s netpal netpal

# Or run directly
sudo netpal
```

### Non-Interactive CLI Mode

```bash
# Complete workflow: discovery → recon → AI reporting
sudo netpal --mode cli \
  --asset-type network \
  --asset-name "DMZ" \
  --asset-network "10.0.0.0/24" \
  --discover \
  --recon \
  --scan-type top100 \
  --ai

# Reuse existing asset (skip discovery)
sudo netpal --mode cli \
  --asset-name "DMZ" \
  --recon \
  --scan-type allports

# AI reporting on existing data
sudo netpal --mode ai

# View findings
sudo netpal --mode findings
```

## CLI Options

```
usage: netpal [-h] [--sync] [--no-sync] [--pull] [--id ID] 
              [--mode {cli,setup,ai,recon,findings}]
              [--asset-type {network,list,single}] [--asset-name ASSET_NAME]
              [--asset-network ASSET_NETWORK] [--asset-list ASSET_LIST] 
              [--asset-target ASSET_TARGET] [--discover] [--recon] [--ai]
              [--scan-type {top100,http,netsec,allports,custom}] 
              [--speed {1,2,3,4,5}] [--interface INTERFACE] 
              [--nmap-options NMAP_OPTIONS] [--exclude EXCLUDE]
              [--exclude-ports EXCLUDE_PORTS] [--batch-size BATCH_SIZE] 
              [--external-id EXTERNAL_ID]

NetPal - Network Penetration Testing CLI Tool

options:
  -h, --help            Show help message and exit
  --sync                Enable AWS S3 sync
  --no-sync             Disable AWS S3 sync
  --pull                Pull projects from S3
  --id ID               Project ID for pull operation
  --mode {cli,setup,ai,recon,findings}
                        Operation mode

Asset Configuration (CLI mode):
  --asset-type {network,list,single}
                        Asset type (required for new assets)
  --asset-name ASSET_NAME
                        Asset name (required in CLI mode)
  --asset-network ASSET_NETWORK
                        Network CIDR (for network type)
  --asset-list ASSET_LIST
                        Comma-separated target list (for list type)
  --asset-target ASSET_TARGET
                        Single target IP/hostname (for single type)

Workflow Phases:
  --discover            Run discovery phase (ping scan)
  --recon               Run reconnaissance phase (port scanning + tools)
  --ai                  Run AI reporting phase

Scan Configuration:
  --scan-type {top100,http,netsec,allports,custom}
                        Scan type for recon phase
  --speed {1,2,3,4,5}   Nmap timing template (1=T1 slowest, 5=T5 fastest)
  --interface INTERFACE Network interface (overrides config.json)
  --nmap-options NMAP_OPTIONS
                        Custom nmap options (requires --scan-type custom)
  --exclude EXCLUDE     IPs to exclude (comma-separated)
  --exclude-ports EXCLUDE_PORTS
                        Ports to exclude (comma-separated)
  --batch-size BATCH_SIZE
                        AI batch size (default: 5)
  --external-id EXTERNAL_ID
                        External tracking ID for the project
```

## Operating Modes

### 1. Setup Mode (`--mode setup`)
Interactive configuration wizard for:
- Project settings (name, interface)
- Network exclusions (IPs, ports)
- AWS S3 sync configuration
- AI provider selection and configuration
- Webhook notifications (Slack/Discord)

### 2. CLI Mode (`--mode cli`)
Non-interactive command-line operation for automation:
- Create or reuse assets
- Run discovery, recon, and AI phases
- Specify scan types and options
- Configure timing and exclusions

### 3. AI Mode (`--mode ai`)
Run AI reporting on existing scan data:
- Analyzes hosts with services
- Reads proof files and screenshots
- Generates security findings
- Uses configured AI provider

### 4. Findings Mode (`--mode findings`)
Interactive findings viewer:
- View findings by severity
- See detailed finding information
- Delete individual or multiple findings
- Export finding data

### 5. Recon Mode (`--mode recon`)
Quick recon without discovery:
- Select existing or create new asset
- Skip straight to port scanning
- Run automated tools
- Generate AI findings

### 6. Interactive Mode (default)
Full-featured interactive workflow:
- Step-by-step guided process
- Create/select assets
- Run discovery and recon
- View and enhance findings
- Delete assets or entire projects

## Scan Types

1. **Top 100 Ports**: Fast scan of most common ports (default)
2. **HTTP Ports**: Web service ports only (80, 443, 8080, etc.)
3. **NetSec Known Ports**: Common security assessment ports (21, 22, 23, 25, etc.)
4. **All Ports**: Full 1-65535 port scan (automatically chunks networks to /27)
5. **Custom**: Specify your own port range or list with `--nmap-options`

## AI Provider Configuration

NetPal supports multiple AI providers for finding generation:

### AWS Bedrock
```json
{
  "ai_type": "aws",
  "ai_aws_profile": "your-profile",
  "ai_aws_account": "123456789012",
  "ai_aws_region": "us-east-1",
  "ai_aws_model": "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
}
```

### Anthropic
```json
{
  "ai_type": "anthropic",
  "ai_anthropic_token": "sk-ant-...",
  "ai_anthropic_model": "claude-sonnet-4-5-20250929"
}
```

### OpenAI
```json
{
  "ai_type": "openai",
  "ai_openai_token": "sk-...",
  "ai_openai_model": "gpt-4o"
}
```

### Ollama (Local)
```json
{
  "ai_type": "ollama",
  "ai_ollama_model": "llama3.1",
  "ai_ollama_host": "http://localhost:11434"
}
```

### Azure OpenAI
```json
{
  "ai_type": "azure",
  "ai_azure_token": "your-api-key",
  "ai_azure_endpoint": "https://your-resource.openai.azure.com/",
  "ai_azure_model": "your-deployment-name"
}
```

### Google Gemini
```json
{
  "ai_type": "gemini",
  "ai_gemini_token": "your-api-key",
  "ai_gemini_model": "gemini-2.5-flash"
}
```

## Workflow

### Interactive Mode Workflow

1. **Tool Check**: Automatically verifies required dependencies
2. **Target Selection**: Choose network, list, or single target
3. **Discovery Phase**: Ping scan to discover active hosts
4. **Recon Phase**: Interactive menu for detailed scanning
   - Select target (full asset, active hosts, or specific host)
   - Choose scan type
   - Configure network interface and speed
   - Execute scans
5. **Automated Tools**: httpx, nuclei, and custom tools run automatically
6. **AI Reporting** (optional): Generate findings using AI analysis
7. **Finding Management**: View, enhance, or delete findings

### CLI Mode Workflow

```bash
# Step 1: Discovery
sudo netpal --mode cli --asset-type network --asset-name "Production" \
  --asset-network "192.168.1.0/24" --discover

# Step 2: Reconnaissance  
sudo netpal --mode cli --asset-name "Production" \
  --recon --scan-type top100

# Step 3: AI Analysis
sudo netpal --mode cli --asset-name "Production" --ai

# Or run all phases together
sudo netpal --mode cli --asset-type network --asset-name "Production" \
  --asset-network "192.168.1.0/24" --discover --recon --scan-type top100 --ai
```

## Results Structure

```
scan_results/
├── <project_id>.json                    # Project data with hosts and services
├── <project_id>_findings.json           # Security findings
├── projects.json                        # Project registry
└── <project_id>/                        # Scan results directory
    └── <asset_identifier>/              # Results per asset
        ├── scan_*.xml                   # Nmap XML outputs
        ├── <asset>_list.txt             # Host list (for list assets)
        └── auto_tools/                  # Automated tool outputs
            ├── auto_httpx_*.txt         # HTTP responses
            ├── auto_httpx_*.png         # Screenshots
            ├── nuclei_*.jsonl           # Nuclei scan results
            └── *_*.txt                  # Other tool outputs
```

### Project JSON Structure

```json
{
  "id": "uuid-here",
  "name": "project_name",
  "external_id": "optional-external-id",
  "assets": [
    {
      "asset_id": 0,
      "type": "network",
      "name": "Primary Network",
      "network": "192.168.1.0/24",
      "associated_host": [0, 1, 2]
    }
  ],
  "hosts": [
    {
      "host_id": 0,
      "ip": "192.168.1.10",
      "hostname": "server.local",
      "os": "Linux 5.x",
      "assets": [0],
      "services": [
        {
          "port": 80,
          "service_name": "http",
          "service_version": "Apache httpd 2.4.41",
          "protocol": "tcp",
          "extrainfo": "",
          "proof": [
            {
              "type": "auto_httpx",
              "result_file": "scan_results/project_id/asset/auto_tools/auto_httpx_192-168-1-10_80.txt",
              "screenshot_file": "scan_results/project_id/asset/auto_tools/auto_httpx_192-168-1-10_80.png",
              "utc_ts": 1767598746
            }
          ]
        }
      ],
      "findings": ["f-uuid-1", "f-uuid-2"]
    }
  ],
  "modified_utc_ts": 1767600025
}
```

### Findings JSON Structure

```json
[
  {
    "finding_id": "f-uuid-1",
    "host_id": 0,
    "name": "Outdated Apache Version",
    "severity": "Medium",
    "description": "The web server is running an outdated version of Apache...",
    "impact": "An attacker could exploit known vulnerabilities...",
    "remediation": "Update Apache to the latest version...",
    "port": 80,
    "cvss": 5.3,
    "cwe": "CWE-1104",
    "proof_file": "scan_results/project_id/asset/auto_tools/auto_httpx_192-168-1-10_80.txt",
    "utc_ts": 1767598750
  }
]
```

## Advanced Features

### Network Chunking

NetPal automatically handles large networks efficiently:

- **/16 networks**: Broken into 256 /24 subnets, scanned 5 at a time
- **/23 networks**: Broken into 2 /24 subnets
- **Lists >100 hosts**: Chunked into groups of 100, scanned in parallel
- **All ports scans**: Networks automatically chunked to /27 for faster processing
- **Progress preservation**: Results saved after each chunk completes

### Tool Automation

Security tools run automatically when services are discovered. Tools are configured in `netpal/config/exploit_tools.json` and trigger based on:
- Specific ports (e.g., SMB on 445)
- Service names (e.g., "http", "mysql")
- HTTP response patterns (for web-based tools)

Supported tool types include:
- **nmap_custom**: Custom nmap NSE scripts
- **http_custom**: HTTP-based tools with regex triggers
- **nuclei**: Nuclei vulnerability templates

For details on adding custom tools, see [CONTRIBUTION.md](CONTRIBUTION.md).

### Evidence Tracking

All tool outputs are stored with metadata:
- Command executed
- Timestamp (UTC)
- Result files
- Screenshots (for web services)
- Associated with specific host:port combinations
- Linked to findings for traceability

### AI Finding Enhancement

Two-phase AI workflow:

1. **Initial Analysis**: Quick finding generation
   - Analyzes scan data and evidence
   - Generates findings with basic details
   - Includes screenshot analysis (vision-capable models)

2. **AI QA Enhancement**: Detailed refinement (optional)
   - Enhances finding names for clarity
   - Expands descriptions with technical details
   - Elaborates on security impact
   - Provides comprehensive remediation steps
   - Classifies CWE categories

### Nmap Timing Templates

Control scan speed with `--speed` option:
- **T1 (--speed 1)**: Paranoid - slowest, IDS evasion
- **T2 (--speed 2)**: Sneaky - slow
- **T3 (--speed 3)**: Normal - default balanced speed
- **T4 (--speed 4)**: Aggressive - fast
- **T5 (--speed 5)**: Insane - fastest, may miss results

## AWS Integration

### S3 Sync Setup

NetPal provides bidirectional S3 synchronization for collaborative penetration testing. Projects are automatically synced to/from S3 at startup and after each scan phase.

#### Initial Setup

```bash
# Configure AWS credentials
aws configure set aws_access_key_id "$ACCESS_KEY" --profile netpal-user
aws configure set aws_secret_access_key "$SECRET_KEY" --profile netpal-user
aws configure set region us-west-2 --profile netpal-user

# Test credentials
aws sts get-caller-identity --profile netpal-user

# Configure in config.json
{
  "aws_sync_account": "123456789012",
  "aws_sync_profile": "netpal-user",
  "aws_sync_bucket": "netpal-123456789012"
}
```

#### How S3 Sync Works

**Automatic Bidirectional Sync at Startup:**
1. Downloads `projects.json` registry from S3
2. Compares local vs S3 timestamps for each project
3. Pulls newer projects from S3 automatically
4. Handles deletion conflicts (deleted in S3 but exists locally)
5. Manages ID conflicts with automatic project migration

**Sync After Each Phase:**
- After discovery scan
- After reconnaissance scan
- After AI finding generation
- After asset deletion
- When switching projects

**S3 Bucket Structure:**
```
s3://netpal-123456789012/
├── projects.json                           # Project registry with timestamps
├── <project_id>.json                       # Project metadata
├── <project_id>_findings.json              # Security findings
└── <project_id>/                           # Scan results
    └── <asset_identifier>/
        ├── scan_*.xml
        └── auto_tools/
            ├── *.txt
            └── *.png
```

**Projects Registry Format:**
The `projects.json` file tracks all projects with metadata:
```json
{
  "projects": [
    {
      "id": "abc123-def456-...",
      "name": "Production Network",
      "updated_utc_ts": 1767600025,
      "external_id": "JIRA-123",
      "deleted": false
    }
  ]
}
```

See [`examples/example-projects.json`](examples/example-projects.json) for a complete example.

#### Conflict Resolution

**Timestamp Conflicts:**
- Newer project (by `modified_utc_ts`) always wins
- Automatic download when S3 is newer
- Automatic upload when local is newer

**Deletion Conflicts:**
- If project deleted in S3 but exists locally: prompts for local deletion
- If project exists in S3 but marked deleted locally: no conflict

**ID Conflicts:**
- Rare case when same project name has different IDs
- Automatic migration to new UUID
- Old project preserved, new ID uploaded to S3

### AI Bedrock Setup (Optional)

```bash
# Configure Bedrock profile
aws configure set aws_access_key_id "$ACCESS_KEY" --profile ai-profile
aws configure set aws_secret_access_key "$SECRET_KEY" --profile ai-profile
aws configure set region us-east-1 --profile ai-profile

# Test access
aws bedrock list-foundation-models --profile ai-profile

# Configure in config.json
{
  "ai_type": "aws",
  "ai_aws_profile": "ai-profile",
  "ai_aws_region": "us-east-1",
  "ai_aws_model": "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
}
```

### Pull Projects from S3

```bash
# Interactive pull - shows all projects with selection menu
netpal --pull

# Download specific project by UUID
netpal --pull --id <project-uuid>

# Pull will download:
# - Project metadata (<project_id>.json)
# - Findings (<project_id>_findings.json)
# - All scan results and evidence files
# - Updates local projects.json registry
```

#### Pull Mode Features
- Lists all available S3 projects with metadata
- Shows project name, ID preview, external ID, and last modified date
- Allows selection of specific projects to download
- Option to download all projects at once
- Automatic conflict detection and resolution
- Updates local registry after successful download

## Webhook Notifications

Configure Slack or Discord notifications for scan completion:

### Slack Setup

1. Create a Slack webhook URL
2. Configure in setup mode or config.json:

```json
{
  "notification_enabled": true,
  "notification_type": "slack",
  "notification_webhook_url": "https://hooks.slack.com/...",
  "notification_user_email": "user@example.com"
}
```

### Discord Setup

```json
{
  "notification_enabled": true,
  "notification_type": "discord",
  "notification_webhook_url": "https://discord.com/api/webhooks/..."
}
```

Notifications include:
- Project and asset name
- Scan type and duration
- Hosts discovered
- Services found
- Tools executed
- Nmap command for reproducibility

## Troubleshooting

### "Permission denied" errors
```bash
# Ensure running with sudo
sudo netpal

# Or set nmap capabilities (alternative to sudo in Linux)
sudo setcap cap_net_raw,cap_net_admin+eip $(which nmap)
```

### "Tool not found" errors
```bash
# Verify tools are installed
which nmap
which httpx
which nuclei

# Add GO tools to PATH
export PATH=$PATH:~/go/bin
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
```

### Large network scans taking too long
- NetPal automatically chunks networks for parallel scanning
- Use more specific target ranges
- Select "Active Hosts" after discovery to scan only responsive hosts
- Choose faster scan types (Top 100 instead of All Ports)
- Increase speed with `--speed 4` or `--speed 5`

### AWS profile errors
```bash
# Verify profile exists
aws configure list --profile your-profile

# Test access
aws sts get-caller-identity --profile your-profile
```

### AI reporting not working
- Verify AI provider is configured in config.json
- Check API credentials are valid
- Ensure appropriate permissions for AWS Bedrock
- Test connection separately (e.g., `aws bedrock list-foundation-models`)

## Examples

### Example 1: Home Network Assessment

```bash
# Interactive mode with setup
sudo netpal --mode setup  # Configure once

# Run scan
sudo tmux new -s netpal netpal

# Select: Network (CIDR)
# Enter: 192.168.1.0/24
# Discovery runs automatically
# Select: Top 100 ports scan
# Wait for completion
# View findings
```

### Example 2: Web Application Scan

```bash
# Target specific web servers
sudo netpal --mode cli \
  --asset-type list \
  --asset-name "Web Servers" \
  --asset-list "web1.example.com,web2.example.com,192.168.1.50" \
  --recon \
  --scan-type http \
  --ai
```

### Example 3: Deep Single Host Analysis

```bash
# All ports scan on critical server
sudo netpal --mode cli \
  --asset-type single \
  --asset-name "Critical Database" \
  --asset-target "10.0.0.50" \
  --discover \
  --recon \
  --scan-type allports \
  --speed 2 \
  --ai \
  --sync
```

### Example 4: Stealth Scan with Custom Options

```bash
# Slow, fragmented scan for IDS evasion
sudo netpal --mode cli \
  --asset-type network \
  --asset-name "DMZ" \
  --asset-network "10.10.10.0/24" \
  --recon \
  --scan-type custom \
  --nmap-options "-p 1-1000 -sS -f -T1" \
  --exclude "10.10.10.1,10.10.10.254"
```

### Example 5: Collaborative Testing

```bash
# Team member 1: Initial scan and upload
sudo netpal --mode cli \
  --asset-type network \
  --asset-name "Production" \
  --asset-network "172.16.0.0/24" \
  --discover \
  --recon \
  --scan-type top100 \
  --sync

# Team member 2: Pull and continue
netpal --pull
sudo netpal --mode cli \
  --asset-name "Production" \
  --recon \
  --scan-type allports \
  --sync
```

## Best Practices

1. **Always run with sudo**: Network scanning requires raw socket access
2. **Use session persistence**: Run in tmux or screen for long scans
3. **Start small**: Test on small networks (/27 or /28) before large deployments
4. **Review exploit_tools.json**: Customize automated tools for your engagement
5. **Set exclusions**: Configure `exclude` in config.json for critical infrastructure
6. **Monitor progress**: Watch real-time output during scans
7. **Backup results**: Project files are continuously updated, consider version control
8. **Use specific targets**: Instead of scanning /16, break into specific /24 ranges
9. **Enable notifications**: Get alerted when long scans complete
10. **Leverage AI enhancement**: Use AI QA mode to improve finding quality

## Network Interface Selection

NetPal automatically detects available network interfaces:

```bash
# View available interfaces
ip link show      # Linux
ifconfig          # macOS

# Common interfaces
# - eth0: First Ethernet interface (Linux)
# - en0: First Ethernet interface (macOS)
# - wlan0: First wireless interface (Linux)
# - utun*: VPN interfaces (macOS)
```

Configure in config.json or use `--interface` flag:
```bash
sudo netpal --mode cli --interface en0 ...
```

## Contributing

Interested in contributing? See [CONTRIBUTION.md](CONTRIBUTION.md) for:
- Project structure and code organization
- How to add custom automated tools
- Development setup and workflow
- Code style guidelines and best practices

## Support

- **Issues**: https://github.com/DefenderGB/NetPal/issues
- **Developer Questions**: defender-gb@protonmail.com

## License

MIT License - see LICENSE file for details.

## Credits

NetPal was created by Gustavo Bobbio-Hertog (defendergb)

**Version**: 1.0.0

## Changelog

### Version 1.0.0 (Current)
- Initial release with full feature set
- Multi-threaded nmap scanning (up to 5 concurrent)
- Automatic network chunking for large targets
- httpx integration for web service enumeration
- nuclei integration for vulnerability scanning
- Automated exploit tool execution framework
- Multiple AI provider support (AWS Bedrock, Anthropic, OpenAI, Ollama, Azure, Gemini)
- Vision-capable AI analysis for screenshots
- JSON-based project management with registry
- AWS S3 bidirectional sync support
- Webhook notifications (Slack/Discord)
- Interactive and CLI modes
- Finding management with AI enhancement
- Setup wizard for easy configuration
- External ID tracking for project integration
- Nmap timing template support
- Custom scan options
- Project migration capabilities