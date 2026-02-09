# Contributing to NetPal

Thanks for the interest on contribution! This guide will help you understand the project structure and how to add new features.

## Getting Help

For questions, issues, or support, please contact: **defender-gb@protonmail.com**

## Development Setup

### Prerequisites
- Python 3.10 or higher
- Git
- Required external tools (nmap, httpx, nuclei)

### Setting Up Your Development Environment

```bash
# Clone the repository
git clone https://github.com/DefenderGB/NetPal.git
cd NetPal

# Install in development mode
python3.10 -m pip install -e . --break-system-packages
```

## Project Structure

```
netpal/
├── cli.py                    # Main CLI interface
├── config/                   # Configuration files
│   ├── config.json          # Main configuration
│   ├── ai_prompts.json      # AI finding prompts
│   └── exploit_tools.json   # Tool automation config
├── models/                   # Data models
│   ├── project.py           # Project container
│   ├── asset.py             # Scan target
│   ├── host.py              # Discovered host
│   ├── service.py           # Network service
│   └── finding.py           # Security vulnerability
├── services/                 # Scanner services
│   ├── nmap_scanner.py      # Multi-threaded nmap
│   ├── tool_runner.py       # Tool automation
│   ├── xml_parser.py        # Nmap XML parsing
│   ├── ai_analyzer.py       # AI-powered analysis
│   ├── aws_sync.py          # S3 synchronization
│   └── notification_service.py # Webhook notifications
└── utils/                    # Utilities
    ├── config_loader.py     # Configuration management
    ├── file_utils.py        # File operations
    ├── network_utils.py     # Network functions
    └── validation.py        # Input validation
```

### Key Components

#### Models (`netpal/models/`)
Data structures representing scan entities:
- **project.py**: Top-level container for all scan data
- **asset.py**: Target definition (network, list, or single host)
- **host.py**: Discovered host with services and findings
- **service.py**: Network service on a specific port
- **finding.py**: Security vulnerability or issue

#### Services (`netpal/services/`)
Core functionality modules:
- **nmap_scanner.py**: Multi-threaded scanning with network chunking
- **tool_runner.py**: Automated security tool execution
- **xml_parser.py**: Nmap XML output parsing
- **ai_analyzer.py**: AI-powered finding generation
- **aws_sync.py**: S3 synchronization for collaboration
- **notification_service.py**: Webhook notifications (Slack/Discord)

#### Utils (`netpal/utils/`)
Helper functions and utilities:
- **config_loader.py**: Configuration file management
- **file_utils.py**: File I/O operations
- **network_utils.py**: Network address manipulation
- **validation.py**: Input validation and sanitization

## Adding Custom Automated Tools

NetPal can automatically execute security tools when specific conditions are met. Tools are configured in `netpal/config/exploit_tools.json`.

### Tool Configuration Format

```json
{
  "port": [445, 139],
  "service_name": ["microsoft-ds", "netbios-ssn", "smb"],
  "tool_name": "SMB Vulnerability Scan",
  "tool_type": "nmap_custom",
  "command": "nmap -p {port} --script smb-vuln* {ip}"
}
```

### Tool Types

#### 1. `nmap_custom` - Custom Nmap NSE Scripts
Execute nmap with specific NSE scripts:

```json
{
  "port": [3389],
  "service_name": ["ms-wbt-server"],
  "tool_name": "RDP Security Check",
  "tool_type": "nmap_custom",
  "command": "nmap -p {port} --script rdp-enum-encryption {ip}"
}
```

#### 2. `http_custom` - HTTP-Based Tools with Regex Triggers
Tools that trigger based on HTTP response content:

```json
{
  "port": [80, 443],
  "service_name": ["http", "https"],
  "tool_name": "Git Directory Exposure",
  "tool_type": "http_custom",
  "regex_match": "HTTP\\/1\\.1 200 OK",
  "command": "nuclei -u {protocol}://{ip}:{port} -t git-config.yaml -o {path/to/upload/file.txt}"
}
```

#### 3. `nuclei` - Nuclei Vulnerability Templates
Nuclei-specific vulnerability scanning:

```json
{
  "port": [80, 443, 8080],
  "service_name": ["http", "https"],
  "tool_name": "Web Vulnerabilities",
  "tool_type": "nuclei",
  "command": "nuclei -u {protocol}://{ip}:{port} -severity critical,high -o {path/to/upload/file.txt}"
}
```

### Available Placeholders

When writing tool commands, use these placeholders:
- **{ip}**: Target IP address
- **{port}**: Port number
- **{protocol}**: `http` or `https` (for web services)
- **{path/to/upload/file.txt}**: Auto-generated output file path

### Tool Trigger Logic

Tools execute when:
1. A matching port is discovered (from the `port` array)
2. A matching service name is detected (from the `service_name` array)
3. For `http_custom` tools: HTTP content matches the `regex_match` pattern

### Example: Adding a MySQL Enumeration Tool

```json
{
  "port": [3306],
  "service_name": ["mysql"],
  "tool_name": "MySQL Enumeration",
  "tool_type": "nmap_custom",
  "command": "nmap -p {port} --script mysql-enum,mysql-info {ip}"
}
```

### Example: Adding a Custom HTTP Scanner

```json
{
  "port": [80, 443, 8080],
  "service_name": ["http", "https"],
  "tool_name": "Admin Panel Discovery",
  "tool_type": "http_custom",
  "regex_match": "200",
  "command": "ffuf -u {protocol}://{ip}:{port}/FUZZ -w /path/to/wordlist.txt -o {path/to/upload/file.txt}"
}
```

## Contributing Code

### Workflow

1. **Fork the repository**
   ```bash
   # Click the "Fork" button on GitHub
   git clone https://github.com/DefenderGB/NetPal.git
   ```

2. **Create a feature branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```

3. **Make your changes**
   - Write clean, documented code
   - Follow existing code style
   - Test your changes thoroughly

4. **Commit your changes**
   ```bash
   git add .
   git commit -m 'Add amazing feature: detailed description'
   ```

5. **Push to your fork**
   ```bash
   git push origin feature/amazing-feature
   ```

6. **Open a Pull Request**
   - Go to the original repository on GitHub
   - Click "New Pull Request"
   - Select your feature branch
   - Provide a clear description of your changes

### Code Style Guidelines

- Follow PEP 8 for Python code
- Use meaningful variable and function names
- Add docstrings to functions and classes
- Keep functions focused and single-purpose
- Comment complex logic

### Testing

Before submitting a PR:
- Test all modified functionality
- Verify no existing features are broken
- Test with different scan types and configurations
- Check error handling

### Documentation

When adding features:
- Update README.md if user-facing
- Update CONTRIBUTION.md if developer-facing
- Add inline code comments for complex logic
- Update configuration examples if needed

## Extending NetPal

### Adding a New AI Provider

To add support for a new AI provider:

1. Edit `netpal/services/ai_analyzer.py`
2. Add configuration parameters to `config.json`
3. Implement the API integration
4. Update setup wizard in `cli.py`
5. Document in README.md

### Adding New Scan Types

To add a new scan type:

1. Edit `netpal/cli.py` - add to scan type choices
2. Define nmap options for the new scan type
3. Update documentation
4. Test thoroughly

### Adding New Models

When adding data models:

1. Create new model file in `netpal/models/`
2. Implement serialization methods (`to_dict()`, `from_dict()`)
3. Update project structure if needed
4. Document the model structure

## Configuration Files

### config.json
Main configuration file - see setup wizard for options

### ai_prompts.json
AI prompt templates for finding generation

### exploit_tools.json
Automated tool execution configurations

## Best Practices

1. **Always test with small targets first**: Use /27 or /28 networks for testing
2. **Handle errors gracefully**: All functions should handle exceptions
3. **Log important events**: Use logging for debugging
4. **Validate user input**: Check inputs before processing
5. **Document edge cases**: Comment unusual situations
6. **Keep dependencies minimal**: Only add necessary packages
7. **Maintain backward compatibility**: Don't break existing projects

## Security Considerations

When contributing:
- Never commit API keys or credentials
- Validate all user inputs
- Sanitize file paths
- Be cautious with command execution
- Follow principle of least privilege

## Questions or Issues?

- **Email**: defender-gb@protonmail.com
- **GitHub Issues**: https://github.com/DefenderGB/NetPal/issues

## License

By contributing, you agree that your contributions will be licensed under the MIT License.