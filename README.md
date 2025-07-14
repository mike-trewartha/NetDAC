# NetDAC - Network Device Artifact Collector

NetDAC is a forensically sound network device data collection tool designed for incident responders and forensic investigators. It provides comprehensive volatile state collection from network devices following vendor-specific forensic guidelines and procedures.

## 🚀 Current Capabilities

NetDAC provides **enterprise-grade network device forensics** with complete multi-vendor support and forensically sound data collection procedures.

### Supported Platforms

#### ✅ **Cisco Devices** (Full Forensic Compliance)
- **IOS/IOS XE**: Complete forensic procedures implementation
- **IOS XR**: Full forensic compliance with specialized parsing
- **NX-OS**: VDC analysis and container enumeration  
- **FTD (Firepower Threat Defense)**: Trust Anchor and threat analysis
- **ASA (Adaptive Security Appliance)**: SSL VPN and connection forensics
- **FXOS**: Firepower eXtensible Operating System forensic collection
- **FPR 4100/9300**: Firepower 4100/9300 series multi-slot analysis
- **WLC IOS XE**: Wireless LAN Controller comprehensive forensics

#### ✅ **Third-Party Devices** (Enhanced Live State Analysis)
- **Palo Alto PAN-OS**: Comprehensive security policy and session analysis (37 commands)
- **Fortinet FortiGate**: Firewall policy and VPN monitoring (48 commands)
- **Juniper Junos**: Network device state and security analysis (40+ commands)

### Core Features

- **🔒 Forensically Sound**: Follows official vendor forensic procedures where available
- **🔍 Advanced Parsing**: 70+ specialized parsers for comprehensive data extraction
- **🛡️ Tampering Detection**: Image integrity, memory analysis, and digital signature verification
- **📊 Multiple Formats**: JSON, YAML, and CSV output with forensic metadata
- **⚡ Flexible Collection**: Minimal, standard, and full command sets
- **🔗 Chain of Custody**: Complete metadata tracking and evidence documentation

### Data Collection Capabilities

**Comprehensive Volatile Evidence Collection:**
- Device identification and hardware details
- Active network connections and sessions  
- Routing tables and network topology
- Running processes and memory usage
- User sessions and authentication logs
- Security configurations (ACLs, firewall rules)
- System logs and event history
- File system analysis and image verification
- Memory region analysis for tampering detection

**Command Sets:**
- `minimal`: Essential volatile data (5-10 commands, ~30-60 seconds)
- `standard`: Standard forensic collection (15-25 commands, ~2-5 minutes)  
- `full`: Comprehensive forensic analysis (35-66 commands, ~5-15 minutes)

## Quick Start

### Installation

**Prerequisites:** Go 1.19+, SSH access to target devices, privileged access for forensic commands

```bash
git clone <repository-url>
cd NetDAC
go mod tidy
go build -o netdac ./cmd/netdac
```

### Authentication Methods

NetDAC supports multiple secure authentication methods:

1. **SSH Key Authentication (Recommended)**
   ```bash
   # Using default SSH key
   netdac collect -t device.company.com -u admin -k ~/.ssh/id_rsa -v cisco-ios

   # Using custom key path
   netdac collect -t device.company.com -u admin -k /path/to/private/key -v cisco-ios
   ```

2. **Interactive Password Prompt (Secure)**
   ```bash
   # Password will be prompted securely (not displayed)
   netdac collect -t device.company.com -u admin -v cisco-ios
   ```

3. **Explicit Password (Not Recommended)**
   ```bash
   # Password visible in command history
   netdac collect -t device.company.com -u admin -p password -v cisco-ios
   ```

### SSH Key Setup

For enhanced security, configure SSH key authentication:

```bash
# Generate SSH key pair (if you don't have one)
ssh-keygen -t rsa -b 4096 -f ~/.ssh/netdac_key

# Copy public key to network devices
ssh-copy-id -i ~/.ssh/netdac_key.pub admin@device.company.com

# Use NetDAC with SSH key
netdac collect -t device.company.com -u admin -k ~/.ssh/netdac_key -v cisco-ios
```

**Supported SSH Key Types:**
- RSA keys (`~/.ssh/id_rsa`)
- ECDSA keys (`~/.ssh/id_ecdsa`) 
- Ed25519 keys (`~/.ssh/id_ed25519`)
- Password-protected keys (passphrase will be prompted)

### Basic Usage Examples

```bash
# SSH key authentication (recommended for security)
netdac collect -t asa.company.com -u investigator -k ~/.ssh/id_rsa -v cisco-asa --command-set full

# Interactive password prompt (secure alternative)
netdac collect -t wlc.company.com -u admin -v cisco-wlc-iosxe --command-set full

# SSH key with custom key path
netdac collect -t fpr4140.company.com -u admin -k /path/to/custom/key -v cisco-fpr4100-9300 --command-set full

# PAN-OS live state analysis with SSH key
netdac collect -t panos.company.com -u admin -k ~/.ssh/id_ecdsa -v paloalto --command-set full

# FortiGate full analysis  
netdac collect -t fortigate.company.com -u admin -v fortinet --command-set full

# Juniper device live state analysis
netdac collect -t mx480.company.com -u admin -k ~/.ssh/id_rsa -v juniper --command-set full

# Quick triage with default SSH key detection
netdac collect -t 10.0.0.1 -u admin -k ~/.ssh/id_rsa -v cisco-ios-xe --command-set minimal

# Output to file with SSH key authentication
netdac collect -t router.com -u admin -k ~/.ssh/id_rsa -v cisco-ios -f yaml -o evidence.yaml
netdac collect -t router.com -u admin -k ~/.ssh/id_rsa -v cisco-ios -f csv -o data.csv

# Using explicit password (not recommended for security)
netdac collect -t 192.168.1.1 -u admin -p password -v cisco-asa -o evidence.json
```

## Command Line Reference

### Global Options
- `-t, --target`: Target device IP/hostname (required)
- `-u, --username`: Authentication username (required)  
- `-p, --password`: Authentication password (optional - will prompt if not provided)
- `-k, --ssh-key`: Path to SSH private key file for authentication
- `-v, --vendor`: Device vendor (required)
- `-f, --output-format`: Output format: json, yaml, csv (default: json)
- `-o, --output`: Output file path (default: stdout)
- `--verbose`: Enable verbose output

### Supported Vendors
- `cisco-ios`: Cisco IOS devices
- `cisco-ios-xe`: Cisco IOS XE devices  
- `cisco-ios-xr`: Cisco IOS XR devices
- `cisco-nxos`: Cisco NX-OS devices
- `cisco-ftd`: Cisco FTD devices
- `cisco-asa`: Cisco ASA devices
- `cisco-fxos`: Cisco FXOS devices
- `cisco-fpr4100-9300`: Cisco Firepower 4100/9300 series
- `cisco-wlc-iosxe`: Cisco Wireless LAN Controllers (IOS XE)
- `paloalto`: Palo Alto PAN-OS devices
- `fortinet`: Fortinet FortiGate devices
- `juniper`: Juniper Junos devices

### Collection Options
- `--command-set`: Command set (minimal, standard, full) - default: standard
- `--timeout`: SSH timeout in seconds - default: 30
- `--retry`: Retry attempts for failed commands - default: 3

### Shell Completion
NetDAC supports shell autocompletion for faster command entry:

```bash
# Generate PowerShell completion script
netdac completion powershell > netdac_completion.ps1

# Generate Bash completion script  
netdac completion bash > /etc/bash_completion.d/netdac

# Generate Zsh completion script
netdac completion zsh > ~/.zsh/completions/_netdac

# Generate Fish completion script
netdac completion fish > ~/.config/fish/completions/netdac.fish
```

**Autocompletion Features:**
- Command and flag completion (`netdac collect --target`)
- Vendor name completion (`cisco-ios`, `cisco-asa`, etc.)
- File path completion for SSH keys and output files
- Interactive help and descriptions

## Forensic Compliance & Detection

### Cisco Platform Compliance
NetDAC implements official Cisco forensic data collection procedures:

- **✅ IOS/IOS XE**: Full compliance with Cisco forensic procedures including image verification, digital signatures, and memory analysis
- **✅ IOS XR**: Complete forensic implementation with process enumeration and platform integrity verification  
- **✅ NX-OS**: VDC analysis, guest shell enumeration, and software authenticity verification
- **✅ FTD**: Trust Anchor verification, threat detection integration, and connection forensics
- **✅ ASA**: SSL VPN analysis, kernel examination, and connection table forensics
- **✅ FXOS**: Firepower eXtensible Operating System forensic procedures with context switching
- **✅ FPR 4100/9300**: Multi-slot forensic analysis for Firepower 4100/9300 series chassis
- **✅ WLC IOS XE**: Wireless controller forensics with AP association and client analysis

### Evidence Quality & Chain of Custody
- **Non-invasive Collection**: No device reboots or configuration changes
- **Volatile Data Preservation**: Captures time-sensitive network state before loss
- **Integrity Verification**: Hash verification of system images and configurations
- **Metadata Tracking**: Complete timestamps, execution duration, and error logging
- **Raw Data Preservation**: Complete command output retained for analysis

## Project Structure

```
netdac/
├── cmd/netdac/                 # CLI application entry point
│   ├── main.go                 # Root command and CLI setup
│   └── collect.go              # Collection subcommand logic
├── internal/
│   ├── core/                   # Core data structures and interfaces
│   │   ├── types.go            # Data structure definitions
│   │   ├── collector.go        # Collector interface
│   │   └── parser.go           # Parser interface and utilities
│   ├── device/                 # Vendor-specific implementations
│   │   ├── cisco/              # Cisco device support
│   │   │   ├── asa.go          # ASA collector
│   │   │   └── asa_parser.go   # ASA parser
│   │   ├── fortinet/           # FortiNet device support
│   │   │   ├── fortios.go      # FortiOS collector
│   │   │   └── fortios_parser.go # FortiOS parser
│   │   └── paloalto/           # Palo Alto device support
│   │       ├── panos.go        # PAN-OS collector
│   │       └── panos_parser.go # PAN-OS parser
│   └── output/                 # Output formatting
│       ├── json.go             # JSON formatter
│       ├── yaml.go             # YAML formatter
│       └── csv.go              # CSV formatter
├── test files                  # Comprehensive test coverage
├── documentation              # Implementation reports and guides
├── go.mod & go.sum            # Go module dependencies
└── README.md                  # This documentation
```

## Current Status

### ✅ **Production Ready**
- **Multi-vendor support**: 12 major platform types fully implemented
- **Enhanced consistency**: PAN-OS, FortiGate and Junos command sets expanded by 130-150%
- **Forensic compliance**: Cisco official procedures implemented
- **Comprehensive coverage**: 80+ specialized parsers across all platforms
- **Testing**: Comprehensive test coverage with all tests passing
- **Documentation**: Complete usage guides and implementation reports
- **CLI**: Full command-line interface with all options
- **Output formats**: JSON, YAML, and CSV support
- **Error handling**: Robust connection and command error handling
- **Secure authentication**: SSH key authentication and interactive password prompts

### ✅ **Complete Implementations**
- Cisco ASA (Adaptive Security Appliance)
- Cisco IOS/IOS XE devices
- Cisco IOS XR devices  
- Cisco NX-OS devices
- Cisco FTD (Firepower Threat Defense)
- Cisco FXOS (Firepower eXtensible Operating System)
- Cisco FPR 4100/9300 (Firepower 4100/9300 series)
- Cisco WLC IOS XE (Wireless LAN Controllers)
- Palo Alto PAN-OS devices
- Fortinet FortiGate devices
- Juniper Junos devices

### 🔮 **Future Enhancements**
- Additional vendor support (Arista, etc.)
- Parallel device collection
- Configuration baseline comparison
- Plugin system for custom parsers
- CI/CD integration for automated testing

## Important Forensic Considerations

⚠️ **Critical Safety Guidelines:**
- **Never reboot devices** during forensic examination - volatile evidence will be lost
- **Isolate suspected devices** from the network before examination when possible
- **Verify image integrity** using `verify` commands in full collection mode
- **Manual procedures required** for memory dumps and core file collection

⚠️ **Platform-Specific Notes:**
- **Cisco Devices**: Some forensic procedures require manual execution (memory dumps, ROMMON analysis)
- **FTD Devices**: Crashinfo collection requires device reload - plan during maintenance window
- **PAN-OS/FortiOS/Junos**: Live analysis only - consider centralized logging platforms for historical data

## Security Considerations

- **Credential Handling**: Passwords are prompted interactively and processed in memory only, never stored or displayed
- **SSH Key Authentication**: Supports private key authentication with automatic key discovery (~/.ssh/id_rsa, ~/.ssh/id_ecdsa, etc.)
- **Interactive Password Input**: Secure password prompting prevents credentials from appearing in command history or process lists
- **Encrypted SSH Keys**: Supports password-protected SSH private keys with secure passphrase prompting
- **SSH Security**: Uses secure protocols with configurable timeouts
- **Access Requirements**: Privileged access required for most forensic commands
- **Network Impact**: Minimal impact on device performance during collection
- **Host Verification**: Implement SSH host key verification for production use
- **Authentication Flexibility**: Support for SSH keys (recommended), interactive passwords, and explicit password input

## Output Examples

### JSON Output (Default)
```bash
netdac collect -t 192.168.1.1 -u admin -k ~/.ssh/id_rsa -v cisco-asa -o evidence.json
# SSH key authentication for secure access
```

### YAML Output (Human-Readable)
```bash
netdac collect -t firewall.company.com -u admin -k ~/.ssh/id_rsa -v fortinet -f yaml -o analysis.yaml
# SSH key authentication recommended
```

### CSV Output (Analysis-Friendly)
```bash
netdac collect -t panos.company.com -u admin -k ~/.ssh/id_rsa -v paloalto -f csv -o data.csv
# SSH key authentication for automated workflows
```

## Contributing

We welcome contributions to NetDAC! Please follow these guidelines:

1. **Fork the repository** and create a feature branch
2. **Implement your changes** with appropriate tests
3. **Follow Go best practices** and maintain code quality
4. **Add tests** for new functionality and ensure all tests pass
5. **Update documentation** for any new features or changes
6. **Submit a pull request** with a clear description of changes

### Development Guidelines
- Maintain forensic compliance for new vendor implementations
- Follow existing code patterns and naming conventions
- Include comprehensive error handling and logging
- Add parser tests for new command outputs
- Update README.md for new features or vendors

## License

This project is licensed under the **MIT License**.

**Copyright (c) 2025 Mike Trewartha**

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## Support & Contact

- **Issues & Bug Reports**: [Create an issue](https://github.com/username/netdac/issues) in the repository
- **Feature Requests**: Submit via GitHub issues with the enhancement label
- **Documentation**: Check existing documentation and implementation reports
- **Community**: Discussions and community support via GitHub Discussions

## Acknowledgments

NetDAC was inspired by:
- **Eric Zimmerman's forensic tools** and methodologies for digital evidence collection
- **Cisco's official forensic procedures** for network device investigation
- **The incident response community's** need for rapid, forensically sound network device analysis
- **Open source forensic tools** that prioritize evidence integrity and chain of custody

---

**NetDAC** - Professional network device forensics for incident responders and digital investigators.
