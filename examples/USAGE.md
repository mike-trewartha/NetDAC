# NetDAC Usage Examples

This directory contains practical examples of how to use NetDAC for different scenarios.

## Basic Usage

### Single Device Collection
```bash
# Collect from a single router with password authentication
netdac collect --target 192.168.1.1 --username admin --password mypass --vendor cisco-ios --output router-data.json

# Collect from firewall with SSH key authentication  
netdac collect --target 10.0.0.1 --username admin --ssh-key ~/.ssh/id_rsa --vendor cisco-asa --output firewall-data.yaml

# Skip host key verification (use with caution)
netdac collect --target 172.16.1.1 --username admin --password mypass --vendor fortinet --skip-ssl-verify --output data.csv
```

### Different Output Formats
```bash
# JSON output (default)
netdac collect -t 192.168.1.1 -u admin -p mypass -v cisco-ios -f json -o device.json

# YAML output for human readability
netdac collect -t 192.168.1.1 -u admin -p mypass -v cisco-ios -f yaml -o device.yaml

# CSV output for forensic analysis
netdac collect -t 192.168.1.1 -u admin -p mypass -v cisco-ios -f csv -o device.csv
```

## Supported Vendors and Device Types

NetDAC currently supports the following vendor/device combinations:

- **cisco-ios** - Cisco IOS routers and switches
- **cisco-ios-xe** - Cisco IOS-XE devices  
- **cisco-ios-xr** - Cisco IOS-XR routers
- **cisco-nxos** - Cisco Nexus switches
- **cisco-asa** - Cisco ASA firewalls
- **cisco-ftd** - Cisco FTD (Firepower Threat Defense)
- **cisco-fxos** - Cisco FXOS chassis
- **cisco-fpr4100-9300** - Cisco Firepower appliances
- **cisco-wlc-iosxe** - Cisco Wireless LAN Controllers
- **fortinet** - FortiGate firewalls
- **paloalto** - Palo Alto Networks firewalls

## Advanced Usage

### Command Sets
```bash
# Minimal data collection (fastest)
netdac collect -t 192.168.1.1 -u admin -p mypass -v cisco-ios --command-set minimal

# Standard collection (default - balanced speed/completeness)  
netdac collect -t 192.168.1.1 -u admin -p mypass -v cisco-ios --command-set standard

# Full collection (comprehensive but slower)
netdac collect -t 192.168.1.1 -u admin -p mypass -v cisco-ios --command-set full
```

### Connection Options
```bash
# Custom SSH timeout (default 30 seconds)
netdac collect -t 192.168.1.1 -u admin -p mypass -v cisco-ios --timeout 60

# Retry failed commands (default 3 attempts)
netdac collect -t 192.168.1.1 -u admin -p mypass -v cisco-ios --retry 5

# Skip SSL certificate and SSH host key verification
netdac collect -t 192.168.1.1 -u admin -p mypass -v cisco-ios --skip-ssl-verify
```

### Verbose Output
```bash
# Enable verbose logging for troubleshooting
netdac collect -t 192.168.1.1 -u admin -p mypass -v cisco-ios --verbose

# Combine with other options
netdac collect -t 192.168.1.1 -u admin -v cisco-ios --verbose --timeout 60 --command-set full
```

## Authentication Methods

### Password Authentication
```bash
# Prompt for password (most secure)
netdac collect -t 192.168.1.1 -u admin -v cisco-ios

# Provide password on command line (less secure - visible in process list)
netdac collect -t 192.168.1.1 -u admin -p mypassword -v cisco-ios
```

### SSH Key Authentication  
```bash
# Use specific SSH key
netdac collect -t 192.168.1.1 -u admin -k ~/.ssh/id_rsa -v cisco-ios

# NetDAC will automatically try common SSH key locations if no key specified:
# ~/.ssh/id_rsa, ~/.ssh/id_ecdsa, ~/.ssh/id_ed25519, ~/.ssh/id_dsa
netdac collect -t 192.168.1.1 -u admin -v cisco-ios
```

## Real-World Examples

### Incident Response Scenarios
```bash
# Emergency collection from compromised firewall
netdac collect -t 10.1.1.1 -u incident -v cisco-asa --verbose --command-set full --output ./incident/firewall-$(date +%Y%m%d-%H%M%S).json

# Quick assessment of router during outage
netdac collect -t 192.168.1.1 -u netops -v cisco-ios --command-set minimal --timeout 15 --output outage-router.yaml

# Collect from multiple critical devices
netdac collect -t 10.0.0.1 -u admin -v cisco-ios --output core-router.json
netdac collect -t 10.0.0.2 -u admin -v cisco-asa --output edge-firewall.json  
netdac collect -t 10.0.0.3 -u admin -v fortinet --output dmz-firewall.json
```

### Forensic Investigation
```bash
# Comprehensive forensic collection preserving all command output
netdac collect -t 192.168.1.1 -u forensic -v cisco-ios --command-set full --output-format json --verbose --output evidence/router-core-01.json

# Collect from Palo Alto firewall for security investigation
netdac collect -t 172.16.1.1 -u readonly -v paloalto --command-set full --output evidence/palo-alto-fw.yaml
```

### Compliance and Auditing
```bash
# Network device inventory collection
netdac collect -t 192.168.1.1 -u audit -v cisco-ios --command-set standard --output-format csv --output audit/device-inventory.csv

# Security configuration assessment
netdac collect -t 10.0.0.1 -u compliance -v cisco-asa --command-set full --output compliance/firewall-config.yaml
```

## Troubleshooting

### Common Issues

#### Connection Problems
```bash
# Test basic connectivity
ping 192.168.1.1

# Verify SSH service is running  
telnet 192.168.1.1 22

# Debug connection with verbose output
netdac collect -t 192.168.1.1 -u admin -v cisco-ios --verbose
```

#### Authentication Failures
```bash
# Verify credentials manually
ssh admin@192.168.1.1

# Try different authentication methods
netdac collect -t 192.168.1.1 -u admin -v cisco-ios    # Will prompt for password
netdac collect -t 192.168.1.1 -u admin -k ~/.ssh/id_rsa -v cisco-ios    # SSH key
```

#### Timeout Issues
```bash
# Increase timeout for slow devices
netdac collect -t 192.168.1.1 -u admin -v cisco-ios --timeout 120

# Use minimal command set for faster collection
netdac collect -t 192.168.1.1 -u admin -v cisco-ios --command-set minimal
```

#### Device Type Issues
```bash
# List all supported device types
netdac collect --help

# Try different vendor types if auto-detection fails
netdac collect -t 192.168.1.1 -u admin -v cisco-ios-xe    # Instead of cisco-ios
netdac collect -t 192.168.1.1 -u admin -v cisco-nxos     # For Nexus switches
```

### Performance Optimization

#### Slow Network Links
```bash
# Use minimal command set to reduce data transfer
netdac collect -t 192.168.1.1 -u admin -v cisco-ios --command-set minimal

# Reduce timeout to fail faster on unresponsive devices
netdac collect -t 192.168.1.1 -u admin -v cisco-ios --timeout 15
```

#### Large Device Configurations
```bash
# Increase retry attempts for devices with large configs
netdac collect -t 192.168.1.1 -u admin -v cisco-ios --retry 5

# Use longer timeout for devices with many interfaces/routes
netdac collect -t 192.168.1.1 -u admin -v cisco-ios --timeout 180
```

## Command Reference

### Global Flags (available for all commands)
- `-t, --target` - Target device IP address or hostname (required)
- `-u, --username` - Username for device authentication (required)  
- `-p, --password` - Password for authentication (optional - will prompt if not provided)
- `-k, --ssh-key` - Path to SSH private key file
- `-v, --vendor` - Device vendor type (required)
- `-f, --output-format` - Output format: json, yaml, csv (default: json)
- `-o, --output` - Output file path (default: stdout)
- `--verbose` - Enable verbose output

### Collect Command Flags
- `--command-set` - Command set to execute: minimal, standard, full (default: standard)
- `--timeout` - SSH connection timeout in seconds (default: 30)
- `--retry` - Number of retry attempts for failed commands (default: 3)
- `--skip-ssl-verify` - Skip SSL certificate and SSH host key verification

## Security Considerations

### Production Environment Safety
- Always use read-only accounts when possible
- Test commands on lab devices first
- Schedule collection during maintenance windows if possible
- Monitor device CPU/memory during collection (use `--verbose` to see timing)
- Use `--command-set minimal` for initial assessment to reduce device load

### Credential Security
- Use SSH key authentication instead of passwords when possible
- If using passwords, let NetDAC prompt rather than putting passwords on command line
- Rotate device credentials after forensic collection
- Use dedicated investigation accounts with appropriate access levels

### Network Security
- Use `--skip-ssl-verify` only in controlled environments
- Be aware that SSH host keys will be automatically accepted if not in known_hosts
- Consider using jump hosts/bastion hosts for production device access
- Log all forensic collection activities for audit trails

### Data Protection
- Collected data may contain sensitive network topology information
- Store output files securely and encrypt if necessary
- Consider data retention policies for forensic evidence
- Be aware of regulatory requirements for network data collection

## Examples by Device Type

### Cisco IOS/IOS-XE Routers
```bash
# Standard collection from ISR router
netdac collect -t 192.168.1.1 -u admin -v cisco-ios -o isr-router.json

# Full collection from ASR router  
netdac collect -t 10.0.0.1 -u netops -v cisco-ios-xe --command-set full -o asr-router.yaml
```

### Cisco Switches
```bash
# Catalyst switch collection
netdac collect -t 192.168.1.10 -u admin -v cisco-ios -o catalyst-switch.json

# Nexus switch collection
netdac collect -t 10.0.0.10 -u admin -v cisco-nxos -o nexus-switch.yaml
```

### Cisco Firewalls
```bash
# ASA firewall collection
netdac collect -t 172.16.1.1 -u admin -v cisco-asa --command-set full -o asa-firewall.json

# FTD collection via CLI
netdac collect -t 172.16.1.2 -u admin -v cisco-ftd -o ftd-firewall.yaml
```

### Multi-Vendor Firewalls
```bash
# FortiGate collection
netdac collect -t 10.1.1.1 -u admin -v fortinet --command-set standard -o fortigate.json

# Palo Alto collection  
netdac collect -t 10.2.1.1 -u readonly -v paloalto --command-set full -o paloalto.yaml
```
