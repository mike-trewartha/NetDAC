# NetDAC Example Outputs

This directory contains example outputs from NetDAC showing what data is collected from different types of network devices. These examples demonstrate the comprehensive forensic data collection capabilities across multiple vendors and device types.

## Included Examples

### Cisco Devices

#### 1. ISR4321 Router (`cisco-router-isr4321.json`)
- **Device Type**: Branch office router
- **Key Features**: WAN/LAN interfaces, static routing, basic ACLs
- **Use Case**: Small to medium business edge router
- **Security Context**: Shows external/internal network separation

#### 2. Catalyst 9300 Switch (`cisco-switch-catalyst9300.yaml`) 
- **Device Type**: Layer 3 access switch
- **Key Features**: VLAN interfaces, STP, server/user network segments
- **Use Case**: Campus network access layer
- **Security Context**: Inter-VLAN access controls

#### 3. ASA 5516-X Firewall (`cisco-asa-asa5516x.yaml`)
- **Device Type**: Next-generation firewall
- **Key Features**: Security zones, VPN, object-based ACLs
- **Use Case**: Enterprise perimeter security
- **Security Context**: DMZ isolation, VPN termination

#### 4. ASR1001-X Core Router (`cisco-router-asr1001x-datacenter.csv`)
- **Device Type**: Data center core router
- **Key Features**: BGP, OSPF, high-speed interfaces, redundancy
- **Use Case**: Service provider or large enterprise core
- **Security Context**: BGP security, management access controls

### Multi-Vendor Devices

#### 5. FortiGate 100F Firewall (`fortinet-firewall-fortigate100f.csv`)
- **Device Type**: Unified threat management firewall  
- **Key Features**: Multiple security zones, web filtering, intrusion prevention
- **Use Case**: SMB security appliance
- **Security Context**: Zone-based policies, threat protection

#### 6. Palo Alto PA-3220 (`paloalto-firewall-pa3220.json`)
- **Device Type**: Next-generation firewall
- **Key Features**: App-ID, User-ID, security policies
- **Use Case**: Enterprise security with application visibility
- **Security Context**: Application-aware security policies

## Output Format Details

### JSON Format
- **Best for**: API integration, programmatic analysis
- **Features**: Nested structures, easy parsing, machine-readable
- **Use Case**: SIEM integration, automated analysis tools

### YAML Format  
- **Best for**: Human readability, configuration management
- **Features**: Clean structure, comments support, version control friendly
- **Use Case**: Documentation, manual review, configuration templates

### CSV Format
- **Best for**: Spreadsheet analysis, Timeline Explorer import
- **Features**: Tabular data, Excel compatibility, forensic timeline integration
- **Use Case**: Forensic analysis, compliance reporting, data correlation

## Forensic Investigation Context

### Timeline Analysis
- All outputs include precise timestamps for forensic reconstruction
- Compatible with Eric Zimmerman's Timeline Explorer for correlation
- Cross-reference with host-based artifacts for complete picture

### Evidence Integrity
- Device information includes serial numbers and software versions
- Collection metadata tracks success/failure rates
- Raw command outputs preserve original device responses

### Security Analysis
- ACL rules show access control policies in effect during incident
- Active sessions reveal who was connected when
- Network connections show traffic patterns and potential lateral movement

### Compliance & Reporting
- Structured data supports automated compliance checking
- Consistent format across vendors enables bulk analysis
- Professional output suitable for expert witness testimony

## Using These Examples

1. **Reference Templates**: Use as templates for expected output structure
2. **Parser Development**: Test your analysis tools against realistic data
3. **Training Material**: Learn network forensics with real-world examples  
4. **Incident Response**: Compare against collected evidence during investigations

## Data Privacy Note

All IP addresses, hostnames, and serial numbers in these examples are fictional or use RFC 5737 documentation ranges. No real network infrastructure data is included.
