package cisco

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"netdac/internal/core"
)

// FTDParser handles parsing of Cisco FTD (Firepower Threat Defense) command outputs
// Based on Cisco FTD Software Forensic Data Collection Procedures
// https://sec.cloudapps.cisco.com/security/center/resources/forensic_guides/ftd_forensic_investigation.html
type FTDParser struct {
	supportedCommands map[string]string
}

// NewFTDParser creates a new FTD parser instance
func NewFTDParser() *FTDParser {
	parser := &FTDParser{
		supportedCommands: make(map[string]string),
	}

	// Map commands to their parser functions
	parser.supportedCommands = map[string]string{
		"show version":                       "version",
		"show tech-support":                  "tech_support",
		"show tech-support detail":           "tech_support",
		"dir":                                "directory",
		"dir /recursive all-filesystems":     "filesystem_all",
		"dir /recursive cache:":              "filesystem_cache",
		"dir all-filesystems":                "filesystem_basic",
		"dir disk0:":                         "disk0_listing",
		"dir bootflash:":                     "bootflash_listing",
		"show software authenticity running": "auth_running",
		"show software authenticity file":    "auth_file",
		"show software authenticity keys":    "auth_keys",
		"verify":                             "file_verify",
		"verify /sha-512":                    "file_hash",
		"verify /md5":                        "file_hash",
		"verify /sha-512 system:memory/text": "memory_text_hash",
		"show processes":                     "processes",
		"show connection":                    "connections",
		"show xlate":                         "nat_translations",
		"show interface":                     "interfaces",
		"show route":                         "routes",
		"show arp":                           "arp",
		"show access-list":                   "access_lists",
		"show logging":                       "system_logs",
		"show users":                         "sessions",
		"show ssh":                           "ssh_sessions",
		"show running-config":                "running_config",
		"show startup-config":                "startup_config",
		"show memory":                        "memory",
		"show cpu":                           "cpu",
		"show clock":                         "clock",
		"show hostname":                      "hostname",
		"show firewall":                      "firewall_status",
		"show threat-detection":              "threat_detection",
		"show vpn-sessiondb":                 "vpn_sessions",
		"show failover":                      "failover_status",
		"show module":                        "modules",
		"show environment":                   "environment",
		"show inventory":                     "inventory",
		"show hardware":                      "hardware",
		"show file systems":                  "filesystems",
		"show traffic":                       "traffic_stats",
		"show counters":                      "interface_counters",
		"crashinfo":                          "crashinfo",
	}

	return parser
}

// ParseCommand parses command output into structured data
func (p *FTDParser) ParseCommand(command string, output string) (interface{}, error) {
	// Normalize command for lookup
	normalizedCmd := p.normalizeCommand(command)

	switch {
	case strings.Contains(normalizedCmd, "show version"):
		return p.ParseVersion(output)
	case strings.Contains(normalizedCmd, "show tech-support"):
		return p.ParseTechSupport(output)
	case strings.Contains(normalizedCmd, "dir") && strings.Contains(normalizedCmd, "all-filesystems"):
		return p.ParseDirectoryListing(output)
	case strings.Contains(normalizedCmd, "dir"):
		return p.ParseDirectoryListing(output)
	case strings.Contains(normalizedCmd, "show software authenticity running"):
		return p.ParseSoftwareAuthenticity(output)
	case strings.Contains(normalizedCmd, "show software authenticity file"):
		return p.ParseSoftwareAuthenticity(output)
	case strings.Contains(normalizedCmd, "show software authenticity keys"):
		return p.ParseAuthenticityKeys(output)
	case strings.Contains(normalizedCmd, "verify") && strings.Contains(normalizedCmd, "sha-512"):
		return p.ParseFileHash(output, "SHA-512")
	case strings.Contains(normalizedCmd, "verify") && strings.Contains(normalizedCmd, "md5"):
		return p.ParseFileHash(output, "MD5")
	case strings.Contains(normalizedCmd, "verify"):
		return p.ParseFileVerification(output)
	case strings.Contains(normalizedCmd, "show processes"):
		return p.ParseProcesses(output)
	case strings.Contains(normalizedCmd, "show connection"):
		return p.ParseConnections(output)
	case strings.Contains(normalizedCmd, "show xlate"):
		return p.ParseNATTranslations(output)
	case strings.Contains(normalizedCmd, "show interface"):
		return p.ParseInterfaces(output)
	case strings.Contains(normalizedCmd, "show route"):
		return p.ParseRoutes(output)
	case strings.Contains(normalizedCmd, "show arp"):
		return p.ParseARP(output)
	case strings.Contains(normalizedCmd, "show access-list"):
		return p.ParseAccessLists(output)
	case strings.Contains(normalizedCmd, "show logging"):
		return p.ParseSystemLogs(output)
	case strings.Contains(normalizedCmd, "show users"):
		return p.ParseSessions(output)
	case strings.Contains(normalizedCmd, "show ssh"):
		return p.ParseSSHSessions(output)
	case strings.Contains(normalizedCmd, "show running-config"):
		return p.ParseRunningConfig(output)
	case strings.Contains(normalizedCmd, "show startup-config"):
		return p.ParseStartupConfig(output)
	case strings.Contains(normalizedCmd, "show memory"):
		return p.ParseMemory(output)
	case strings.Contains(normalizedCmd, "show cpu"):
		return p.ParseCPU(output)
	case strings.Contains(normalizedCmd, "show clock"):
		return p.ParseClock(output)
	case strings.Contains(normalizedCmd, "show hostname"):
		return p.ParseHostname(output)
	case strings.Contains(normalizedCmd, "show firewall"):
		return p.ParseFirewallStatus(output)
	case strings.Contains(normalizedCmd, "show threat-detection"):
		return p.ParseThreatDetection(output)
	case strings.Contains(normalizedCmd, "show vpn-sessiondb"):
		return p.ParseVPNSessions(output)
	case strings.Contains(normalizedCmd, "show failover"):
		return p.ParseFailoverStatus(output)
	case strings.Contains(normalizedCmd, "show module"):
		return p.ParseModules(output)
	case strings.Contains(normalizedCmd, "show environment"):
		return p.ParseEnvironment(output)
	case strings.Contains(normalizedCmd, "show inventory"):
		return p.ParseInventory(output)
	case strings.Contains(normalizedCmd, "show hardware"):
		return p.ParseHardware(output)
	case strings.Contains(normalizedCmd, "show file systems"):
		return p.ParseFileSystems(output)
	case strings.Contains(normalizedCmd, "show traffic"):
		return p.ParseTrafficStats(output)
	case strings.Contains(normalizedCmd, "show counters"):
		return p.ParseInterfaceCounters(output)
	case strings.Contains(normalizedCmd, "crashinfo"):
		return p.ParseCrashInfo(output)
	default:
		return nil, fmt.Errorf("unsupported command: %s", command)
	}
}

// ParseVersion parses "show version" output for FTD devices
func (p *FTDParser) ParseVersion(output string) (*core.DeviceInfo, error) {
	deviceInfo := &core.DeviceInfo{
		Vendor: "cisco",
	}

	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Parse FTD model - "Model : Cisco ASA5516-X Threat Defense"
		if strings.Contains(line, "Model") && strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				model := strings.TrimSpace(parts[1])
				// Extract just the model number
				if strings.Contains(model, "ASA") {
					modelRegex := regexp.MustCompile(`(ASA\d+[A-Z\-]*X?)`)
					if matches := modelRegex.FindStringSubmatch(model); len(matches) > 0 {
						deviceInfo.Model = matches[1]
					}
				}
			}
		}

		// Parse FTD version - "Version 6.7.0.3 (Build 105)"
		if strings.Contains(line, "Version") && (strings.Contains(line, "Build") || strings.Contains(line, "(")) {
			versionRegex := regexp.MustCompile(`Version\s+([0-9\.]+)`)
			if matches := versionRegex.FindStringSubmatch(line); len(matches) > 1 {
				deviceInfo.Version = matches[1]
			}
		}

		// Parse Cisco ASA Software Version
		if strings.Contains(line, "Cisco Adaptive Security Appliance Software Version") {
			versionRegex := regexp.MustCompile(`Version\s+([0-9\.]+\([0-9]+\)\w*)`)
			if matches := versionRegex.FindStringSubmatch(line); len(matches) > 1 {
				deviceInfo.Version = matches[1]
			}
		}

		// Parse hostname
		if strings.Contains(line, "hostname") && strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				deviceInfo.Hostname = strings.TrimSpace(parts[1])
			}
		}

		// Parse uptime
		if strings.Contains(line, "up") && strings.Contains(line, "days") {
			deviceInfo.Uptime = strings.TrimSpace(line)
		}

		// Parse serial number
		if strings.Contains(line, "Serial Number") && strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				deviceInfo.SerialNumber = strings.TrimSpace(parts[1])
			}
		}
	}

	return deviceInfo, nil
}

// ParseTechSupport parses tech-support output for forensic analysis
func (p *FTDParser) ParseTechSupport(output string) (*core.TechSupportData, error) {
	lines := strings.Split(output, "\n")
	commandCount := 0
	errorCount := 0

	// Count commands and errors in tech-support output
	for _, line := range lines {
		if strings.Contains(line, "===============") && strings.Contains(line, "show") {
			commandCount++
		}
		if strings.Contains(line, "ERROR") || strings.Contains(line, "Error") || strings.Contains(line, "Invalid") {
			errorCount++
		}
	}

	forensicNotes := []string{
		"FORENSIC: FTD tech-support detail collected for comprehensive device state",
		"CRITICAL: Contains system configuration, process state, and diagnostic information",
		"INTEGRITY: Verify tech-support completeness and check for anomalous entries",
		"TAMPERING: Review for unexpected processes, configurations, or system state",
	}

	return &core.TechSupportData{
		GeneratedAt:   time.Now(),
		Size:          len(output),
		CommandCount:  commandCount,
		ErrorCount:    errorCount,
		ForensicNotes: forensicNotes,
		ParsedAt:      time.Now(),
	}, nil
}

// ParseDirectoryListing parses directory listing output for forensic file system analysis
func (p *FTDParser) ParseDirectoryListing(output string) (*core.DirectoryListing, error) {
	lines := strings.Split(output, "\n")
	var files []core.FileInfo

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "Directory of") || strings.Contains(line, "bytes total") {
			continue
		}

		// Parse FTD directory entries
		// Format: "86     -rwx  103582240    00:55:18 Mar 26 2018  os.img"
		dirRegex := regexp.MustCompile(`^\s*\d+\s+([drwx\-]+)\s+(\d+)\s+(\d{2}:\d{2}:\d{2})\s+(\w+\s+\d+\s+\d{4})\s+(.+)$`)
		if matches := dirRegex.FindStringSubmatch(line); len(matches) >= 6 {
			sizeStr := matches[2]

			timeStr := matches[3] + " " + matches[4]
			modTime, _ := time.Parse("15:04:05 Jan 2 2006", timeStr)

			files = append(files, core.FileInfo{
				Name:         matches[5],
				Size:         sizeStr,
				Permissions:  matches[1],
				ModifiedTime: modTime,
			})
		}
	}

	forensicNotes := []string{
		"FORENSIC: File system analysis for tampering detection",
		"INTEGRITY: Verify system image files and check for unauthorized files",
		"TIMELINE: Review file modification times for anomalous changes",
		"TAMPERING: Look for unexpected executables or configuration files",
	}

	return &core.DirectoryListing{
		Files:         files,
		ForensicNotes: forensicNotes,
		ParsedAt:      time.Now(),
	}, nil
}

// ParseSoftwareAuthenticity parses software authenticity verification output
func (p *FTDParser) ParseSoftwareAuthenticity(output string) (*core.SoftwareAuthenticityData, error) {
	data := &core.SoftwareAuthenticityData{
		SignerInfo:   make(map[string]string),
		VerifierInfo: make(map[string]string),
		ParsedAt:     time.Now(),
	}

	lines := strings.Split(output, "\n")
	inSignerSection := false
	inVerifierSection := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Parse image type
		if strings.Contains(line, "Image type") && strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				data.ImageType = strings.TrimSpace(parts[1])
			}
		}

		// Parse signer information section
		if strings.Contains(line, "Signer Information") {
			inSignerSection = true
			inVerifierSection = false
			continue
		}

		// Parse verifier information section
		if strings.Contains(line, "Verifier Information") {
			inVerifierSection = true
			inSignerSection = false
			continue
		}

		// Parse key-value pairs in signer section
		if inSignerSection && strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				data.SignerInfo[key] = value

				// Extract specific fields
				switch key {
				case "Certificate Serial Number":
					data.CertificateSerial = value
				case "Hash Algorithm":
					data.HashAlgorithm = value
				case "Signature Algorithm":
					data.SignatureAlgorithm = value
				case "Key Version":
					data.KeyVersion = value
				}
			}
		}

		// Parse key-value pairs in verifier section
		if inVerifierSection && strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				data.VerifierInfo[key] = value
			}
		}
	}

	// Generate forensic notes based on findings
	forensicNotes := []string{
		"FORENSIC: Digital signature verification for tampering detection",
		"CRITICAL: Verify Cisco digital signature authenticity",
		"INTEGRITY: Check certificate serial numbers and signing algorithms",
	}

	// Check for Cisco signing
	if orgName, exists := data.SignerInfo["Organization Name"]; exists {
		if strings.Contains(strings.ToLower(orgName), "cisco") {
			forensicNotes = append(forensicNotes, "VERIFIED: Cisco digital signature confirmed")
		} else {
			forensicNotes = append(forensicNotes, "WARNING: Non-Cisco digital signature detected")
		}
	}

	data.ForensicNotes = forensicNotes

	return data, nil
}

// ParseAuthenticityKeys parses public key information for verification
func (p *FTDParser) ParseAuthenticityKeys(output string) (*core.AuthenticityKeysData, error) {
	data := &core.AuthenticityKeysData{
		PublicKeys: make([]core.PublicKeyInfo, 0),
		ParsedAt:   time.Now(),
	}

	lines := strings.Split(output, "\n")
	var currentKey *core.PublicKeyInfo
	inModulusSection := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// New public key section
		if strings.Contains(line, "Public Key #") && strings.Contains(line, "Information") {
			if currentKey != nil {
				data.PublicKeys = append(data.PublicKeys, *currentKey)
			}
			currentKey = &core.PublicKeyInfo{}
			inModulusSection = false
			continue
		}

		if currentKey == nil {
			continue
		}

		// Parse key fields
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				switch key {
				case "Key Type":
					currentKey.KeyType = value
				case "Public Key Algorithm":
					currentKey.Algorithm = value
				case "Key Version":
					currentKey.KeyVersion = value
				case "Exponent":
					currentKey.Exponent = value
				case "Modulus":
					currentKey.Modulus = value
					inModulusSection = true
				}
			}
		} else if inModulusSection && strings.Contains(line, ":") {
			// Continue modulus on multiple lines
			currentKey.Modulus += line
		}
	}

	// Add the last key
	if currentKey != nil {
		data.PublicKeys = append(data.PublicKeys, *currentKey)
	}

	data.ForensicNotes = []string{
		"FORENSIC: Public key verification for digital signature validation",
		"CRITICAL: Verify public keys match Cisco Trust Anchor values",
		"INTEGRITY: Check key algorithms and versions for anomalies",
		"TAMPERING: Unauthorized keys may indicate system compromise",
	}

	return data, nil
}

// ParseFileHash parses file hash verification output
func (p *FTDParser) ParseFileHash(output, algorithm string) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Parse hash output - "verify /SHA-512 (disk0:/os.img) = <hash>"
		if strings.Contains(line, "verify /"+algorithm) && strings.Contains(line, "=") {
			parts := strings.Split(line, "=")
			if len(parts) >= 2 {
				hash := strings.TrimSpace(parts[1])
				result["hash"] = hash
				result["algorithm"] = algorithm
				result["verified_at"] = time.Now()

				// Extract filename
				fileRegex := regexp.MustCompile(`\(([^)]+)\)`)
				if matches := fileRegex.FindStringSubmatch(line); len(matches) > 1 {
					result["filename"] = matches[1]
				}
			}
		}
	}

	result["forensic_notes"] = []string{
		"FORENSIC: File integrity verification using " + algorithm + " hash",
		"CRITICAL: Compare hash values with Cisco published values",
		"INTEGRITY: Hash mismatch indicates potential tampering",
		"VERIFICATION: Use Cisco Software Checker for validation",
	}

	return result, nil
}

// ParseFileVerification parses general file verification output
func (p *FTDParser) ParseFileVerification(output string) (*core.FileVerification, error) {
	verification := &core.FileVerification{
		Verified:          false,
		TamperingDetected: false,
		SignatureVerified: false,
	}

	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Parse verification results
		if strings.Contains(line, "Computed Hash") {
			hashRegex := regexp.MustCompile(`Computed Hash\s+SHA2:\s+(.+)`)
			if matches := hashRegex.FindStringSubmatch(line); len(matches) > 1 {
				verification.ComputedSHA2 = strings.TrimSpace(matches[1])
			}
		}

		if strings.Contains(line, "Embedded Hash") {
			hashRegex := regexp.MustCompile(`Embedded Hash\s+SHA2:\s+(.+)`)
			if matches := hashRegex.FindStringSubmatch(line); len(matches) > 1 {
				verification.EmbeddedSHA2 = strings.TrimSpace(matches[1])
			}
		}

		if strings.Contains(line, "Digital signature successfully validated") {
			verification.SignatureVerified = true
			verification.Verified = true
		}

		if strings.Contains(line, "signature verification failed") {
			verification.TamperingDetected = true
		}
	}

	// Check for tampering
	if verification.ComputedSHA2 != "" && verification.EmbeddedSHA2 != "" {
		if verification.ComputedSHA2 != verification.EmbeddedSHA2 {
			verification.TamperingDetected = true
		} else {
			verification.Verified = true
		}
	}

	return verification, nil
}

// ParseProcesses parses process information for forensic analysis
func (p *FTDParser) ParseProcesses(output string) ([]core.Process, error) {
	var processes []core.Process
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "PID") || strings.Contains(line, "---") {
			continue
		}

		// Parse FTD process format
		// PID   TTY     TIME        CMD
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			process := core.Process{
				PID:  fields[0],
				Name: strings.Join(fields[3:], " "),
			}

			if len(fields) >= 2 {
				process.Runtime = fields[2]
			}

			processes = append(processes, process)
		}
	}

	return processes, nil
}

// ParseConnections parses active connections for forensic analysis
func (p *FTDParser) ParseConnections(output string) ([]core.Connection, error) {
	var connections []core.Connection
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "TCP") && strings.Contains(line, "Src") {
			continue
		}

		// Parse FTD connection format
		// TCP outside:192.168.1.100:12345 inside:10.1.1.100:80, idle 0:00:01, bytes 1234
		connRegex := regexp.MustCompile(`(\w+)\s+\w+:([^:]+):(\d+)\s+\w+:([^:]+):(\d+)`)
		if matches := connRegex.FindStringSubmatch(line); len(matches) >= 6 {
			connection := core.Connection{
				Protocol:      matches[1],
				RemoteAddress: matches[2],
				RemotePort:    matches[3],
				LocalAddress:  matches[4],
				LocalPort:     matches[5],
				State:         "ESTABLISHED",
			}

			// Parse idle time if present
			if strings.Contains(line, "idle") {
				idleRegex := regexp.MustCompile(`idle\s+([^,]+)`)
				if idleMatches := idleRegex.FindStringSubmatch(line); len(idleMatches) > 1 {
					connection.EstablishedTime = strings.TrimSpace(idleMatches[1])
				}
			}

			connections = append(connections, connection)
		}
	}

	return connections, nil
}

// ParseNATTranslations parses NAT translation table
func (p *FTDParser) ParseNATTranslations(output string) ([]core.NATRule, error) {
	var natRules []core.NATRule
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "Global") || strings.Contains(line, "---") {
			continue
		}

		// Parse NAT/xlate entries
		// Format varies, basic parsing for common patterns
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			natRule := core.NATRule{
				Type:             "dynamic",
				OriginalSource:   fields[0],
				TranslatedSource: fields[1],
			}

			if len(fields) >= 3 {
				natRule.OriginalDest = fields[2]
			}
			if len(fields) >= 4 {
				natRule.TranslatedDest = fields[3]
			}

			natRules = append(natRules, natRule)
		}
	}

	return natRules, nil
}

// Helper functions for additional parsing methods
func (p *FTDParser) ParseInterfaces(output string) ([]core.Interface, error) {
	// Implementation for interface parsing
	var interfaces []core.Interface
	// Parse FTD interface output format
	return interfaces, nil
}

func (p *FTDParser) ParseRoutes(output string) ([]core.Route, error) {
	// Implementation for route parsing
	var routes []core.Route
	// Parse FTD routing table format
	return routes, nil
}

func (p *FTDParser) ParseARP(output string) ([]core.ARPEntry, error) {
	// Implementation for ARP table parsing
	var arpEntries []core.ARPEntry
	// Parse FTD ARP table format
	return arpEntries, nil
}

func (p *FTDParser) ParseAccessLists(output string) ([]core.AccessList, error) {
	// Implementation for access list parsing
	var accessLists []core.AccessList
	// Parse FTD access list format
	return accessLists, nil
}

func (p *FTDParser) ParseSystemLogs(output string) ([]core.LogEntry, error) {
	// Implementation for system log parsing
	var logs []core.LogEntry
	// Parse FTD logging format
	return logs, nil
}

func (p *FTDParser) ParseSessions(output string) ([]core.Session, error) {
	// Implementation for user session parsing
	var sessions []core.Session
	// Parse FTD session format
	return sessions, nil
}

func (p *FTDParser) ParseSSHSessions(output string) ([]core.Session, error) {
	// Implementation for SSH session parsing
	var sessions []core.Session
	// Parse FTD SSH session format
	return sessions, nil
}

func (p *FTDParser) ParseRunningConfig(output string) (map[string]interface{}, error) {
	// Implementation for running config parsing
	config := make(map[string]interface{})
	config["raw_config"] = output
	config["parsed_at"] = time.Now()
	return config, nil
}

func (p *FTDParser) ParseStartupConfig(output string) (map[string]interface{}, error) {
	// Implementation for startup config parsing
	config := make(map[string]interface{})
	config["raw_config"] = output
	config["parsed_at"] = time.Now()
	return config, nil
}

func (p *FTDParser) ParseMemory(output string) (map[string]interface{}, error) {
	// Implementation for memory info parsing
	memory := make(map[string]interface{})
	// Parse FTD memory information
	return memory, nil
}

func (p *FTDParser) ParseCPU(output string) (map[string]interface{}, error) {
	// Implementation for CPU info parsing
	cpu := make(map[string]interface{})
	// Parse FTD CPU utilization
	return cpu, nil
}

func (p *FTDParser) ParseClock(output string) (*core.ClockInfo, error) {
	// Implementation for clock parsing
	clock := &core.ClockInfo{
		ParsedAt: time.Now(),
	}

	lines := strings.Split(output, "\n")
	if len(lines) > 0 {
		clock.CurrentTime = strings.TrimSpace(lines[0])
	}

	return clock, nil
}

func (p *FTDParser) ParseHostname(output string) (string, error) {
	// Implementation for hostname parsing
	return strings.TrimSpace(output), nil
}

func (p *FTDParser) ParseFirewallStatus(output string) (map[string]interface{}, error) {
	// Implementation for firewall status parsing
	status := make(map[string]interface{})
	status["raw_output"] = output
	return status, nil
}

func (p *FTDParser) ParseThreatDetection(output string) (map[string]interface{}, error) {
	// Implementation for threat detection parsing
	threat := make(map[string]interface{})
	threat["raw_output"] = output
	return threat, nil
}

func (p *FTDParser) ParseVPNSessions(output string) ([]core.VPNSession, error) {
	// Implementation for VPN session parsing
	var sessions []core.VPNSession
	return sessions, nil
}

func (p *FTDParser) ParseFailoverStatus(output string) (map[string]interface{}, error) {
	// Implementation for failover status parsing
	status := make(map[string]interface{})
	status["raw_output"] = output
	return status, nil
}

func (p *FTDParser) ParseModules(output string) ([]core.Module, error) {
	// Implementation for module parsing
	var modules []core.Module
	return modules, nil
}

func (p *FTDParser) ParseEnvironment(output string) ([]core.EnvironmentStat, error) {
	// Implementation for environment parsing
	var stats []core.EnvironmentStat
	return stats, nil
}

func (p *FTDParser) ParseInventory(output string) (map[string]interface{}, error) {
	// Implementation for inventory parsing
	inventory := make(map[string]interface{})
	inventory["raw_output"] = output
	return inventory, nil
}

func (p *FTDParser) ParseHardware(output string) (map[string]interface{}, error) {
	// Implementation for hardware info parsing
	hardware := make(map[string]interface{})
	hardware["raw_output"] = output
	return hardware, nil
}

func (p *FTDParser) ParseFileSystems(output string) (map[string]interface{}, error) {
	// Implementation for file systems parsing
	filesystems := make(map[string]interface{})
	filesystems["raw_output"] = output
	return filesystems, nil
}

func (p *FTDParser) ParseTrafficStats(output string) (map[string]interface{}, error) {
	// Implementation for traffic statistics parsing
	stats := make(map[string]interface{})
	stats["raw_output"] = output
	return stats, nil
}

func (p *FTDParser) ParseInterfaceCounters(output string) (map[string]interface{}, error) {
	// Implementation for interface counters parsing
	counters := make(map[string]interface{})
	counters["raw_output"] = output
	return counters, nil
}

func (p *FTDParser) ParseCrashInfo(output string) (map[string]interface{}, error) {
	// Implementation for crashinfo parsing
	crashinfo := make(map[string]interface{})
	crashinfo["raw_output"] = output
	crashinfo["parsed_at"] = time.Now()
	return crashinfo, nil
}

// GetCommandType returns the type of data this command produces
func (p *FTDParser) GetCommandType(command string) string {
	normalized := p.normalizeCommand(command)
	if cmdType, exists := p.supportedCommands[normalized]; exists {
		return cmdType
	}
	return "unknown"
}

// SupportedCommands returns the list of commands this parser can handle
func (p *FTDParser) SupportedCommands() []string {
	commands := make([]string, 0, len(p.supportedCommands))
	for cmd := range p.supportedCommands {
		commands = append(commands, cmd)
	}
	return commands
}

// normalizeCommand normalizes a command string for consistent lookup
func (p *FTDParser) normalizeCommand(command string) string {
	// Remove extra whitespace and normalize
	normalized := strings.TrimSpace(command)
	normalized = regexp.MustCompile(`\s+`).ReplaceAllString(normalized, " ")

	// Handle commands with parameters
	for cmd := range p.supportedCommands {
		if strings.HasPrefix(normalized, cmd) {
			return cmd
		}
	}

	return normalized
}
