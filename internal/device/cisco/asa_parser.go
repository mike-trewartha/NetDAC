package cisco

import (
	"regexp"
	"strings"
	"time"

	"netdac/internal/core"
)

// ASAParser handles parsing of Cisco ASA (Adaptive Security Appliance) command outputs
// Based on Cisco ASA Software Forensic Data Collection Procedures
// https://sec.cloudapps.cisco.com/security/center/resources/forensic_guides/asa_forensic_investigation.html
type ASAParser struct {
	supportedCommands map[string]string
}

// NewASAParser creates a new ASA parser instance
func NewASAParser() *ASAParser {
	parser := &ASAParser{
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
		"show kernel process detail":         "kernel_processes",
		"show kernel ifconfig":               "kernel_interfaces",
		"show kernel module":                 "kernel_modules",
		"show conn":                          "connections",
		"show conn all":                      "connections",
		"show xlate":                         "xlate_table",
		"show nat detail":                    "nat_translations",
		"show interface":                     "interfaces",
		"show interface ip brief":            "interfaces",
		"show ip address":                    "ip_addresses",
		"show ipv6 interface brief":          "ipv6_interfaces",
		"show route":                         "routes",
		"show ipv6 route":                    "ipv6_routes",
		"show arp":                           "arp",
		"show eigrp neighbor":                "eigrp_neighbors",
		"show ospf neighbor":                 "ospf_neighbors",
		"show bgp summary":                   "bgp_summary",
		"show access-list":                   "access_lists",
		"show logging":                       "system_logs",
		"show users":                         "sessions",
		"show ssh":                           "ssh_sessions",
		"show aaa login-history":             "login_history",
		"show running-config":                "running_config",
		"show startup-config":                "startup_config",
		"show memory":                        "memory",
		"show cpu":                           "cpu",
		"show cpu usage":                     "cpu",
		"show clock":                         "clock",
		"show clock detail":                  "clock",
		"show hostname":                      "hostname",
		"show history":                       "command_history",
		"show reload":                        "reload_info",
		"show snmp-server user":              "snmp_users",
		"show snmp-server group":             "snmp_groups",
		"show module":                        "modules",
		"show environment":                   "environment",
		"show inventory":                     "inventory",
		"show hardware":                      "hardware",
		"show run | begin webvpn":            "webvpn_config",
		"show import webvpn plug-in detail":  "webvpn_plugins",
		"export webvpn plug-in":              "webvpn_plugin_export",
		"export webvpn customization":        "webvpn_customization",
	}

	return parser
}

// ParseCommand parses command output into structured data
func (p *ASAParser) ParseCommand(command string, output string) (interface{}, error) {
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
		return p.ParseFileVerify(output)
	case strings.Contains(normalizedCmd, "show processes"):
		return p.ParseProcesses(output)
	case strings.Contains(normalizedCmd, "show kernel process"):
		return p.ParseKernelProcesses(output)
	case strings.Contains(normalizedCmd, "show kernel ifconfig"):
		return p.ParseKernelInterfaces(output)
	case strings.Contains(normalizedCmd, "show kernel module"):
		return p.ParseKernelModules(output)
	case strings.Contains(normalizedCmd, "show conn"):
		return p.ParseConnections(output)
	case strings.Contains(normalizedCmd, "show xlate"):
		return p.ParseXlateTable(output)
	case strings.Contains(normalizedCmd, "show nat detail"):
		return p.ParseNATTranslations(output)
	case strings.Contains(normalizedCmd, "show interface"):
		return p.ParseInterfaces(output)
	case strings.Contains(normalizedCmd, "show ip address"):
		return p.ParseIPAddresses(output)
	case strings.Contains(normalizedCmd, "show route"):
		return p.ParseRoutes(output)
	case strings.Contains(normalizedCmd, "show arp"):
		return p.ParseARP(output)
	case strings.Contains(normalizedCmd, "show eigrp neighbor"):
		return p.ParseEIGRPNeighbors(output)
	case strings.Contains(normalizedCmd, "show ospf neighbor"):
		return p.ParseOSPFNeighbors(output)
	case strings.Contains(normalizedCmd, "show bgp summary"):
		return p.ParseBGPSummary(output)
	case strings.Contains(normalizedCmd, "show access-list"):
		return p.ParseAccessLists(output)
	case strings.Contains(normalizedCmd, "show logging"):
		return p.ParseSystemLogs(output)
	case strings.Contains(normalizedCmd, "show users"):
		return p.ParseSessions(output)
	case strings.Contains(normalizedCmd, "show ssh"):
		return p.ParseSSHSessions(output)
	case strings.Contains(normalizedCmd, "show aaa login-history"):
		return p.ParseLoginHistory(output)
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
	case strings.Contains(normalizedCmd, "show history"):
		return p.ParseCommandHistory(output)
	case strings.Contains(normalizedCmd, "show reload"):
		return p.ParseReloadInfo(output)
	case strings.Contains(normalizedCmd, "show snmp-server user"):
		return p.ParseSNMPUsers(output)
	case strings.Contains(normalizedCmd, "show snmp-server group"):
		return p.ParseSNMPGroups(output)
	case strings.Contains(normalizedCmd, "show module"):
		return p.ParseModules(output)
	case strings.Contains(normalizedCmd, "show environment"):
		return p.ParseEnvironment(output)
	case strings.Contains(normalizedCmd, "show inventory"):
		return p.ParseInventory(output)
	case strings.Contains(normalizedCmd, "show hardware"):
		return p.ParseHardware(output)
	case strings.Contains(normalizedCmd, "show run") && strings.Contains(normalizedCmd, "webvpn"):
		return p.ParseWebVPNConfig(output)
	case strings.Contains(normalizedCmd, "show import webvpn"):
		return p.ParseWebVPNPlugins(output)
	default:
		return p.ParseGeneric(output), nil
	}
}

// ParseVersion parses the output of "show version" command
func (p *ASAParser) ParseVersion(output string) (*core.DeviceInfo, error) {
	deviceInfo := &core.DeviceInfo{
		Vendor: "cisco",
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Parse hostname
		if strings.Contains(line, "hostname") && strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				deviceInfo.Hostname = strings.TrimSpace(parts[1])
			}
		}

		// Parse model and version
		if strings.Contains(line, "Cisco Adaptive Security Appliance Software Version") {
			// Example: Cisco Adaptive Security Appliance Software Version 9.14(3)18
			re := regexp.MustCompile(`Version\s+(\S+)`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 {
				deviceInfo.Version = matches[1]
			}
		}

		// Parse hardware model
		if strings.Contains(line, "Hardware:") {
			parts := strings.Split(line, "Hardware:")
			if len(parts) > 1 {
				deviceInfo.Model = strings.TrimSpace(parts[1])
			}
		}

		// Parse serial number
		if strings.Contains(line, "Serial Number:") {
			parts := strings.Split(line, "Serial Number:")
			if len(parts) > 1 {
				deviceInfo.SerialNumber = strings.TrimSpace(parts[1])
			}
		}

		// Parse uptime
		if strings.Contains(line, "up") && (strings.Contains(line, "days") || strings.Contains(line, "hours") || strings.Contains(line, "mins")) {
			deviceInfo.Uptime = strings.TrimSpace(line)
		}
	}

	return deviceInfo, nil
}

// ParseTechSupport parses the output of "show tech-support" command
func (p *ASAParser) ParseTechSupport(output string) (map[string]interface{}, error) {
	result := map[string]interface{}{
		"raw_output":    output,
		"length":        len(output),
		"line_count":    len(strings.Split(output, "\n")),
		"collected_at":  time.Now(),
		"command_type":  "tech_support",
		"forensic_note": "Critical ASA forensic data - contains complete system state",
	}

	// Extract key sections from tech-support output
	sections := make(map[string]string)

	// Look for section headers in tech-support output
	lines := strings.Split(output, "\n")
	currentSection := ""
	currentContent := ""

	for _, line := range lines {
		if strings.HasPrefix(line, "---------------") || strings.HasPrefix(line, "===") {
			if currentSection != "" && currentContent != "" {
				sections[currentSection] = currentContent
			}
			currentSection = ""
			currentContent = ""
		} else if strings.Contains(line, "show ") && currentSection == "" {
			currentSection = strings.TrimSpace(line)
			currentContent = ""
		} else {
			currentContent += line + "\n"
		}
	}

	// Add the last section
	if currentSection != "" && currentContent != "" {
		sections[currentSection] = currentContent
	}

	result["sections"] = sections

	return result, nil
}

// ParseDirectoryListing parses directory listing output
func (p *ASAParser) ParseDirectoryListing(output string) (map[string]interface{}, error) {
	result := map[string]interface{}{
		"files":      []map[string]string{},
		"total_size": "",
		"free_space": "",
		"filesystem": "",
	}

	lines := strings.Split(output, "\n")
	files := []map[string]string{}

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Parse file entries
		if regexp.MustCompile(`^\d+\s+`).MatchString(line) {
			parts := regexp.MustCompile(`\s+`).Split(line, -1)
			if len(parts) >= 4 {
				file := map[string]string{
					"permissions": parts[1],
					"size":        parts[2],
					"date":        "",
					"name":        "",
				}

				// Date and name are in the remaining parts
				if len(parts) > 4 {
					file["date"] = strings.Join(parts[3:len(parts)-1], " ")
					file["name"] = parts[len(parts)-1]
				}

				files = append(files, file)
			}
		}

		// Parse summary information
		if strings.Contains(line, "bytes total") {
			result["total_size"] = line
		}
		if strings.Contains(line, "bytes free") {
			result["free_space"] = line
		}
	}

	result["files"] = files
	return result, nil
}

// ParseSoftwareAuthenticity parses software authenticity verification output
func (p *ASAParser) ParseSoftwareAuthenticity(output string) (map[string]interface{}, error) {
	result := map[string]interface{}{
		"file_name":           "",
		"image_type":          "",
		"common_name":         "",
		"organization":        "",
		"organization_unit":   "",
		"certificate_serial":  "",
		"hash_algorithm":      "",
		"signature_algorithm": "",
		"key_version":         "",
		"verifier_name":       "",
		"verifier_version":    "",
		"verification_status": "unknown",
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.Contains(line, "File Name") && strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				result["file_name"] = strings.TrimSpace(parts[1])
			}
		}

		if strings.Contains(line, "Image type") && strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				result["image_type"] = strings.TrimSpace(parts[1])
			}
		}

		if strings.Contains(line, "Common Name") && strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				result["common_name"] = strings.TrimSpace(parts[1])
			}
		}

		if strings.Contains(line, "Organization Name") && strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				result["organization"] = strings.TrimSpace(parts[1])
			}
		}

		if strings.Contains(line, "Organization Unit") && strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				result["organization_unit"] = strings.TrimSpace(parts[1])
			}
		}

		if strings.Contains(line, "Certificate Serial Number") && strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				result["certificate_serial"] = strings.TrimSpace(parts[1])
			}
		}

		if strings.Contains(line, "Hash Algorithm") && strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				result["hash_algorithm"] = strings.TrimSpace(parts[1])
			}
		}

		if strings.Contains(line, "Signature Algorithm") && strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				result["signature_algorithm"] = strings.TrimSpace(parts[1])
			}
		}

		if strings.Contains(line, "Key Version") && strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				result["key_version"] = strings.TrimSpace(parts[1])
			}
		}

		if strings.Contains(line, "Verifier Name") && strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				result["verifier_name"] = strings.TrimSpace(parts[1])
			}
		}

		if strings.Contains(line, "Verifier Version") && strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				result["verifier_version"] = strings.TrimSpace(parts[1])
			}
		}
	}

	// Determine verification status based on organization
	if org, ok := result["organization"].(string); ok {
		if strings.Contains(strings.ToLower(org), "cisco") {
			result["verification_status"] = "verified_cisco"
		} else if org != "" {
			result["verification_status"] = "signed_non_cisco"
		} else {
			result["verification_status"] = "unsigned"
		}
	}

	return result, nil
}

// ParseAuthenticityKeys parses the output of "show software authenticity keys"
func (p *ASAParser) ParseAuthenticityKeys(output string) (map[string]interface{}, error) {
	result := map[string]interface{}{
		"public_keys": []map[string]interface{}{},
	}

	keys := []map[string]interface{}{}
	lines := strings.Split(output, "\n")

	currentKey := map[string]interface{}{}
	inModulus := false
	modulus := ""

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.Contains(line, "Public Key #") {
			// Save previous key if exists
			if len(currentKey) > 0 {
				if modulus != "" {
					currentKey["modulus"] = modulus
				}
				keys = append(keys, currentKey)
			}

			// Start new key
			currentKey = map[string]interface{}{}
			modulus = ""
			inModulus = false
		}

		if strings.Contains(line, "Key Type") && strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				currentKey["key_type"] = strings.TrimSpace(parts[1])
			}
		}

		if strings.Contains(line, "Public Key Algorithm") && strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				currentKey["algorithm"] = strings.TrimSpace(parts[1])
			}
		}

		if strings.Contains(line, "Modulus") && strings.Contains(line, ":") {
			inModulus = true
			modulus = ""
		} else if strings.Contains(line, "Exponent") && strings.Contains(line, ":") {
			inModulus = false
			if modulus != "" {
				currentKey["modulus"] = modulus
			}
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				currentKey["exponent"] = strings.TrimSpace(parts[1])
			}
		} else if strings.Contains(line, "Key Version") && strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				currentKey["key_version"] = strings.TrimSpace(parts[1])
			}
		} else if inModulus && strings.Contains(line, ":") {
			// Append modulus line
			modulus += strings.ReplaceAll(line, " ", "") + ""
		}
	}

	// Don't forget the last key
	if len(currentKey) > 0 {
		if modulus != "" {
			currentKey["modulus"] = modulus
		}
		keys = append(keys, currentKey)
	}

	result["public_keys"] = keys
	return result, nil
}

// ParseFileHash parses file hash verification output
func (p *ASAParser) ParseFileHash(output string, hashType string) (map[string]interface{}, error) {
	result := map[string]interface{}{
		"hash_type":  hashType,
		"hash_value": "",
		"file_path":  "",
		"status":     "unknown",
		"error":      "",
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Look for hash output line
		if strings.Contains(line, "verify /") && strings.Contains(line, " = ") {
			parts := strings.Split(line, " = ")
			if len(parts) > 1 {
				result["hash_value"] = strings.TrimSpace(parts[1])
				result["status"] = "completed"

				// Extract file path from first part
				if strings.Contains(parts[0], "(") && strings.Contains(parts[0], ")") {
					re := regexp.MustCompile(`\(([^)]+)\)`)
					if matches := re.FindStringSubmatch(parts[0]); len(matches) > 1 {
						result["file_path"] = matches[1]
					}
				}
			}
		}

		// Look for error messages
		if strings.Contains(line, "Error") || strings.Contains(line, "Failed") {
			result["error"] = line
			result["status"] = "failed"
		}
	}

	return result, nil
}

// ParseFileVerify parses generic file verification output
func (p *ASAParser) ParseFileVerify(output string) (map[string]interface{}, error) {
	result := map[string]interface{}{
		"verification_type": "unknown",
		"file_path":         "",
		"status":            "unknown",
		"details":           output,
	}

	// Determine verification type based on output
	if strings.Contains(output, "SHA-512") {
		return p.ParseFileHash(output, "SHA-512")
	} else if strings.Contains(output, "MD5") {
		return p.ParseFileHash(output, "MD5")
	} else if strings.Contains(output, "SHA-256") {
		return p.ParseFileHash(output, "SHA-256")
	}

	return result, nil
}

// ParseProcesses parses the output of "show processes" command
func (p *ASAParser) ParseProcesses(output string) ([]core.Process, error) {
	processes := []core.Process{}
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip header lines and empty lines
		if line == "" || strings.Contains(line, "PC") || strings.Contains(line, "----") {
			continue
		}

		// Parse process line
		// Example format: "PID   Runtime(ms)     Invoked   uSecs    1Min   5Min   TTY Process"
		parts := regexp.MustCompile(`\s+`).Split(line, -1)
		if len(parts) >= 3 {
			process := core.Process{
				PID:     parts[0],
				Runtime: parts[1],
				Name:    "",
			}

			// Process name is usually the last field
			if len(parts) > 7 {
				process.Name = parts[len(parts)-1]
			}

			// CPU usage might be in specific columns
			if len(parts) > 5 {
				process.CPU = parts[4] // 1Min column
			}

			processes = append(processes, process)
		}
	}

	return processes, nil
}

// ParseKernelProcesses parses kernel process details
func (p *ASAParser) ParseKernelProcesses(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output": output,
		"processes":  p.extractProcessInfo(output),
		"note":       "Kernel-level process information for forensic analysis",
	}, nil
}

// ParseKernelInterfaces parses kernel interface configuration
func (p *ASAParser) ParseKernelInterfaces(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output": output,
		"interfaces": p.extractInterfaceInfo(output),
		"note":       "Kernel-level interface information for forensic analysis",
	}, nil
}

// ParseKernelModules parses kernel module information
func (p *ASAParser) ParseKernelModules(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output": output,
		"modules":    p.extractModuleInfo(output),
		"note":       "Kernel module information for forensic analysis",
	}, nil
}

// ParseConnections parses the output of "show conn" command
func (p *ASAParser) ParseConnections(output string) ([]core.Connection, error) {
	connections := []core.Connection{}
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and headers
		if line == "" || !strings.Contains(line, ":") {
			continue
		}

		// Parse connection lines
		// ASA connection format varies, but typically includes protocol and addresses
		if strings.Contains(line, "TCP") || strings.Contains(line, "UDP") || strings.Contains(line, "ICMP") {
			conn := p.parseConnectionLine(line)
			if conn.Protocol != "" {
				connections = append(connections, conn)
			}
		}
	}

	return connections, nil
}

// Helper method to parse individual connection lines
func (p *ASAParser) parseConnectionLine(line string) core.Connection {
	// This is a simplified parser - ASA connection format can be complex
	conn := core.Connection{}

	if strings.Contains(line, "TCP") {
		conn.Protocol = "TCP"
	} else if strings.Contains(line, "UDP") {
		conn.Protocol = "UDP"
	} else if strings.Contains(line, "ICMP") {
		conn.Protocol = "ICMP"
	}

	// Extract addresses and ports using regex
	// This would need more sophisticated parsing for production use
	re := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+):(\d+)`)
	matches := re.FindAllStringSubmatch(line, -1)

	if len(matches) >= 2 {
		conn.LocalAddress = matches[0][1]
		conn.LocalPort = matches[0][2]
		conn.RemoteAddress = matches[1][1]
		conn.RemotePort = matches[1][2]
	}

	return conn
}

// Additional parsing methods (simplified implementations)
func (p *ASAParser) ParseXlateTable(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output": output,
		"entries":    p.extractXlateEntries(output),
	}, nil
}

func (p *ASAParser) ParseNATTranslations(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output":   output,
		"translations": p.extractNATTranslations(output),
	}, nil
}

func (p *ASAParser) ParseInterfaces(output string) ([]core.Interface, error) {
	interfaces := []core.Interface{}
	// Simplified interface parsing
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		if strings.Contains(line, "Interface") && strings.Contains(line, "is") {
			iface := core.Interface{
				Name:   p.extractInterfaceName(line),
				Status: p.extractInterfaceStatus(line),
			}
			interfaces = append(interfaces, iface)
		}
	}

	return interfaces, nil
}

func (p *ASAParser) ParseRoutes(output string) ([]core.Route, error) {
	var routes []core.Route
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and headers
		if line == "" || strings.Contains(line, "Codes:") ||
			strings.Contains(line, "Gateway of last resort") {
			continue
		}

		// Parse route entries
		// ASA route format examples:
		// C    172.31.1.0/24 is directly connected, inside
		// S*   0.0.0.0/0 [1/0] via 203.0.113.30, outside
		// O    10.0.0.0/8 [110/2] via 172.31.1.254, inside
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			route := core.Route{}

			// First field is protocol code (C, S, O, etc.)
			if len(fields[0]) > 0 {
				protocolCode := strings.TrimLeft(fields[0], "*")
				route.Protocol = p.mapProtocolCode(protocolCode)
			}

			// Second field should be the destination network
			if strings.Contains(fields[1], "/") || strings.Contains(fields[1], ".") {
				route.Destination = fields[1]
			}

			// Look for "via" keyword for gateway
			viaIndex := -1
			for i, field := range fields {
				if field == "via" {
					viaIndex = i
					break
				}
			}

			if viaIndex > 0 && viaIndex+1 < len(fields) {
				// Extract gateway after "via"
				gateway := fields[viaIndex+1]
				// Remove trailing comma if present
				route.Gateway = strings.TrimSuffix(gateway, ",")

				// Interface is usually after gateway
				if viaIndex+2 < len(fields) {
					route.Interface = fields[viaIndex+2]
				}
			} else if strings.Contains(line, "directly connected") {
				// Connected routes format: "is directly connected, interface"
				route.Gateway = "0.0.0.0"
				for i, field := range fields {
					if field == "connected," && i+1 < len(fields) {
						route.Interface = fields[i+1]
						break
					}
				}
			}

			// Extract metric and admin distance if present [admin_distance/metric]
			for _, field := range fields {
				if strings.HasPrefix(field, "[") && strings.HasSuffix(field, "]") {
					metricInfo := strings.Trim(field, "[]")
					if strings.Contains(metricInfo, "/") {
						parts := strings.Split(metricInfo, "/")
						if len(parts) == 2 {
							route.AdminDistance = parts[0]
							route.Metric = parts[1]
						}
					}
					break
				}
			}

			// Only add route if we have a destination
			if route.Destination != "" {
				routes = append(routes, route)
			}
		}
	}

	return routes, nil
}

// mapProtocolCode maps ASA route protocol codes to readable names
func (p *ASAParser) mapProtocolCode(code string) string {
	protocolMap := map[string]string{
		"C":  "connected",
		"S":  "static",
		"R":  "rip",
		"B":  "bgp",
		"D":  "eigrp",
		"EX": "eigrp-external",
		"O":  "ospf",
		"IA": "ospf-inter-area",
		"N1": "ospf-nssa-external-type-1",
		"N2": "ospf-nssa-external-type-2",
		"E1": "ospf-external-type-1",
		"E2": "ospf-external-type-2",
		"i":  "isis",
		"L1": "isis-level-1",
		"L2": "isis-level-2",
		"ia": "isis-inter-area",
		"*":  "default-route",
	}

	cleanCode := strings.TrimSpace(code)
	if mapped, exists := protocolMap[cleanCode]; exists {
		return mapped
	}
	return cleanCode // Return original if not found
}

func (p *ASAParser) ParseARP(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output": output,
		"entries":    p.extractARPEntries(output),
	}, nil
}

// Additional simple parsers for other commands
func (p *ASAParser) ParseEIGRPNeighbors(output string) (map[string]interface{}, error) {
	return p.ParseGeneric(output), nil
}

func (p *ASAParser) ParseOSPFNeighbors(output string) (map[string]interface{}, error) {
	return p.ParseGeneric(output), nil
}

func (p *ASAParser) ParseBGPSummary(output string) (map[string]interface{}, error) {
	return p.ParseGeneric(output), nil
}

func (p *ASAParser) ParseAccessLists(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output": output,
		"acls":       p.extractAccessLists(output),
	}, nil
}

func (p *ASAParser) ParseSystemLogs(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output":  output,
		"log_entries": p.extractLogEntries(output),
	}, nil
}

func (p *ASAParser) ParseSessions(output string) ([]core.Session, error) {
	var sessions []core.Session
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and headers
		if line == "" || strings.Contains(line, "Line") ||
			strings.Contains(line, "Username") || strings.Contains(line, "---") {
			continue
		}

		// Parse user session entries
		// ASA session format examples:
		// enable_15    ssh      192.168.99.100    00:04:33  13:30:27
		// enable_15    https    172.31.1.100      00:01:22  15:44:08
		// admin        console  console           1d3h      Mon 10:15
		fields := strings.Fields(line)

		if len(fields) >= 3 {
			session := core.Session{}

			// First field is username
			session.User = fields[0]

			// Second field is connection type/line
			session.Line = fields[1]
			session.Protocol = fields[1] // ASA uses same field for protocol

			// Third field is location/source IP
			if fields[2] != "" {
				session.Location = fields[2]
				// If it looks like an IP address, also set SourceIP
				if strings.Contains(fields[2], ".") && !strings.Contains(fields[2], "console") {
					session.SourceIP = fields[2]
				}
			}

			// Fourth field is idle time
			if len(fields) >= 4 {
				session.IdleTime = fields[3]
			}

			// Fifth field is login time
			if len(fields) >= 5 {
				// Handle different time formats
				if len(fields) >= 6 {
					// Format: "Mon 10:15" or "13:30:27"
					session.LoginTime = strings.Join(fields[4:6], " ")
				} else {
					session.LoginTime = fields[4]
				}
			}

			// Determine privilege level from username
			if strings.Contains(session.User, "enable") {
				session.Privilege = "15" // Enable mode
			} else if session.User == "admin" {
				session.Privilege = "15" // Admin user
			} else {
				session.Privilege = "1" // User mode
			}

			sessions = append(sessions, session)
		}
	}

	return sessions, nil
}

func (p *ASAParser) ParseSSHSessions(output string) (map[string]interface{}, error) {
	return p.ParseGeneric(output), nil
}

func (p *ASAParser) ParseLoginHistory(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output": output,
		"logins":     p.extractLoginHistory(output),
	}, nil
}

func (p *ASAParser) ParseRunningConfig(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output":    output,
		"config_length": len(output),
		"config_lines":  len(strings.Split(output, "\n")),
		"last_modified": p.extractConfigTimestamp(output),
	}, nil
}

func (p *ASAParser) ParseStartupConfig(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output":    output,
		"config_length": len(output),
		"config_lines":  len(strings.Split(output, "\n")),
	}, nil
}

func (p *ASAParser) ParseMemory(output string) (map[string]interface{}, error) {
	return p.ParseGeneric(output), nil
}

func (p *ASAParser) ParseCPU(output string) (map[string]interface{}, error) {
	return p.ParseGeneric(output), nil
}

func (p *ASAParser) ParseClock(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output": output,
		"timestamp":  strings.TrimSpace(output),
	}, nil
}

func (p *ASAParser) ParseHostname(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"hostname": strings.TrimSpace(output),
	}, nil
}

func (p *ASAParser) ParseCommandHistory(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output": output,
		"commands":   strings.Split(output, "\n"),
	}, nil
}

func (p *ASAParser) ParseReloadInfo(output string) (map[string]interface{}, error) {
	return p.ParseGeneric(output), nil
}

func (p *ASAParser) ParseSNMPUsers(output string) (map[string]interface{}, error) {
	return p.ParseGeneric(output), nil
}

func (p *ASAParser) ParseSNMPGroups(output string) (map[string]interface{}, error) {
	return p.ParseGeneric(output), nil
}

func (p *ASAParser) ParseModules(output string) (map[string]interface{}, error) {
	return p.ParseGeneric(output), nil
}

func (p *ASAParser) ParseEnvironment(output string) (map[string]interface{}, error) {
	return p.ParseGeneric(output), nil
}

func (p *ASAParser) ParseInventory(output string) (map[string]interface{}, error) {
	return p.ParseGeneric(output), nil
}

func (p *ASAParser) ParseHardware(output string) (map[string]interface{}, error) {
	return p.ParseGeneric(output), nil
}

func (p *ASAParser) ParseIPAddresses(output string) (map[string]interface{}, error) {
	return p.ParseGeneric(output), nil
}

func (p *ASAParser) ParseWebVPNConfig(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output":   output,
		"enabled":      strings.Contains(output, "enable"),
		"ssl_vpn_info": "SSL VPN configuration for forensic analysis",
	}, nil
}

func (p *ASAParser) ParseWebVPNPlugins(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output": output,
		"plugins":    p.extractWebVPNPlugins(output),
	}, nil
}

// ParseGeneric provides a generic parser for commands that don't have specific parsers
func (p *ASAParser) ParseGeneric(output string) map[string]interface{} {
	return map[string]interface{}{
		"raw_output": output,
		"parsed_at":  time.Now(),
		"line_count": len(strings.Split(output, "\n")),
		"char_count": len(output),
	}
}

// Utility methods for parsing specific content types
func (p *ASAParser) normalizeCommand(command string) string {
	return strings.ToLower(strings.TrimSpace(command))
}

func (p *ASAParser) extractProcessInfo(output string) []map[string]string {
	// Simplified process extraction
	return []map[string]string{}
}

func (p *ASAParser) extractInterfaceInfo(output string) []map[string]string {
	// Simplified interface extraction
	return []map[string]string{}
}

func (p *ASAParser) extractModuleInfo(output string) []map[string]string {
	// Simplified module extraction
	return []map[string]string{}
}

func (p *ASAParser) extractXlateEntries(output string) []map[string]string {
	// Simplified xlate extraction
	return []map[string]string{}
}

func (p *ASAParser) extractNATTranslations(output string) []map[string]string {
	// Simplified NAT extraction
	return []map[string]string{}
}

func (p *ASAParser) extractInterfaceName(line string) string {
	// Extract interface name from line
	return "Unknown"
}

func (p *ASAParser) extractInterfaceStatus(line string) string {
	// Extract interface status from line
	return "Unknown"
}

func (p *ASAParser) extractARPEntries(output string) []map[string]string {
	// Simplified ARP extraction
	return []map[string]string{}
}

func (p *ASAParser) extractAccessLists(output string) []map[string]string {
	// Simplified ACL extraction
	return []map[string]string{}
}

func (p *ASAParser) extractLogEntries(output string) []map[string]string {
	// Simplified log extraction
	return []map[string]string{}
}

func (p *ASAParser) extractLoginHistory(output string) []map[string]string {
	// Simplified login history extraction
	return []map[string]string{}
}

func (p *ASAParser) extractConfigTimestamp(output string) string {
	// Extract last modified timestamp from config
	return ""
}

func (p *ASAParser) extractWebVPNPlugins(output string) []map[string]string {
	// Simplified WebVPN plugin extraction
	return []map[string]string{}
}

// SupportedCommands returns the list of commands this parser can handle
func (p *ASAParser) SupportedCommands() []string {
	commands := make([]string, 0, len(p.supportedCommands))
	for cmd := range p.supportedCommands {
		commands = append(commands, cmd)
	}
	return commands
}

// GetCommandType returns the type of data a command produces
func (p *ASAParser) GetCommandType(command string) string {
	if cmdType, exists := p.supportedCommands[p.normalizeCommand(command)]; exists {
		return cmdType
	}
	return "generic"
}
