package cisco

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"netdac/internal/core"
)

// FPR4100_9300Parser implements parsing of command output from Cisco Firepower 4100/9300 Series appliances
// based on official forensic data collection procedures
type FPR4100_9300Parser struct {
	patterns map[string]*regexp.Regexp
}

// NewFPR4100_9300Parser creates a new parser instance for Firepower 4100/9300 series
func NewFPR4100_9300Parser() *FPR4100_9300Parser {
	return &FPR4100_9300Parser{
		patterns: map[string]*regexp.Regexp{
			// FXOS Platform Patterns
			"fxos_version":  regexp.MustCompile(`Firepower Extensible Operating System.*Version\s+(\S+)`),
			"fxos_model":    regexp.MustCompile(`Model:\s+Cisco\s+(\S+)`),
			"fxos_hostname": regexp.MustCompile(`hostname\s+(\S+)`),
			"fxos_serial":   regexp.MustCompile(`Serial Number:\s+(\w+)`),
			"fxos_uptime":   regexp.MustCompile(`System uptime:\s+(.+)`),
			"fxos_chassis":  regexp.MustCompile(`Chassis\s+(\d+)\s+(\S+)\s+(\S+)`),

			// FTD Application Patterns
			"ftd_hostname": regexp.MustCompile(`hostname\s+(\S+)`),
			"ftd_version":  regexp.MustCompile(`Cisco Firepower Threat Defense.*Version\s+(\S+)`),
			"ftd_model":    regexp.MustCompile(`Model\s*:\s*Cisco\s+(\S+)`),
			"ftd_serial":   regexp.MustCompile(`Serial Number\s*:\s*(\w+)`),
			"ftd_uptime":   regexp.MustCompile(`up\s+(.+)`),

			// App Instance Patterns
			"app_instance": regexp.MustCompile(`^\s*(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$`),
			"slot_info":    regexp.MustCompile(`Slot\s+(\d+):\s+(\S+)`),

			// Process Patterns
			"process":         regexp.MustCompile(`^\s*(\d+)\s+\d+\s+\d+\s+\d+\s+\S+\s+[\d\.]+\s+[\d\.]+\s+\d+\s+\d+\s+\S*\s+(.+)$`),
			"ftd_process":     regexp.MustCompile(`^\s*(\d+)\s+([a-zA-Z_][a-zA-Z0-9_-]*)\s+\S+\s+\S+\s+(.+)$`),
			"adapter_process": regexp.MustCompile(`^\s*(\d+)\s+(\S+)\s+\d+\s+\d+\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(.+)$`),

			// Mezzanine Adapter Patterns
			"adapter_load":   regexp.MustCompile(`load avg:\s+([\d\.]+),\s+([\d\.]+),\s+([\d\.]+)`),
			"adapter_uptime": regexp.MustCompile(`up\s+(.+?)\s+\d+:\d+:\d+`),
			"adapter_memory": regexp.MustCompile(`Memory:\s+(\d+M)\s+used,\s+(\d+M)\s+free,\s+(\d+M)\s+cached`),
			"adapter_cpu":    regexp.MustCompile(`CPU states:\s+([\d\.]+)%\s+user,\s+([\d\.]+)%\s+nice,\s+([\d\.]+)%\s+system,\s+([\d\.]+)%\s+idle`),

			// Network Patterns
			"interface":           regexp.MustCompile(`^(\S+)\s+is\s+(\S+),\s+line\s+protocol\s+is\s+(\S+)`),
			"ip_address":          regexp.MustCompile(`Internet address is (\S+)`),
			"mac_address":         regexp.MustCompile(`Hardware is .+, address is (\S+)`),
			"fabric_interconnect": regexp.MustCompile(`Fabric\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)`),

			// Connection Patterns
			"tcp_conn": regexp.MustCompile(`tcp\s+\d+\s+\d+\s+(\S+)\.(\d+)\s+(\S+)\.(\d+)\s+(\S+)`),
			"udp_conn": regexp.MustCompile(`udp\s+\d+\s+\d+\s+(\S+)\.(\d+)\s+(\S+)\.(\d+)`),

			// Route Patterns
			"route":           regexp.MustCompile(`(\S+)\s+(\S+)\s+\[(\d+)/(\d+)\]\s+via\s+(\S+)`),
			"connected_route": regexp.MustCompile(`(\S+)\s+is\s+directly\s+connected,\s+(\S+)`),

			// Authentication/Security Patterns
			"auth_signature":   regexp.MustCompile(`Signature Algorithm\s*:\s*(.+)`),
			"auth_serial":      regexp.MustCompile(`Certificate Serial Number\s*:\s*(\w+)`),
			"auth_hash":        regexp.MustCompile(`Hash Algorithm\s*:\s*(.+)`),
			"auth_common_name": regexp.MustCompile(`Common Name\s*:\s*(.+)`),
			"auth_org_unit":    regexp.MustCompile(`Organization Unit\s*:\s*(.+)`),
			"auth_org_name":    regexp.MustCompile(`Organization Name\s*:\s*(.+)`),
			"auth_key_version": regexp.MustCompile(`Key Version\s*:\s*(\S+)`),
			"auth_verifier":    regexp.MustCompile(`Verifier name\s*:\s*(\S+)`),

			// Memory/Hash Patterns
			"memory_hash": regexp.MustCompile(`verify /SHA-512 \(.*\) = ([a-fA-F0-9]+)`),
			"file_hash":   regexp.MustCompile(`([a-fA-F0-9]{128})\s+(.+)`),
			"icdb_hash":   regexp.MustCompile(`([a-fA-F0-9]{128})\s+(.*\.icdb\.RELEASE\.tar)`),

			// File System Patterns
			"directory_entry":  regexp.MustCompile(`^\s*(\d+)\s+([d-][rwx-]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\S+\s+\d+\s+[\d:]+)\s+(.+)$`),
			"filesystem_usage": regexp.MustCompile(`(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)%\s+(.+)`),
			"mount_point":      regexp.MustCompile(`(\S+)\s+on\s+(\S+)\s+type\s+(\S+)\s+\((.+)\)`),

			// System Status Patterns
			"chassis_status":   regexp.MustCompile(`Chassis\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)`),
			"security_service": regexp.MustCompile(`(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)`),
			"platform_info":    regexp.MustCompile(`Platform\s+(\S+)\s+with\s+(\d+)\s+Mbytes`),

			// Certificate and Key Patterns
			"certificate":  regexp.MustCompile(`Certificate.*:\s*(.+)`),
			"public_key":   regexp.MustCompile(`Public Key Algorithm\s*:\s*(.+)`),
			"key_modulus":  regexp.MustCompile(`Modulus\s*:\s*((?:[A-F0-9]{2}:?)+)`),
			"key_exponent": regexp.MustCompile(`Exponent\s*:\s*(\d+)`),
		},
	}
}

// ParseCommand parses a command output based on the command type
func (p *FPR4100_9300Parser) ParseCommand(command string, output string) (interface{}, error) {
	switch {
	case strings.Contains(command, "show version"):
		if strings.Contains(command, "fxos") || strings.Contains(output, "Firepower Extensible Operating System") {
			return p.ParseFXOSVersion(output)
		}
		return p.ParseFTDVersion(output)
	case strings.Contains(command, "show app-instance"):
		return p.ParseAppInstances(output)
	case strings.Contains(command, "show tech-support"):
		return p.ParseTechSupport(output)
	case strings.Contains(command, "show processes"):
		return p.ParseProcesses(output)
	case strings.Contains(command, "show-systemstatus"):
		return p.ParseAdapterStatus(output)
	case strings.Contains(command, "show interface"):
		return p.ParseInterfaces(output)
	case strings.Contains(command, "show route"):
		return p.ParseRoutes(output)
	case strings.Contains(command, "show connection"):
		return p.ParseConnections(output)
	case strings.Contains(command, "show software authenticity"):
		return p.ParseSoftwareAuthenticity(output)
	case strings.Contains(command, "show software authenticity keys"):
		return p.ParseAuthKeys(output)
	case strings.Contains(command, "verify") && strings.Contains(command, "memory/text"):
		return p.ParseMemoryTextHash(output)
	case strings.Contains(command, "find") && strings.Contains(command, "icdb"):
		return p.ParseICDBHashes(output)
	case strings.Contains(command, "verify_file_integ.sh"):
		return p.ParseFileIntegrity(output)
	case strings.Contains(command, "dir") && strings.Contains(command, "recursive"):
		return p.ParseDirectoryListing(output)
	case strings.Contains(command, "show fabric-interconnect"):
		return p.ParseFabricInterconnect(output)
	case strings.Contains(command, "show chassis"):
		return p.ParseChassisInfo(output)
	case strings.Contains(command, "show security-service"):
		return p.ParseSecurityServices(output)
	case strings.Contains(command, "cat /proc/*/smaps"):
		return p.ParseProcessMemoryMaps(output)
	case strings.Contains(command, "ps aux"):
		return p.ParseDetailedProcesses(output)
	case strings.Contains(command, "netstat"):
		return p.ParseNetworkConnections(output)
	case strings.Contains(command, "lsof"):
		return p.ParseOpenFiles(output)
	case strings.Contains(command, "ls -la"):
		return p.ParseDirectoryListing(output)
	case strings.Contains(command, "df -h"):
		return p.ParseDiskUsage(output)
	case strings.Contains(command, "mount"):
		return p.ParseMountedFilesystems(output)
	case strings.Contains(command, "ip addr"):
		return p.ParseIPAddresses(output)
	case strings.Contains(command, "ip route"):
		return p.ParseRoutingTable(output)
	case strings.Contains(command, "arp -a"):
		return p.ParseARPTable(output)
	default:
		// Return raw output for unsupported commands
		return map[string]string{"raw_output": output}, nil
	}
}

// ParseFXOSVersion extracts FXOS version and platform information
func (p *FPR4100_9300Parser) ParseFXOSVersion(output string) (*core.DeviceInfo, error) {
	info := &core.DeviceInfo{
		Vendor: "cisco",
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Extract FXOS version
		if match := p.patterns["fxos_version"].FindStringSubmatch(line); match != nil {
			info.Version = match[1]
		}

		// Extract model number
		if match := p.patterns["fxos_model"].FindStringSubmatch(line); match != nil {
			info.Model = match[1]
		}

		// Extract hostname
		if match := p.patterns["fxos_hostname"].FindStringSubmatch(line); match != nil {
			info.Hostname = match[1]
		}

		// Extract serial number
		if match := p.patterns["fxos_serial"].FindStringSubmatch(line); match != nil {
			info.SerialNumber = match[1]
		}

		// Extract uptime
		if match := p.patterns["fxos_uptime"].FindStringSubmatch(line); match != nil {
			info.Uptime = match[1]
		}

		// Extract platform information
		if match := p.patterns["platform_info"].FindStringSubmatch(line); match != nil {
			info.Model = match[1]
		}
	}

	return info, nil
}

// ParseFTDVersion extracts FTD version information
func (p *FPR4100_9300Parser) ParseFTDVersion(output string) (*core.DeviceInfo, error) {
	info := &core.DeviceInfo{
		Vendor: "cisco",
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Extract FTD version
		if match := p.patterns["ftd_version"].FindStringSubmatch(line); match != nil {
			info.Version = match[1]
		}

		// Extract model number
		if match := p.patterns["ftd_model"].FindStringSubmatch(line); match != nil {
			info.Model = match[1]
		}

		// Extract hostname
		if match := p.patterns["ftd_hostname"].FindStringSubmatch(line); match != nil {
			info.Hostname = match[1]
		}

		// Extract serial number
		if match := p.patterns["ftd_serial"].FindStringSubmatch(line); match != nil {
			info.SerialNumber = match[1]
		}

		// Extract uptime
		if match := p.patterns["ftd_uptime"].FindStringSubmatch(line); match != nil {
			info.Uptime = match[1]
		}
	}

	return info, nil
}

// ParseAppInstances extracts application instance information
func (p *FPR4100_9300Parser) ParseAppInstances(output string) ([]map[string]string, error) {
	var instances []map[string]string
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if match := p.patterns["app_instance"].FindStringSubmatch(line); match != nil {
			instance := map[string]string{
				"slot":    match[1],
				"name":    match[2],
				"type":    match[3],
				"status":  match[4],
				"version": match[5],
			}
			instances = append(instances, instance)
		}
	}

	return instances, nil
}

// ParseTechSupport extracts summary information from tech-support output
func (p *FPR4100_9300Parser) ParseTechSupport(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	// Extract key forensic information markers
	lines := strings.Split(output, "\n")

	techSupportInfo := map[string]string{
		"collection_time": time.Now().Format(time.RFC3339),
		"output_size":     fmt.Sprintf("%d bytes", len(output)),
		"line_count":      fmt.Sprintf("%d lines", len(lines)),
	}

	// Look for specific forensic markers
	warningCount := 0
	errorCount := 0

	for _, line := range lines {
		line = strings.ToLower(strings.TrimSpace(line))
		if strings.Contains(line, "warning") {
			warningCount++
		}
		if strings.Contains(line, "error") {
			errorCount++
		}
	}

	techSupportInfo["warnings_found"] = fmt.Sprintf("%d", warningCount)
	techSupportInfo["errors_found"] = fmt.Sprintf("%d", errorCount)

	result["tech_support_summary"] = techSupportInfo
	result["full_output"] = output

	return result, nil
}

// ParseProcesses extracts process information for forensic analysis
func (p *FPR4100_9300Parser) ParseProcesses(output string) ([]core.Process, error) {
	var processes []core.Process
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Try FTD process format first
		if match := p.patterns["ftd_process"].FindStringSubmatch(line); match != nil {
			processes = append(processes, core.Process{
				PID:         match[1],
				Name:        match[2],
				CommandLine: strings.TrimSpace(match[3]),
			})
		} else if match := p.patterns["process"].FindStringSubmatch(line); match != nil {
			// Standard process format: PID ... COMMAND
			commandLine := strings.TrimSpace(match[2])
			// Extract process name from command line (first word)
			commandParts := strings.Fields(commandLine)
			processName := commandLine
			if len(commandParts) > 0 {
				processName = commandParts[0]
			}

			processes = append(processes, core.Process{
				PID:         match[1],
				Name:        processName,
				CommandLine: commandLine,
			})
		}
	}

	return processes, nil
}

// ParseAdapterStatus extracts mezzanine adapter status and process information
func (p *FPR4100_9300Parser) ParseAdapterStatus(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	lines := strings.Split(output, "\n")

	var processes []map[string]string
	systemInfo := make(map[string]string)

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Parse system load average
		if match := p.patterns["adapter_load"].FindStringSubmatch(line); match != nil {
			systemInfo["load_1min"] = match[1]
			systemInfo["load_5min"] = match[2]
			systemInfo["load_15min"] = match[3]
		}

		// Parse uptime
		if match := p.patterns["adapter_uptime"].FindStringSubmatch(line); match != nil {
			systemInfo["uptime"] = match[1]
		}

		// Parse memory usage
		if match := p.patterns["adapter_memory"].FindStringSubmatch(line); match != nil {
			systemInfo["memory_used"] = match[1]
			systemInfo["memory_free"] = match[2]
			systemInfo["memory_cached"] = match[3]
		}

		// Parse CPU usage
		if match := p.patterns["adapter_cpu"].FindStringSubmatch(line); match != nil {
			systemInfo["cpu_user"] = match[1]
			systemInfo["cpu_nice"] = match[2]
			systemInfo["cpu_system"] = match[3]
			systemInfo["cpu_idle"] = match[4]
		}

		// Parse adapter processes
		if match := p.patterns["adapter_process"].FindStringSubmatch(line); match != nil {
			process := map[string]string{
				"pid":     match[1],
				"user":    match[2],
				"command": match[3],
			}
			processes = append(processes, process)
		}
	}

	result["system_info"] = systemInfo
	result["processes"] = processes

	return result, nil
}

// ParseInterfaces extracts interface information
func (p *FPR4100_9300Parser) ParseInterfaces(output string) ([]core.Interface, error) {
	var interfaces []core.Interface
	lines := strings.Split(output, "\n")

	var currentInterface *core.Interface

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// New interface
		if match := p.patterns["interface"].FindStringSubmatch(line); match != nil {
			if currentInterface != nil {
				interfaces = append(interfaces, *currentInterface)
			}
			currentInterface = &core.Interface{
				Name:   match[1],
				Status: match[2],
			}
		}

		// IP address
		if currentInterface != nil {
			if match := p.patterns["ip_address"].FindStringSubmatch(line); match != nil {
				currentInterface.IPAddress = match[1]
			}

			// MAC address
			if match := p.patterns["mac_address"].FindStringSubmatch(line); match != nil {
				currentInterface.MACAddress = match[1]
			}
		}
	}

	// Add the last interface
	if currentInterface != nil {
		interfaces = append(interfaces, *currentInterface)
	}

	return interfaces, nil
}

// ParseRoutes extracts routing table information
func (p *FPR4100_9300Parser) ParseRoutes(output string) ([]core.Route, error) {
	var routes []core.Route
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Standard route
		if match := p.patterns["route"].FindStringSubmatch(line); match != nil {
			routes = append(routes, core.Route{
				Destination: match[1],
				Gateway:     match[5],
				Interface:   match[2],
			})
		}

		// Connected route
		if match := p.patterns["connected_route"].FindStringSubmatch(line); match != nil {
			routes = append(routes, core.Route{
				Destination: match[1],
				Gateway:     "directly connected",
				Interface:   match[2],
			})
		}
	}

	return routes, nil
}

// ParseConnections extracts connection information
func (p *FPR4100_9300Parser) ParseConnections(output string) ([]core.Connection, error) {
	var connections []core.Connection
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// TCP connections
		if match := p.patterns["tcp_conn"].FindStringSubmatch(line); match != nil {
			connections = append(connections, core.Connection{
				Protocol:      "tcp",
				LocalAddress:  match[1],
				LocalPort:     match[2],
				RemoteAddress: match[3],
				RemotePort:    match[4],
				State:         match[5],
			})
		}

		// UDP connections
		if match := p.patterns["udp_conn"].FindStringSubmatch(line); match != nil {
			connections = append(connections, core.Connection{
				Protocol:      "udp",
				LocalAddress:  match[1],
				LocalPort:     match[2],
				RemoteAddress: match[3],
				RemotePort:    match[4],
				State:         "established", // UDP doesn't have state
			})
		}
	}

	return connections, nil
}

// ParseSoftwareAuthenticity extracts digital signature verification results
func (p *FPR4100_9300Parser) ParseSoftwareAuthenticity(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	lines := strings.Split(output, "\n")

	var currentImage map[string]string
	imageType := ""

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Detect image type sections
		if strings.Contains(line, "MANAGER IMAGE") {
			imageType = "manager"
			currentImage = make(map[string]string)
		} else if strings.Contains(line, "SYSTEM IMAGE") {
			if currentImage != nil && imageType != "" {
				result[imageType] = currentImage
			}
			imageType = "system"
			currentImage = make(map[string]string)
		} else if strings.Contains(line, "KICKSTART IMAGE") {
			if currentImage != nil && imageType != "" {
				result[imageType] = currentImage
			}
			imageType = "kickstart"
			currentImage = make(map[string]string)
		}

		// Parse authentication fields
		if currentImage != nil {
			if strings.HasPrefix(line, "File Name") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					currentImage["file_name"] = strings.TrimSpace(parts[1])
				}
			}

			if match := p.patterns["auth_common_name"].FindStringSubmatch(line); match != nil {
				currentImage["common_name"] = match[1]
			}

			if match := p.patterns["auth_org_unit"].FindStringSubmatch(line); match != nil {
				currentImage["organization_unit"] = match[1]
			}

			if match := p.patterns["auth_org_name"].FindStringSubmatch(line); match != nil {
				currentImage["organization_name"] = match[1]
			}

			if match := p.patterns["auth_serial"].FindStringSubmatch(line); match != nil {
				currentImage["certificate_serial"] = match[1]
			}

			if match := p.patterns["auth_hash"].FindStringSubmatch(line); match != nil {
				currentImage["hash_algorithm"] = match[1]
			}

			if match := p.patterns["auth_signature"].FindStringSubmatch(line); match != nil {
				currentImage["signature_algorithm"] = match[1]
			}

			if match := p.patterns["auth_key_version"].FindStringSubmatch(line); match != nil {
				currentImage["key_version"] = match[1]
			}

			if match := p.patterns["auth_verifier"].FindStringSubmatch(line); match != nil {
				currentImage["verifier_name"] = match[1]
			}
		}
	}

	// Add the last image
	if currentImage != nil && imageType != "" {
		result[imageType] = currentImage
	}

	return result, nil
}

// ParseAuthKeys extracts public key information
func (p *FPR4100_9300Parser) ParseAuthKeys(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	lines := strings.Split(output, "\n")

	var currentKeyType string
	var currentKey map[string]string

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Detect key type sections
		if strings.Contains(line, "Primary Public Keys") {
			currentKeyType = "primary"
		} else if strings.Contains(line, "Backup Public Keys") {
			currentKeyType = "backup"
		} else if strings.Contains(line, "Feature Public Keys") {
			currentKeyType = "feature"
		}

		// Start of a new key
		if strings.HasPrefix(line, "Key ") && strings.Contains(line, ":") {
			if currentKey != nil && currentKeyType != "" {
				if result[currentKeyType] == nil {
					result[currentKeyType] = []map[string]string{}
				}
				keys := result[currentKeyType].([]map[string]string)
				result[currentKeyType] = append(keys, currentKey)
			}
			currentKey = make(map[string]string)
		}

		// Parse key fields
		if currentKey != nil {
			if match := p.patterns["public_key"].FindStringSubmatch(line); match != nil {
				currentKey["algorithm"] = match[1]
			}

			if match := p.patterns["key_exponent"].FindStringSubmatch(line); match != nil {
				currentKey["exponent"] = match[1]
			}

			if match := p.patterns["auth_key_version"].FindStringSubmatch(line); match != nil {
				currentKey["version"] = match[1]
			}

			// Collect modulus lines (multi-line hex values)
			if strings.Contains(line, ":") && len(strings.Fields(line)) > 1 {
				fields := strings.Fields(line)
				for _, field := range fields {
					if strings.Contains(field, ":") && len(field) > 10 {
						if currentKey["modulus"] == "" {
							currentKey["modulus"] = field
						} else {
							currentKey["modulus"] += " " + field
						}
					}
				}
			}
		}
	}

	// Add the last key
	if currentKey != nil && currentKeyType != "" {
		if result[currentKeyType] == nil {
			result[currentKeyType] = []map[string]string{}
		}
		keys := result[currentKeyType].([]map[string]string)
		result[currentKeyType] = append(keys, currentKey)
	}

	return result, nil
}

// ParseMemoryTextHash extracts memory text segment hash for integrity verification
func (p *FPR4100_9300Parser) ParseMemoryTextHash(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if match := p.patterns["memory_hash"].FindStringSubmatch(line); match != nil {
			result["hash_algorithm"] = "SHA-512"
			result["hash_value"] = match[1]
			result["segment"] = "memory/text"
			result["verification_time"] = time.Now().Format(time.RFC3339)
		}
	}

	return result, nil
}

// ParseICDBHashes extracts ICDB file hashes for integrity verification
func (p *FPR4100_9300Parser) ParseICDBHashes(output string) ([]map[string]string, error) {
	var hashes []map[string]string
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if match := p.patterns["icdb_hash"].FindStringSubmatch(line); match != nil {
			hash := map[string]string{
				"hash_value": match[1],
				"file_path":  match[2],
				"algorithm":  "SHA-512",
				"type":       "ICDB",
			}
			hashes = append(hashes, hash)
		}
	}

	return hashes, nil
}

// ParseFileIntegrity extracts file integrity verification results
func (p *FPR4100_9300Parser) ParseFileIntegrity(output string) (map[string]string, error) {
	result := make(map[string]string)

	result["verification_time"] = time.Now().Format(time.RFC3339)
	result["raw_output"] = output

	// Check for success/failure indicators
	if strings.Contains(output, "Successfully verified file integrity") {
		result["status"] = "PASS"
		result["result"] = "File integrity verification successful"
	} else if strings.Contains(output, "Failed to verify file integrity") {
		result["status"] = "FAIL"
		result["result"] = "File integrity verification failed"
	} else {
		result["status"] = "UNKNOWN"
		result["result"] = "Unable to determine verification status"
	}

	return result, nil
}

// ParseDirectoryListing extracts directory listing information
func (p *FPR4100_9300Parser) ParseDirectoryListing(output string) ([]map[string]string, error) {
	var files []map[string]string
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if match := p.patterns["directory_entry"].FindStringSubmatch(line); match != nil {
			file := map[string]string{
				"inode":       match[1],
				"permissions": match[2],
				"links":       match[3],
				"owner":       match[4],
				"group":       match[5],
				"size":        match[6],
				"date":        match[7],
				"name":        match[8],
			}
			files = append(files, file)
		}
	}

	return files, nil
}

// ParseFabricInterconnect extracts fabric interconnect information
func (p *FPR4100_9300Parser) ParseFabricInterconnect(output string) ([]map[string]string, error) {
	var fabrics []map[string]string
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if match := p.patterns["fabric_interconnect"].FindStringSubmatch(line); match != nil {
			fabric := map[string]string{
				"name":   match[1],
				"status": match[2],
				"role":   match[3],
				"state":  match[4],
			}
			fabrics = append(fabrics, fabric)
		}
	}

	return fabrics, nil
}

// ParseChassisInfo extracts chassis information
func (p *FPR4100_9300Parser) ParseChassisInfo(output string) ([]map[string]string, error) {
	var chassis []map[string]string
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if match := p.patterns["chassis_status"].FindStringSubmatch(line); match != nil {
			chassisInfo := map[string]string{
				"id":     match[1],
				"status": match[2],
				"model":  match[3],
				"serial": match[4],
			}
			chassis = append(chassis, chassisInfo)
		}
	}

	return chassis, nil
}

// ParseSecurityServices extracts security service information
func (p *FPR4100_9300Parser) ParseSecurityServices(output string) ([]map[string]string, error) {
	var services []map[string]string
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if match := p.patterns["security_service"].FindStringSubmatch(line); match != nil {
			service := map[string]string{
				"name":    match[1],
				"status":  match[2],
				"type":    match[3],
				"version": match[4],
				"health":  match[5],
			}
			services = append(services, service)
		}
	}

	return services, nil
}

// Parsing methods for additional comprehensive commands

// ParseProcessMemoryMaps extracts process memory mapping information
func (p *FPR4100_9300Parser) ParseProcessMemoryMaps(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	result["raw_output"] = output
	result["size_bytes"] = len(output)
	result["collection_time"] = time.Now().Format(time.RFC3339)

	// Count memory segments
	segmentCount := strings.Count(output, "VmFlags:")
	result["memory_segments"] = segmentCount

	return result, nil
}

// ParseDetailedProcesses extracts detailed process information from ps aux
func (p *FPR4100_9300Parser) ParseDetailedProcesses(output string) ([]map[string]string, error) {
	var processes []map[string]string
	lines := strings.Split(output, "\n")

	for i, line := range lines {
		if i == 0 { // Skip header
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 11 {
			process := map[string]string{
				"user":    fields[0],
				"pid":     fields[1],
				"cpu":     fields[2],
				"mem":     fields[3],
				"vsz":     fields[4],
				"rss":     fields[5],
				"tty":     fields[6],
				"stat":    fields[7],
				"start":   fields[8],
				"time":    fields[9],
				"command": strings.Join(fields[10:], " "),
			}
			processes = append(processes, process)
		}
	}

	return processes, nil
}

// ParseNetworkConnections extracts network connection information from netstat
func (p *FPR4100_9300Parser) ParseNetworkConnections(output string) ([]map[string]string, error) {
	var connections []map[string]string
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 6 && (fields[0] == "tcp" || fields[0] == "udp") {
			connection := map[string]string{
				"protocol":    fields[0],
				"local_addr":  fields[3],
				"remote_addr": fields[4],
				"state":       fields[5],
			}
			if len(fields) > 6 {
				connection["pid_program"] = strings.Join(fields[6:], " ")
			}
			connections = append(connections, connection)
		}
	}

	return connections, nil
}

// ParseOpenFiles extracts open files information from lsof
func (p *FPR4100_9300Parser) ParseOpenFiles(output string) ([]map[string]string, error) {
	var files []map[string]string
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 9 {
			file := map[string]string{
				"command": fields[0],
				"pid":     fields[1],
				"user":    fields[2],
				"fd":      fields[3],
				"type":    fields[4],
				"device":  fields[5],
				"size":    fields[6],
				"node":    fields[7],
				"name":    strings.Join(fields[8:], " "),
			}
			files = append(files, file)
		}
	}

	return files, nil
}

// ParseDiskUsage extracts disk usage information from df -h
func (p *FPR4100_9300Parser) ParseDiskUsage(output string) ([]map[string]string, error) {
	var filesystems []map[string]string
	lines := strings.Split(output, "\n")

	for i, line := range lines {
		if i == 0 { // Skip header
			continue
		}

		if match := p.patterns["filesystem_usage"].FindStringSubmatch(line); match != nil {
			filesystem := map[string]string{
				"filesystem":  match[1],
				"size":        match[2],
				"used":        match[3],
				"available":   match[4],
				"use_percent": match[5],
				"mounted_on":  match[6],
			}
			filesystems = append(filesystems, filesystem)
		}
	}

	return filesystems, nil
}

// ParseMountedFilesystems extracts mounted filesystem information
func (p *FPR4100_9300Parser) ParseMountedFilesystems(output string) ([]map[string]string, error) {
	var mounts []map[string]string
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		if match := p.patterns["mount_point"].FindStringSubmatch(line); match != nil {
			mount := map[string]string{
				"device":      match[1],
				"mount_point": match[2],
				"filesystem":  match[3],
				"options":     match[4],
			}
			mounts = append(mounts, mount)
		}
	}

	return mounts, nil
}

// ParseIPAddresses extracts IP address information
func (p *FPR4100_9300Parser) ParseIPAddresses(output string) ([]map[string]string, error) {
	var addresses []map[string]string

	// Simple parsing for IP addresses - could be enhanced with more specific patterns
	lines := strings.Split(output, "\n")
	currentInterface := ""

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Interface line
		if strings.Contains(line, ":") && !strings.Contains(line, "inet") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				currentInterface = strings.TrimSuffix(fields[1], ":")
			}
		}

		// IP address line
		if strings.Contains(line, "inet ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				address := map[string]string{
					"interface": currentInterface,
					"address":   fields[1],
					"type":      "inet",
				}
				addresses = append(addresses, address)
			}
		}
	}

	return addresses, nil
}

// ParseRoutingTable extracts routing table information
func (p *FPR4100_9300Parser) ParseRoutingTable(output string) ([]map[string]string, error) {
	var routes []map[string]string
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			route := map[string]string{
				"destination": fields[0],
			}

			// Parse different route formats
			if len(fields) >= 5 && fields[1] == "via" {
				route["gateway"] = fields[2]
				route["interface"] = fields[4]
			} else if len(fields) >= 3 && fields[1] == "dev" {
				route["interface"] = fields[2]
				route["gateway"] = "direct"
			}

			routes = append(routes, route)
		}
	}

	return routes, nil
}

// ParseARPTable extracts ARP table information
func (p *FPR4100_9300Parser) ParseARPTable(output string) ([]map[string]string, error) {
	var arpEntries []map[string]string
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		// Simple ARP parsing - format may vary
		if strings.Contains(line, "at") && strings.Contains(line, "on") {
			fields := strings.Fields(line)
			if len(fields) >= 6 {
				entry := map[string]string{
					"ip_address":  strings.Trim(fields[1], "()"),
					"mac_address": fields[3],
					"interface":   fields[5],
				}
				arpEntries = append(arpEntries, entry)
			}
		}
	}

	return arpEntries, nil
}

// GetCommandType determines the appropriate parser for a command
func (p *FPR4100_9300Parser) GetCommandType(command string) string {
	switch {
	case strings.Contains(command, "show version"):
		return "version"
	case strings.Contains(command, "show app-instance"):
		return "app_instances"
	case strings.Contains(command, "show tech-support"):
		return "tech_support"
	case strings.Contains(command, "show processes"):
		return "processes"
	case strings.Contains(command, "show-systemstatus"):
		return "adapter_status"
	case strings.Contains(command, "show interface"):
		return "interfaces"
	case strings.Contains(command, "show route"):
		return "routes"
	case strings.Contains(command, "show connection"):
		return "connections"
	case strings.Contains(command, "show software authenticity"):
		return "software_authenticity"
	case strings.Contains(command, "verify") && strings.Contains(command, "memory/text"):
		return "memory_hash"
	default:
		return "raw"
	}
}

// SupportedCommands returns a list of commands that have specific parsers
func (p *FPR4100_9300Parser) SupportedCommands() []string {
	return []string{
		"show version",
		"show app-instance",
		"show tech-support detail",
		"show processes",
		"show-systemstatus",
		"show interface",
		"show route",
		"show connection",
		"show software authenticity running",
		"show software authenticity keys",
		"verify /sha-512 system:memory/text",
		"find /ngfw/var/sf/.icdb/* -name *.icdb.RELEASE.tar | xargs sha512sum",
		"verify_file_integ.sh -f",
		"dir /recursive all-filesystems",
		"show fabric-interconnect",
		"show chassis",
		"show security-service",
	}
}
