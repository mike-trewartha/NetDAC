package cisco

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"netdac/internal/core"
)

// FXOSParser handles parsing of FXOS command outputs for forensic analysis
// Implements specialized parsing for Cisco Firepower 1000/2100 Series Forensic Data Collection Procedures
type FXOSParser struct {
	patterns map[string]*regexp.Regexp
}

// NewFXOSParser creates a new FXOS parser instance
func NewFXOSParser() *FXOSParser {
	return &FXOSParser{
		patterns: map[string]*regexp.Regexp{
			// FXOS Platform Patterns
			"fxos_hostname": regexp.MustCompile(`hostname\s+(\S+)`),
			"fxos_version":  regexp.MustCompile(`Cisco Firepower Extensible Operating System.*Version\s+(\S+)`),
			"fxos_model":    regexp.MustCompile(`cisco\s+(FPR-\d+\w*)`),
			"fxos_serial":   regexp.MustCompile(`Processor board ID\s+(\w+)`),
			"fxos_uptime":   regexp.MustCompile(`System uptime is (.+)`),

			// FTD Application Patterns
			"ftd_hostname": regexp.MustCompile(`hostname\s+(\S+)`),
			"ftd_version":  regexp.MustCompile(`Cisco Firepower Threat Defense.*Version\s+(\S+)`),
			"ftd_model":    regexp.MustCompile(`Model\s*:\s*Cisco\s+(\S+)`),
			"ftd_serial":   regexp.MustCompile(`Serial Number\s*:\s*(\w+)`),
			"ftd_uptime":   regexp.MustCompile(`up\s+(.+)`),

			// Process Patterns
			"process":     regexp.MustCompile(`^\s*(\d+)\s+\d+\s+\d+\s+\d+\s+\S+\s+[\d\.]+\s+[\d\.]+\s+\d+\s+\d+\s+\S*\s+(.+)$`),
			"ftd_process": regexp.MustCompile(`^\s*(\d+)\s+([a-zA-Z_][a-zA-Z0-9_-]*)\s+\S+\s+\S+\s+(.+)$`),

			// Network Patterns
			"interface":   regexp.MustCompile(`^(\S+)\s+is\s+(\S+),\s+line\s+protocol\s+is\s+(\S+)`),
			"ip_address":  regexp.MustCompile(`Internet address is (\S+)`),
			"mac_address": regexp.MustCompile(`Hardware is \S+, address is (\S+)`),

			// Connection Patterns
			"tcp_conn": regexp.MustCompile(`tcp\s+\d+\s+\d+\s+(\S+)\.(\d+)\s+(\S+)\.(\d+)\s+(\S+)`),
			"udp_conn": regexp.MustCompile(`udp\s+\d+\s+\d+\s+(\S+)\.(\d+)\s+(\S+)\.(\d+)`),

			// Route Patterns
			"route":           regexp.MustCompile(`(\S+)\s+(\S+)\s+\[(\d+)/(\d+)\]\s+via\s+(\S+)`),
			"connected_route": regexp.MustCompile(`(\S+)\s+is\s+directly\s+connected,\s+(\S+)`),

			// Authentication/Security Patterns
			"auth_signature":   regexp.MustCompile(`Signature Algorithm\s*:\s*(.+)`),
			"auth_serial":      regexp.MustCompile(`Certificate Serial Number\s*:\s*(\d+)`),
			"auth_hash":        regexp.MustCompile(`Hash Algorithm\s*:\s*(.+)`),
			"auth_common_name": regexp.MustCompile(`Common Name\s*:\s*(.+)`),
			"auth_org_unit":    regexp.MustCompile(`Organization Unit\s*:\s*(.+)`),
			"auth_org_name":    regexp.MustCompile(`Organization Name\s*:\s*(.+)`),

			// Memory/Hash Patterns
			"memory_hash": regexp.MustCompile(`verify /SHA-512 \(.*\) = ([a-fA-F0-9]+)`),
			"file_hash":   regexp.MustCompile(`([a-fA-F0-9]{128})\s+(.+)`),
		},
	}
}

// ParseCommand parses a command output based on the command type
func (p *FXOSParser) ParseCommand(command string, output string) (interface{}, error) {
	switch {
	case strings.Contains(command, "show version"):
		if strings.Contains(command, "fxos") || strings.Contains(output, "Firepower Extensible Operating System") {
			return p.ParseFXOSVersion(output)
		}
		return p.ParseFTDVersion(output)
	case strings.Contains(command, "show tech-support"):
		return p.ParseTechSupport(output)
	case strings.Contains(command, "show processes"):
		return p.ParseProcesses(output)
	case strings.Contains(command, "show interface"):
		return p.ParseInterfaces(output)
	case strings.Contains(command, "show route"):
		return p.ParseRoutes(output)
	case strings.Contains(command, "show connection"):
		return p.ParseConnections(output)
	case strings.Contains(command, "show software authenticity"):
		return p.ParseSoftwareAuthenticity(output)
	case strings.Contains(command, "verify") && strings.Contains(command, "memory/text"):
		return p.ParseMemoryTextHash(output)
	case strings.Contains(command, "show hardware"):
		return p.ParseHardware(output)
	case strings.Contains(command, "show environment"):
		return p.ParseEnvironment(output)
	case strings.Contains(command, "dir"):
		return p.ParseDirectoryListing(output)
	case strings.Contains(command, "show file"):
		return p.ParseFileInfo(output)
	default:
		// Return raw output for unsupported commands
		return map[string]string{"raw_output": output}, nil
	}
}

// ParseFXOSVersion extracts FXOS version and platform information
func (p *FXOSParser) ParseFXOSVersion(output string) (*core.DeviceInfo, error) {
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
	}

	return info, nil
}

// ParseFTDVersion extracts FTD version and application information
func (p *FXOSParser) ParseFTDVersion(output string) (*core.DeviceInfo, error) {
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

// ParseTechSupport extracts summary information from tech-support output
func (p *FXOSParser) ParseTechSupport(output string) (map[string]interface{}, error) {
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
		line = strings.TrimSpace(line)
		if strings.Contains(strings.ToLower(line), "warning") {
			warningCount++
		}
		if strings.Contains(strings.ToLower(line), "error") {
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
func (p *FXOSParser) ParseProcesses(output string) ([]core.Process, error) {
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

// ParseInterfaces extracts interface information
func (p *FXOSParser) ParseInterfaces(output string) ([]core.Interface, error) {
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
				Name:        match[1],
				AdminStatus: match[2],
				Status:      match[3],
			}
		}

		if currentInterface != nil {
			// IP address
			if match := p.patterns["ip_address"].FindStringSubmatch(line); match != nil {
				parts := strings.Split(match[1], "/")
				if len(parts) == 2 {
					currentInterface.IPAddress = parts[0]
					if cidr, err := strconv.Atoi(parts[1]); err == nil {
						// Convert CIDR to subnet mask (simplified)
						currentInterface.SubnetMask = fmt.Sprintf("/%d", cidr)
					}
				}
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
func (p *FXOSParser) ParseRoutes(output string) ([]core.Route, error) {
	var routes []core.Route
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Standard route format
		if match := p.patterns["route"].FindStringSubmatch(line); match != nil {
			routes = append(routes, core.Route{
				Destination:   match[1],
				NextHop:       match[5],
				Interface:     match[2],
				Metric:        match[4],
				AdminDistance: match[3],
			})
		}

		// Connected route format
		if match := p.patterns["connected_route"].FindStringSubmatch(line); match != nil {
			routes = append(routes, core.Route{
				Destination:   match[1],
				Gateway:       "0.0.0.0",
				Interface:     match[2],
				Metric:        "0",
				AdminDistance: "0",
			})
		}
	}

	return routes, nil
}

// ParseConnections extracts connection information
func (p *FXOSParser) ParseConnections(output string) ([]core.Connection, error) {
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
				State:         "LISTENING",
			})
		}
	}

	return connections, nil
}

// ParseSoftwareAuthenticity extracts digital signature verification information
func (p *FXOSParser) ParseSoftwareAuthenticity(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	authInfo := make(map[string]string)

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if match := p.patterns["auth_signature"].FindStringSubmatch(line); match != nil {
			authInfo["signature_algorithm"] = strings.TrimSpace(match[1])
		}
		if match := p.patterns["auth_serial"].FindStringSubmatch(line); match != nil {
			authInfo["certificate_serial"] = match[1]
		}
		if match := p.patterns["auth_hash"].FindStringSubmatch(line); match != nil {
			authInfo["hash_algorithm"] = strings.TrimSpace(match[1])
		}
		if match := p.patterns["auth_common_name"].FindStringSubmatch(line); match != nil {
			authInfo["common_name"] = strings.TrimSpace(match[1])
		}
		if match := p.patterns["auth_org_unit"].FindStringSubmatch(line); match != nil {
			authInfo["organization_unit"] = strings.TrimSpace(match[1])
		}
		if match := p.patterns["auth_org_name"].FindStringSubmatch(line); match != nil {
			authInfo["organization_name"] = strings.TrimSpace(match[1])
		}
	}

	result["authenticity_info"] = authInfo
	result["raw_output"] = output

	return result, nil
}

// ParseMemoryTextHash extracts memory .text segment hash verification
func (p *FXOSParser) ParseMemoryTextHash(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if match := p.patterns["memory_hash"].FindStringSubmatch(line); match != nil {
			result["memory_text_hash"] = match[1]
			result["hash_algorithm"] = "SHA-512"
			result["verification_time"] = time.Now().Format(time.RFC3339)
			break
		}
	}

	result["raw_output"] = output
	return result, nil
}

// ParseHardware extracts hardware information
func (p *FXOSParser) ParseHardware(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	hardwareInfo := make(map[string]string)

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Extract various hardware details
		if strings.Contains(line, "Processor") {
			hardwareInfo["processor"] = line
		}
		if strings.Contains(line, "Memory") {
			hardwareInfo["memory"] = line
		}
		if strings.Contains(line, "Flash") {
			hardwareInfo["flash"] = line
		}
	}

	result["hardware_info"] = hardwareInfo
	result["raw_output"] = output

	return result, nil
}

// ParseEnvironment extracts environmental monitoring information
func (p *FXOSParser) ParseEnvironment(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	envInfo := make(map[string]string)

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Extract environmental data
		if strings.Contains(line, "Temperature") {
			envInfo["temperature"] = line
		}
		if strings.Contains(line, "Fan") {
			envInfo["fan_status"] = line
		}
		if strings.Contains(line, "Power") {
			envInfo["power_status"] = line
		}
		if strings.Contains(line, "Voltage") {
			envInfo["voltage"] = line
		}
	}

	result["environment_info"] = envInfo
	result["raw_output"] = output

	return result, nil
}

// ParseDirectoryListing extracts file system information
func (p *FXOSParser) ParseDirectoryListing(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	files := make([]map[string]string, 0)

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip headers, empty lines, and summary lines
		if strings.HasPrefix(line, "Directory") || line == "" ||
			strings.Contains(line, "bytes total") || strings.Contains(line, "bytes free") {
			continue
		}

		// Parse file information
		fields := strings.Fields(line)
		if len(fields) >= 6 && !strings.HasSuffix(fields[0], ":") {
			fileInfo := map[string]string{
				"permissions": fields[1],                      // Second field is permissions
				"size":        fields[2],                      // Third field is size
				"date":        strings.Join(fields[3:6], " "), // Date, day, and time
				"name":        strings.Join(fields[6:], " "),  // Filename
			}
			files = append(files, fileInfo)
		}
	}

	result["files"] = files
	result["file_count"] = len(files)
	result["raw_output"] = output

	return result, nil
}

// ParseFileInfo extracts specific file information
func (p *FXOSParser) ParseFileInfo(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	// Look for file hashes
	lines := strings.Split(output, "\n")
	hashes := make([]map[string]string, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if match := p.patterns["file_hash"].FindStringSubmatch(line); match != nil {
			hashInfo := map[string]string{
				"hash":     match[1],
				"filename": match[2],
			}
			hashes = append(hashes, hashInfo)
		}
	}

	if len(hashes) > 0 {
		result["file_hashes"] = hashes
	}

	result["raw_output"] = output
	return result, nil
}

// GetCommandType returns the type of data this command produces
func (p *FXOSParser) GetCommandType(command string) string {
	switch {
	case strings.Contains(command, "show version"):
		return "device_info"
	case strings.Contains(command, "show processes"):
		return "processes"
	case strings.Contains(command, "show interface"):
		return "interfaces"
	case strings.Contains(command, "show route"):
		return "routes"
	case strings.Contains(command, "show connection"):
		return "connections"
	case strings.Contains(command, "show software authenticity"):
		return "security_verification"
	case strings.Contains(command, "verify") && strings.Contains(command, "memory/text"):
		return "memory_integrity"
	case strings.Contains(command, "show tech-support"):
		return "comprehensive_diagnostics"
	case strings.Contains(command, "dir"):
		return "filesystem_analysis"
	default:
		return "raw_output"
	}
}

// SupportedCommands returns the list of commands this parser can handle
func (p *FXOSParser) SupportedCommands() []string {
	return []string{
		"show version",
		"show tech-support fprm detail",
		"show tech-support detail",
		"show processes",
		"show interface",
		"show route",
		"show connection",
		"show software authenticity running",
		"show software authenticity keys",
		"verify /sha-512 system:memory/text",
		"show hardware",
		"show environment",
		"dir",
		"show file",
		"show running-config",
		"show logging",
		"show users",
		"show access-list",
		"show arp",
		"show inventory",
		"show module",
		"show failover",
		"show cpu usage",
		"show memory",
		"show traffic",
	}
}
