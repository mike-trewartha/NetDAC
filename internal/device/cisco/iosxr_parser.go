package cisco

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"netdac/internal/core"
)

// IOSXRParser handles parsing of IOS XR command outputs for forensic analysis
// Implements specialized parsing for Cisco IOS XR Software Forensic Data Collection Procedures
type IOSXRParser struct {
	patterns map[string]*regexp.Regexp
}

// NewIOSXRParser creates a new IOS XR parser instance
func NewIOSXRParser() *IOSXRParser {
	return &IOSXRParser{
		patterns: map[string]*regexp.Regexp{
			"hostname":     regexp.MustCompile(`RP/\d+/\w+/\w+:(\w+)#`),
			"version":      regexp.MustCompile(`Cisco IOS XR Software.*Version\s+(\S+)`),
			"model":        regexp.MustCompile(`cisco\s+(\S+)`),
			"serial":       regexp.MustCompile(`Processor board ID\s+(\w+)`),
			"uptime":       regexp.MustCompile(`(.*) uptime is (.+)`),
			"tcp_conn":     regexp.MustCompile(`tcp\s+\d+\s+\d+\s+(\S+)\.(\d+)\s+(\S+)\.(\d+)\s+(\S+)`),
			"udp_conn":     regexp.MustCompile(`(\S+)\s+(\d+)\s+(\S+)`),
			"interface":    regexp.MustCompile(`^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)`),
			"process_pid":  regexp.MustCompile(`PID:\s+(\d+)`),
			"process_path": regexp.MustCompile(`Executable path:\s+(.+)`),
			"route":        regexp.MustCompile(`(\S+)\s+(\S+)\s+(\S+)`),
		},
	}
}

// ParseCommand parses a command output based on the command type
func (p *IOSXRParser) ParseCommand(command string, output string) (interface{}, error) {
	switch {
	case strings.Contains(command, "show version"):
		return p.ParseVersion(output)
	case strings.Contains(command, "show tech-support"):
		return p.ParseTechSupport(output)
	case strings.Contains(command, "show processes"):
		return p.ParseProcesses(output)
	case strings.Contains(command, "show tcp brief"):
		return p.ParseTCPConnections(output)
	case strings.Contains(command, "show udp brief"):
		return p.ParseUDPConnections(output)
	case strings.Contains(command, "show interfaces"):
		return p.ParseInterfaces(output)
	case strings.Contains(command, "show netio clients"):
		return p.ParseNetIOClients(output)
	case strings.Contains(command, "show packet-memory clients"):
		return p.ParsePacketMemoryClients(output)
	case strings.Contains(command, "show platform security integrity"):
		return p.ParsePlatformIntegrity(output)
	case strings.Contains(command, "show install active"):
		return p.ParseInstallInfo(output)
	case strings.Contains(command, "show logging"):
		return p.ParseSystemLogs(output)
	case strings.Contains(command, "dir /recurse"):
		return p.ParseDirectoryListing(output)
	case strings.Contains(command, "show users"):
		return p.ParseSessions(output)
	case strings.Contains(command, "show route"):
		return p.ParseRoutes(output)
	default:
		// Return raw output for unparsed commands
		return map[string]interface{}{
			"raw_output": output,
			"command":    command,
		}, nil
	}
}

// ParseVersion extracts device information from show version output
func (p *IOSXRParser) ParseVersion(output string) (*core.DeviceInfo, error) {
	info := &core.DeviceInfo{
		Vendor: "cisco",
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Extract hostname from prompt
		if match := p.patterns["hostname"].FindStringSubmatch(line); match != nil {
			info.Hostname = match[1]
		}

		// Extract IOS XR version
		if match := p.patterns["version"].FindStringSubmatch(line); match != nil {
			info.Version = match[1]
		}

		// Extract model
		if match := p.patterns["model"].FindStringSubmatch(strings.ToLower(line)); match != nil {
			info.Model = strings.ToUpper(match[1])
		}

		// Extract serial number
		if match := p.patterns["serial"].FindStringSubmatch(line); match != nil {
			info.SerialNumber = match[1]
		}

		// Extract uptime
		if match := p.patterns["uptime"].FindStringSubmatch(line); match != nil {
			info.Uptime = match[2]
		}
	}

	return info, nil
}

// ParseTechSupport analyzes tech-support output for forensic evidence
func (p *IOSXRParser) ParseTechSupport(output string) (*core.TechSupportData, error) {
	data := &core.TechSupportData{
		GeneratedAt:   time.Now(),
		Size:          len(output),
		CommandCount:  strings.Count(output, "show "),
		ForensicNotes: []string{},
		ParsedAt:      time.Now(),
	}

	// Check for suspicious patterns in tech-support
	suspiciousPatterns := []string{
		"core dump",
		"segmentation fault",
		"memory corruption",
		"unexpected reboot",
		"authentication failure",
		"privilege escalation",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(strings.ToLower(output), pattern) {
			data.ForensicNotes = append(data.ForensicNotes,
				fmt.Sprintf("SUSPICIOUS: Found pattern '%s' in tech-support", pattern))
		}
	}

	// Extract critical information
	if strings.Contains(output, "crash") {
		data.ForensicNotes = append(data.ForensicNotes, "ALERT: Crash information detected")
	}

	if strings.Contains(output, "error") {
		data.ErrorCount = strings.Count(strings.ToLower(output), "error")
	}

	return data, nil
}

// ParseProcesses extracts process information for forensic analysis
func (p *IOSXRParser) ParseProcesses(output string) ([]core.Process, error) {
	var processes []core.Process
	lines := strings.Split(output, "\n")

	var currentPID, currentPath string

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Extract PID
		if match := p.patterns["process_pid"].FindStringSubmatch(line); match != nil {
			currentPID = match[1]
		}

		// Extract executable path
		if match := p.patterns["process_path"].FindStringSubmatch(line); match != nil {
			currentPath = match[1]

			// If we have both PID and path, create a process entry
			if currentPID != "" {
				// Extract process name from path
				pathParts := strings.Split(currentPath, "/")
				processName := pathParts[len(pathParts)-1]

				processes = append(processes, core.Process{
					PID:         currentPID,
					Name:        processName,
					CommandLine: currentPath,
				})

				// Reset for next process
				currentPID = ""
				currentPath = ""
			}
		}
	}

	return processes, nil
}

// ParseTCPConnections extracts TCP connection information
func (p *IOSXRParser) ParseTCPConnections(output string) ([]core.Connection, error) {
	var connections []core.Connection
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if match := p.patterns["tcp_conn"].FindStringSubmatch(line); match != nil {
			connections = append(connections, core.Connection{
				Protocol:      "TCP",
				LocalAddress:  match[1],
				LocalPort:     match[2],
				RemoteAddress: match[3],
				RemotePort:    match[4],
				State:         match[5],
			})
		}
	}

	return connections, nil
}

// ParseUDPConnections extracts UDP connection information
func (p *IOSXRParser) ParseUDPConnections(output string) ([]core.Connection, error) {
	var connections []core.Connection
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if match := p.patterns["udp_conn"].FindStringSubmatch(line); match != nil {
			connections = append(connections, core.Connection{
				Protocol:     "UDP",
				LocalAddress: match[1],
				LocalPort:    match[2],
				State:        "LISTEN",
			})
		}
	}

	return connections, nil
}

// ParseInterfaces extracts interface information
func (p *IOSXRParser) ParseInterfaces(output string) ([]core.Interface, error) {
	var interfaces []core.Interface
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if match := p.patterns["interface"].FindStringSubmatch(line); match != nil {
			interfaces = append(interfaces, core.Interface{
				Name:        match[1],
				IPAddress:   match[2],
				Status:      match[3],
				AdminStatus: match[4],
			})
		}
	}

	return interfaces, nil
}

// ParseNetIOClients extracts NetIO client information for forensic analysis
// This is critical for IOS XR forensics as it identifies processes communicating with network stack
func (p *IOSXRParser) ParseNetIOClients(output string) (*core.NetIOClientsData, error) {
	data := &core.NetIOClientsData{
		Clients:       []core.NetIOClient{},
		ForensicNotes: []string{},
		ParsedAt:      time.Now(),
	}

	lines := strings.Split(output, "\n")
	inDataSection := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Look for the data section
		if strings.Contains(line, "ClientID") {
			inDataSection = true
			continue
		}

		if inDataSection && line != "" && !strings.Contains(line, "---") {
			fields := strings.Fields(line)
			if len(fields) >= 1 {
				client := core.NetIOClient{
					ClientID: fields[0],
				}

				// Parse additional fields if available
				if len(fields) >= 3 {
					client.DropTotal = fields[1]
					client.DropTotalRx = fields[2]
				}

				data.Clients = append(data.Clients, client)

				// Add forensic notes for suspicious clients
				suspiciousClients := []string{"raw", "tcp", "udp", "ether_sock"}
				for _, suspicious := range suspiciousClients {
					if strings.Contains(strings.ToLower(client.ClientID), suspicious) {
						data.ForensicNotes = append(data.ForensicNotes,
							fmt.Sprintf("FORENSIC: NetIO client '%s' requires memory analysis", client.ClientID))
					}
				}
			}
		}
	}

	return data, nil
}

// ParsePacketMemoryClients extracts packet memory client information
// Critical for IOS XR forensics as these processes have packet processing access
func (p *IOSXRParser) ParsePacketMemoryClients(output string) (*core.PacketMemoryClientsData, error) {
	data := &core.PacketMemoryClientsData{
		Clients:       []core.PacketMemoryClient{},
		ForensicNotes: []string{},
		ParsedAt:      time.Now(),
	}

	lines := strings.Split(output, "\n")
	inDataSection := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Look for the data section
		if strings.Contains(line, "Job Id") {
			inDataSection = true
			continue
		}

		if inDataSection && line != "" && !strings.Contains(line, "---") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				if jobId, err := strconv.Atoi(fields[0]); err == nil {
					if coid, err := strconv.Atoi(fields[1]); err == nil {
						client := core.PacketMemoryClient{
							JobID:   jobId,
							Coid:    coid,
							Options: fields[2],
							Process: fields[3],
						}

						data.Clients = append(data.Clients, client)

						// Add forensic note for all packet memory clients
						data.ForensicNotes = append(data.ForensicNotes,
							fmt.Sprintf("FORENSIC: Process '%s' has packet memory access - requires examination", client.Process))
					}
				}
			}
		}
	}

	return data, nil
}

// ParsePlatformIntegrity analyzes platform integrity information
func (p *IOSXRParser) ParsePlatformIntegrity(output string) (*core.PlatformIntegrityData, error) {
	data := &core.PlatformIntegrityData{
		SecureBootStatus: "Unknown",
		IntegrityChecks:  []string{},
		ForensicNotes:    []string{},
		ParsedAt:         time.Now(),
	}

	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.Contains(strings.ToLower(line), "secure boot") {
			if strings.Contains(strings.ToLower(line), "enabled") {
				data.SecureBootStatus = "Enabled"
			} else if strings.Contains(strings.ToLower(line), "disabled") {
				data.SecureBootStatus = "Disabled"
				data.ForensicNotes = append(data.ForensicNotes, "WARNING: Secure boot is disabled")
			}
		}

		if strings.Contains(strings.ToLower(line), "integrity") {
			data.IntegrityChecks = append(data.IntegrityChecks, line)
		}

		if strings.Contains(strings.ToLower(line), "tamper") {
			data.ForensicNotes = append(data.ForensicNotes,
				fmt.Sprintf("ALERT: Possible tampering detected: %s", line))
		}
	}

	return data, nil
}

// ParseInstallInfo extracts active software installation information
func (p *IOSXRParser) ParseInstallInfo(output string) (*core.InstallInfo, error) {
	info := &core.InstallInfo{
		ActivePackages: []string{},
		Version:        "Unknown",
		ParsedAt:       time.Now(),
	}

	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.Contains(line, "Active Packages") {
			continue
		}

		if strings.Contains(line, ".rpm") || strings.Contains(line, "xr-") {
			info.ActivePackages = append(info.ActivePackages, line)
		}

		if strings.Contains(line, "Version") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				info.Version = fields[len(fields)-1]
			}
		}
	}

	return info, nil
}

// ParseSystemLogs extracts system log information for forensic analysis
func (p *IOSXRParser) ParseSystemLogs(output string) (*core.SystemLogData, error) {
	data := &core.SystemLogData{
		LogEntries:    []core.LogEntry{},
		ForensicNotes: []string{},
		ParsedAt:      time.Now(),
	}

	lines := strings.Split(output, "\n")

	// Forensic patterns to look for in logs
	forensicPatterns := map[string]string{
		"authentication failure": "SECURITY",
		"privilege escalation":   "SECURITY",
		"core dump":              "SYSTEM",
		"segmentation fault":     "SYSTEM",
		"memory corruption":      "SYSTEM",
		"unexpected reboot":      "SYSTEM",
		"tamper":                 "INTEGRITY",
		"integrity":              "INTEGRITY",
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}

		// Create log entry
		entry := core.LogEntry{
			Message:   line,
			Timestamp: time.Now(), // In real implementation, parse actual timestamp
		}

		// Check for forensic patterns
		for pattern, category := range forensicPatterns {
			if strings.Contains(strings.ToLower(line), pattern) {
				entry.Category = category
				data.ForensicNotes = append(data.ForensicNotes,
					fmt.Sprintf("FORENSIC ALERT [%s]: %s", category, pattern))
			}
		}

		data.LogEntries = append(data.LogEntries, entry)
	}

	return data, nil
}

// ParseDirectoryListing analyzes directory listings for forensic evidence
func (p *IOSXRParser) ParseDirectoryListing(output string) (*core.DirectoryListing, error) {
	listing := &core.DirectoryListing{
		Files:         []core.FileInfo{},
		ForensicNotes: []string{},
		ParsedAt:      time.Now(),
	}

	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "Directory of") {
			continue
		}

		// Simple parsing - in real implementation would be more sophisticated
		fields := strings.Fields(line)
		if len(fields) >= 5 {
			file := core.FileInfo{
				Name:         fields[len(fields)-1],
				Size:         fields[len(fields)-3],
				Permissions:  fields[0],
				ModifiedTime: time.Now(), // Would parse actual timestamp
			}

			listing.Files = append(listing.Files, file)

			// Check for suspicious files
			suspiciousExtensions := []string{".sh", ".bin", ".exe", ".py", ".pl"}
			for _, ext := range suspiciousExtensions {
				if strings.HasSuffix(strings.ToLower(file.Name), ext) {
					listing.ForensicNotes = append(listing.ForensicNotes,
						fmt.Sprintf("FORENSIC: Suspicious file found: %s", file.Name))
				}
			}
		}
	}

	return listing, nil
}

// ParseSessions extracts user session information
func (p *IOSXRParser) ParseSessions(output string) ([]core.Session, error) {
	var sessions []core.Session
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.Contains(line, "tty") || strings.Contains(line, "vty") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				session := core.Session{
					User:      fields[0],
					Line:      fields[1],
					LoginTime: time.Now().Format("2006-01-02 15:04:05"), // Format as string
					Location:  "console",
				}

				if len(fields) >= 4 {
					session.Location = fields[3]
				}

				sessions = append(sessions, session)
			}
		}
	}

	return sessions, nil
}

// ParseRoutes extracts routing table information
func (p *IOSXRParser) ParseRoutes(output string) ([]core.Route, error) {
	var routes []core.Route
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if match := p.patterns["route"].FindStringSubmatch(line); match != nil {
			routes = append(routes, core.Route{
				Destination: match[1],
				NextHop:     match[2],
				Interface:   match[3],
				Protocol:    "unknown", // Would need better parsing
			})
		}
	}

	return routes, nil
}

// GetCommandType returns the type of data a command produces
func (p *IOSXRParser) GetCommandType(command string) string {
	switch {
	case strings.Contains(command, "show version"):
		return "version_info"
	case strings.Contains(command, "show tech-support"):
		return "tech_support"
	case strings.Contains(command, "show processes"):
		return "processes"
	case strings.Contains(command, "show tcp brief"):
		return "tcp_connections"
	case strings.Contains(command, "show udp brief"):
		return "udp_connections"
	case strings.Contains(command, "show netio clients"):
		return "netio_clients"
	case strings.Contains(command, "show packet-memory clients"):
		return "packet_memory_clients"
	case strings.Contains(command, "show platform security integrity"):
		return "platform_integrity"
	default:
		return "generic"
	}
}

// SupportedCommands returns the list of commands this parser can handle
func (p *IOSXRParser) SupportedCommands() []string {
	return []string{
		"show version",
		"show tech-support",
		"show processes",
		"show tcp brief",
		"show udp brief",
		"show interfaces",
		"show netio clients",
		"show packet-memory clients",
		"show platform security integrity",
		"show install active",
		"show logging",
		"dir /recurse",
		"show users",
		"show route",
	}
}
