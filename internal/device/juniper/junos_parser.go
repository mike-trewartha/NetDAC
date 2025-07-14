package juniper

import (
	"regexp"
	"strings"
)

// JunOSParser implements the CommandParser interface for Juniper Junos devices
type JunOSParser struct {
	supportedCommands map[string]func(string) (interface{}, error)
}

// NewJunOSParser creates a new Junos parser instance
func NewJunOSParser() *JunOSParser {
	parser := &JunOSParser{
		supportedCommands: make(map[string]func(string) (interface{}, error)),
	}

	// Register command parsers
	parser.registerParsers()

	return parser
}

// ParseCommand parses the output of a specific command (implements CommandParser interface)
func (p *JunOSParser) ParseCommand(command, output string) (interface{}, error) {
	// Normalize command for lookup
	normalizedCommand := p.normalizeCommand(command)

	if parseFunc, exists := p.supportedCommands[normalizedCommand]; exists {
		return parseFunc(output)
	}

	// Return raw output if no specific parser exists
	return map[string]interface{}{
		"command": command,
		"output":  output,
		"raw":     true,
	}, nil
}

// GetCommandType returns the type of data this command produces (implements CommandParser interface)
func (p *JunOSParser) GetCommandType(command string) string {
	normalizedCommand := p.normalizeCommand(command)

	// Map commands to their data types
	commandTypes := map[string]string{
		"show version":               "version",
		"show system hostname":       "hostname",
		"show chassis hardware":      "hardware",
		"show system processes":      "processes",
		"show interfaces terse":      "interfaces",
		"show route summary":         "routing",
		"show system users":          "users",
		"show security policies":     "security",
		"show security zones":        "security",
		"show security nat":          "security",
		"show security flow session": "sessions",
		"show system storage":        "storage",
		"show system memory":         "memory",
		"show log messages":          "logs",
		"show configuration":         "configuration",
	}

	if dataType, exists := commandTypes[normalizedCommand]; exists {
		return dataType
	}

	return "raw"
}

// SupportedCommands returns a list of commands that have specific parsers (implements CommandParser interface)
func (p *JunOSParser) SupportedCommands() []string {
	commands := make([]string, 0, len(p.supportedCommands))
	for cmd := range p.supportedCommands {
		commands = append(commands, cmd)
	}
	return commands
}

// registerParsers registers all command-specific parsers
func (p *JunOSParser) registerParsers() {
	// System information parsers
	p.supportedCommands["show version"] = p.parseVersion
	p.supportedCommands["show system hostname"] = p.parseHostname
	p.supportedCommands["show chassis hostname"] = p.parseHostname
	p.supportedCommands["show chassis hardware"] = p.parseChassisHardware
	p.supportedCommands["show system uptime"] = p.parseUptime

	// Process and system parsers
	p.supportedCommands["show system processes"] = p.parseProcesses
	p.supportedCommands["ps aux"] = p.parseProcessesShell
	p.supportedCommands["show system memory"] = p.parseMemory
	p.supportedCommands["show system virtual-memory"] = p.parseVirtualMemory
	p.supportedCommands["show task memory"] = p.parseTaskMemory

	// Network and interface parsers
	p.supportedCommands["show interfaces terse"] = p.parseInterfacesTerse
	p.supportedCommands["show interfaces extensive"] = p.parseInterfacesExtensive
	p.supportedCommands["show system connections"] = p.parseConnections
	p.supportedCommands["netstat -an"] = p.parseNetstat

	// Routing parsers
	p.supportedCommands["show route summary"] = p.parseRouteSummary
	p.supportedCommands["show route extensive"] = p.parseRouteExtensive
	p.supportedCommands["show bgp summary"] = p.parseBGPSummary
	p.supportedCommands["show ospf neighbor"] = p.parseOSPFNeighbor
	p.supportedCommands["show isis adjacency"] = p.parseISISAdjacency

	// Security parsers
	p.supportedCommands["show security policies"] = p.parseSecurityPolicies
	p.supportedCommands["show security zones"] = p.parseSecurityZones
	p.supportedCommands["show security nat"] = p.parseSecurityNAT
	p.supportedCommands["show security flow session"] = p.parseSecuritySessions
	p.supportedCommands["show security ike security-associations"] = p.parseIKESA
	p.supportedCommands["show security ipsec security-associations"] = p.parseIPSecSA

	// User and authentication parsers
	p.supportedCommands["show system users"] = p.parseUsers
	p.supportedCommands["who"] = p.parseWho
	p.supportedCommands["last"] = p.parseLastLogins
	p.supportedCommands["show system login"] = p.parseLoginConfig
	p.supportedCommands["show system authentication-order"] = p.parseAuthOrder

	// Storage and file system parsers
	p.supportedCommands["show system storage"] = p.parseStorage
	p.supportedCommands["df -h"] = p.parseDiskUsage
	p.supportedCommands["mount"] = p.parseMountPoints
	p.supportedCommands["file list"] = p.parseFileList

	// Log parsers
	p.supportedCommands["show log messages"] = p.parseLogMessages
	p.supportedCommands["show security log"] = p.parseSecurityLog
	p.supportedCommands["show log chassisd"] = p.parseChassisLog
	p.supportedCommands["show log dcd"] = p.parseDCDLog
	p.supportedCommands["show log rpd"] = p.parseRPDLog

	// Configuration and software parsers
	p.supportedCommands["show configuration"] = p.parseConfiguration
	p.supportedCommands["show system commit"] = p.parseCommitHistory
	p.supportedCommands["show system software"] = p.parseSoftware
	p.supportedCommands["show system license"] = p.parseLicense

	// Hardware and environment parsers
	p.supportedCommands["show chassis environment"] = p.parseEnvironment
	p.supportedCommands["show system alarms"] = p.parseAlarms
	p.supportedCommands["show chassis fpc pic-status"] = p.parsePICStatus
	p.supportedCommands["show chassis pic"] = p.parsePICInfo

	// MPLS parsers
	p.supportedCommands["show ldp session"] = p.parseLDPSessions
	p.supportedCommands["show mpls lsp"] = p.parseMPLSLSP
	p.supportedCommands["show rsvp session"] = p.parseRSVPSessions

	// Cluster parsers
	p.supportedCommands["show chassis cluster status"] = p.parseClusterStatus
	p.supportedCommands["show chassis cluster interfaces"] = p.parseClusterInterfaces
}

// normalizeCommand normalizes command strings for consistent lookup
func (p *JunOSParser) normalizeCommand(command string) string {
	// Remove common variations and normalize
	normalized := strings.ToLower(strings.TrimSpace(command))

	// Handle piped commands - take the first part
	if strings.Contains(normalized, "|") {
		parts := strings.Split(normalized, "|")
		normalized = strings.TrimSpace(parts[0])
	}

	// Normalize file list commands
	if strings.HasPrefix(normalized, "file list") {
		return "file list"
	}

	// Normalize log commands
	if strings.HasPrefix(normalized, "show log messages") {
		return "show log messages"
	}
	if strings.HasPrefix(normalized, "show log chassisd") {
		return "show log chassisd"
	}
	if strings.HasPrefix(normalized, "show log dcd") {
		return "show log dcd"
	}
	if strings.HasPrefix(normalized, "show log rpd") {
		return "show log rpd"
	}

	// Normalize last command
	if strings.HasPrefix(normalized, "last") {
		return "last"
	}

	return normalized
}

// parseVersion parses "show version" output
func (p *JunOSParser) parseVersion(output string) (interface{}, error) {
	lines := strings.Split(output, "\n")
	version := map[string]interface{}{
		"raw": output,
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(strings.ToLower(line), "junos") {
			version["os_version"] = line
		}
		if strings.Contains(strings.ToLower(line), "hostname") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				version["hostname"] = strings.TrimSpace(parts[1])
			}
		}
		if strings.Contains(strings.ToLower(line), "model") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				version["model"] = strings.TrimSpace(parts[1])
			}
		}
		if strings.Contains(strings.ToLower(line), "uptime") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				version["uptime"] = strings.TrimSpace(parts[1])
			}
		}
	}

	return version, nil
}

// parseHostname parses hostname output
func (p *JunOSParser) parseHostname(output string) (interface{}, error) {
	return map[string]interface{}{
		"hostname": strings.TrimSpace(output),
		"raw":      output,
	}, nil
}

// parseChassisHardware parses "show chassis hardware" output
func (p *JunOSParser) parseChassisHardware(output string) (interface{}, error) {
	lines := strings.Split(output, "\n")
	hardware := make([]map[string]interface{}, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Hardware") || strings.HasPrefix(line, "Item") {
			continue
		}

		// Handle tabular data with potential empty fields
		// Split by multiple spaces and handle empty fields
		parts := strings.Split(line, "  ")
		cleanedParts := make([]string, 0)

		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			if trimmed != "" {
				cleanedParts = append(cleanedParts, trimmed)
			}
		}

		if len(cleanedParts) >= 1 {
			item := map[string]interface{}{
				"item":        cleanedParts[0],
				"version":     "",
				"part_number": "",
				"serial":      "",
				"description": "",
				"raw_line":    line,
			}

			// Map fields based on available data
			if len(cleanedParts) >= 2 {
				// Check if second field looks like a version (REV XX) or serial/description
				if strings.Contains(cleanedParts[1], "REV") {
					item["version"] = cleanedParts[1]
					if len(cleanedParts) >= 3 {
						item["part_number"] = cleanedParts[2]
					}
					if len(cleanedParts) >= 4 {
						item["serial"] = cleanedParts[3]
					}
					if len(cleanedParts) >= 5 {
						item["description"] = strings.Join(cleanedParts[4:], " ")
					}
				} else {
					// Likely a serial number or description
					item["serial"] = cleanedParts[1]
					if len(cleanedParts) >= 3 {
						item["description"] = strings.Join(cleanedParts[2:], " ")
					}
				}
			}

			hardware = append(hardware, item)
		}
	}

	return map[string]interface{}{
		"hardware_items": hardware,
		"raw":            output,
	}, nil
}

// parseUptime parses uptime information
func (p *JunOSParser) parseUptime(output string) (interface{}, error) {
	return map[string]interface{}{
		"uptime": strings.TrimSpace(output),
		"raw":    output,
	}, nil
}

// parseProcesses parses "show system processes" output
func (p *JunOSParser) parseProcesses(output string) (interface{}, error) {
	lines := strings.Split(output, "\n")
	processes := make([]map[string]interface{}, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "PID") || strings.HasPrefix(line, "last") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 6 {
			process := map[string]interface{}{
				"pid":      fields[0],
				"username": fields[1],
				"priority": fields[2],
				"nice":     fields[3],
				"size":     fields[4],
				"res":      fields[5],
				"command":  strings.Join(fields[6:], " "),
				"raw_line": line,
			}
			processes = append(processes, process)
		}
	}

	return map[string]interface{}{
		"processes": processes,
		"count":     len(processes),
		"raw":       output,
	}, nil
}

// parseProcessesShell parses "ps aux" output
func (p *JunOSParser) parseProcessesShell(output string) (interface{}, error) {
	lines := strings.Split(output, "\n")
	processes := make([]map[string]interface{}, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "USER") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 11 {
			process := map[string]interface{}{
				"user":     fields[0],
				"pid":      fields[1],
				"cpu":      fields[2],
				"mem":      fields[3],
				"vsz":      fields[4],
				"rss":      fields[5],
				"tty":      fields[6],
				"stat":     fields[7],
				"start":    fields[8],
				"time":     fields[9],
				"command":  strings.Join(fields[10:], " "),
				"raw_line": line,
			}
			processes = append(processes, process)
		}
	}

	return map[string]interface{}{
		"processes": processes,
		"count":     len(processes),
		"raw":       output,
	}, nil
}

// parseMemory parses memory information
func (p *JunOSParser) parseMemory(output string) (interface{}, error) {
	lines := strings.Split(output, "\n")
	memory := make(map[string]interface{})

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				key := strings.TrimSpace(strings.ToLower(strings.ReplaceAll(parts[0], " ", "_")))
				value := strings.TrimSpace(parts[1])
				memory[key] = value
			}
		}
	}

	memory["raw"] = output
	return memory, nil
}

// parseVirtualMemory parses virtual memory information
func (p *JunOSParser) parseVirtualMemory(output string) (interface{}, error) {
	return p.parseMemory(output) // Similar structure
}

// parseTaskMemory parses task memory information
func (p *JunOSParser) parseTaskMemory(output string) (interface{}, error) {
	lines := strings.Split(output, "\n")
	tasks := make([]map[string]interface{}, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Task") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 4 {
			task := map[string]interface{}{
				"task":     fields[0],
				"memory":   fields[1],
				"percent":  fields[2],
				"time":     fields[3],
				"raw_line": line,
			}
			tasks = append(tasks, task)
		}
	}

	return map[string]interface{}{
		"tasks": tasks,
		"count": len(tasks),
		"raw":   output,
	}, nil
}

// parseInterfacesTerse parses "show interfaces terse" output
func (p *JunOSParser) parseInterfacesTerse(output string) (interface{}, error) {
	lines := strings.Split(output, "\n")
	interfaces := make([]map[string]interface{}, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Interface") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 3 {
			iface := map[string]interface{}{
				"interface":   fields[0],
				"admin_state": fields[1],
				"link_state":  fields[2],
				"description": "",
				"raw_line":    line,
			}

			if len(fields) > 3 {
				iface["description"] = strings.Join(fields[3:], " ")
			}

			interfaces = append(interfaces, iface)
		}
	}

	return map[string]interface{}{
		"interfaces": interfaces,
		"count":      len(interfaces),
		"raw":        output,
	}, nil
}

// parseInterfacesExtensive parses detailed interface information
func (p *JunOSParser) parseInterfacesExtensive(output string) (interface{}, error) {
	// For extensive output, we'll parse it as sections
	sections := strings.Split(output, "\n\n")
	interfaces := make([]map[string]interface{}, 0)

	for _, section := range sections {
		section = strings.TrimSpace(section)
		if section == "" {
			continue
		}

		lines := strings.Split(section, "\n")
		if len(lines) > 0 {
			// First line usually contains interface name
			firstLine := strings.TrimSpace(lines[0])
			if strings.Contains(firstLine, ":") {
				interfaceName := strings.Split(firstLine, ":")[0]

				iface := map[string]interface{}{
					"interface": interfaceName,
					"details":   section,
					"raw":       section,
				}

				interfaces = append(interfaces, iface)
			}
		}
	}

	return map[string]interface{}{
		"interfaces": interfaces,
		"count":      len(interfaces),
		"raw":        output,
	}, nil
}

// parseConnections parses "show system connections" output
func (p *JunOSParser) parseConnections(output string) (interface{}, error) {
	lines := strings.Split(output, "\n")
	connections := make([]map[string]interface{}, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Proto") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 6 {
			conn := map[string]interface{}{
				"protocol":        fields[0],
				"recv_q":          fields[1],
				"send_q":          fields[2],
				"local_address":   fields[3],
				"foreign_address": fields[4],
				"state":           fields[5],
				"raw_line":        line,
			}
			connections = append(connections, conn)
		}
	}

	return map[string]interface{}{
		"connections": connections,
		"count":       len(connections),
		"raw":         output,
	}, nil
}

// parseNetstat parses "netstat -an" output
func (p *JunOSParser) parseNetstat(output string) (interface{}, error) {
	return p.parseConnections(output) // Similar structure
}

// parseRouteSummary parses routing table summary
func (p *JunOSParser) parseRouteSummary(output string) (interface{}, error) {
	lines := strings.Split(output, "\n")
	routes := make(map[string]interface{})

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				key := strings.TrimSpace(strings.ToLower(strings.ReplaceAll(parts[0], " ", "_")))
				value := strings.TrimSpace(parts[1])
				routes[key] = value
			}
		}
	}

	routes["raw"] = output
	return routes, nil
}

// parseRouteExtensive parses detailed routing information
func (p *JunOSParser) parseRouteExtensive(output string) (interface{}, error) {
	return map[string]interface{}{
		"routing_details": output,
		"raw":             output,
	}, nil
}

// parseBGPSummary parses BGP summary information
func (p *JunOSParser) parseBGPSummary(output string) (interface{}, error) {
	lines := strings.Split(output, "\n")
	peers := make([]map[string]interface{}, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Peer") || strings.HasPrefix(line, "Groups") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 6 {
			peer := map[string]interface{}{
				"peer":     fields[0],
				"as":       fields[1],
				"input":    fields[2],
				"output":   fields[3],
				"outq":     fields[4],
				"flaps":    fields[5],
				"last_up":  "",
				"raw_line": line,
			}

			if len(fields) > 6 {
				peer["last_up"] = strings.Join(fields[6:], " ")
			}

			peers = append(peers, peer)
		}
	}

	return map[string]interface{}{
		"bgp_peers": peers,
		"count":     len(peers),
		"raw":       output,
	}, nil
}

// parseOSPFNeighbor parses OSPF neighbor information
func (p *JunOSParser) parseOSPFNeighbor(output string) (interface{}, error) {
	lines := strings.Split(output, "\n")
	neighbors := make([]map[string]interface{}, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Address") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 6 {
			neighbor := map[string]interface{}{
				"address":   fields[0],
				"interface": fields[1],
				"state":     fields[2],
				"id":        fields[3],
				"priority":  fields[4],
				"dead_time": fields[5],
				"raw_line":  line,
			}
			neighbors = append(neighbors, neighbor)
		}
	}

	return map[string]interface{}{
		"ospf_neighbors": neighbors,
		"count":          len(neighbors),
		"raw":            output,
	}, nil
}

// parseISISAdjacency parses ISIS adjacency information
func (p *JunOSParser) parseISISAdjacency(output string) (interface{}, error) {
	lines := strings.Split(output, "\n")
	adjacencies := make([]map[string]interface{}, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Interface") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 4 {
			adj := map[string]interface{}{
				"interface": fields[0],
				"system":    fields[1],
				"level":     fields[2],
				"state":     fields[3],
				"raw_line":  line,
			}
			adjacencies = append(adjacencies, adj)
		}
	}

	return map[string]interface{}{
		"isis_adjacencies": adjacencies,
		"count":            len(adjacencies),
		"raw":              output,
	}, nil
}

// parseSecurityPolicies parses security policies
func (p *JunOSParser) parseSecurityPolicies(output string) (interface{}, error) {
	return map[string]interface{}{
		"security_policies": output,
		"raw":               output,
	}, nil
}

// parseSecurityZones parses security zones
func (p *JunOSParser) parseSecurityZones(output string) (interface{}, error) {
	return map[string]interface{}{
		"security_zones": output,
		"raw":            output,
	}, nil
}

// parseSecurityNAT parses NAT information
func (p *JunOSParser) parseSecurityNAT(output string) (interface{}, error) {
	return map[string]interface{}{
		"nat_rules": output,
		"raw":       output,
	}, nil
}

// parseSecuritySessions parses active security sessions
func (p *JunOSParser) parseSecuritySessions(output string) (interface{}, error) {
	lines := strings.Split(output, "\n")
	sessions := make([]map[string]interface{}, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Session") {
			continue
		}

		// Parse session information - format may vary
		if strings.Contains(line, "->") {
			session := map[string]interface{}{
				"session_info": line,
				"raw_line":     line,
			}
			sessions = append(sessions, session)
		}
	}

	return map[string]interface{}{
		"security_sessions": sessions,
		"count":             len(sessions),
		"raw":               output,
	}, nil
}

// parseIKESA parses IKE security associations
func (p *JunOSParser) parseIKESA(output string) (interface{}, error) {
	return map[string]interface{}{
		"ike_sa": output,
		"raw":    output,
	}, nil
}

// parseIPSecSA parses IPSec security associations
func (p *JunOSParser) parseIPSecSA(output string) (interface{}, error) {
	return map[string]interface{}{
		"ipsec_sa": output,
		"raw":      output,
	}, nil
}

// parseUsers parses current user sessions
func (p *JunOSParser) parseUsers(output string) (interface{}, error) {
	lines := strings.Split(output, "\n")
	users := make([]map[string]interface{}, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 4 {
			user := map[string]interface{}{
				"user":      fields[0],
				"class":     fields[1],
				"type":      fields[2],
				"idle_time": fields[3],
				"raw_line":  line,
			}

			if len(fields) > 4 {
				user["from"] = strings.Join(fields[4:], " ")
			}

			users = append(users, user)
		}
	}

	return map[string]interface{}{
		"users": users,
		"count": len(users),
		"raw":   output,
	}, nil
}

// parseWho parses "who" command output
func (p *JunOSParser) parseWho(output string) (interface{}, error) {
	lines := strings.Split(output, "\n")
	users := make([]map[string]interface{}, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 3 {
			user := map[string]interface{}{
				"user":     fields[0],
				"tty":      fields[1],
				"login":    strings.Join(fields[2:], " "),
				"raw_line": line,
			}
			users = append(users, user)
		}
	}

	return map[string]interface{}{
		"current_users": users,
		"count":         len(users),
		"raw":           output,
	}, nil
}

// parseLastLogins parses login history
func (p *JunOSParser) parseLastLogins(output string) (interface{}, error) {
	lines := strings.Split(output, "\n")
	logins := make([]map[string]interface{}, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "wtmp") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 4 {
			login := map[string]interface{}{
				"user":     fields[0],
				"tty":      fields[1],
				"host":     fields[2],
				"date":     strings.Join(fields[3:], " "),
				"raw_line": line,
			}
			logins = append(logins, login)
		}
	}

	return map[string]interface{}{
		"login_history": logins,
		"count":         len(logins),
		"raw":           output,
	}, nil
}

// parseLoginConfig parses login configuration
func (p *JunOSParser) parseLoginConfig(output string) (interface{}, error) {
	return map[string]interface{}{
		"login_config": output,
		"raw":          output,
	}, nil
}

// parseAuthOrder parses authentication order
func (p *JunOSParser) parseAuthOrder(output string) (interface{}, error) {
	return map[string]interface{}{
		"auth_order": strings.TrimSpace(output),
		"raw":        output,
	}, nil
}

// parseStorage parses storage information
func (p *JunOSParser) parseStorage(output string) (interface{}, error) {
	lines := strings.Split(output, "\n")
	filesystems := make([]map[string]interface{}, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Filesystem") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 6 {
			fs := map[string]interface{}{
				"filesystem": fields[0],
				"size":       fields[1],
				"used":       fields[2],
				"available":  fields[3],
				"percent":    fields[4],
				"mounted":    fields[5],
				"raw_line":   line,
			}
			filesystems = append(filesystems, fs)
		}
	}

	return map[string]interface{}{
		"filesystems": filesystems,
		"count":       len(filesystems),
		"raw":         output,
	}, nil
}

// parseDiskUsage parses "df -h" output
func (p *JunOSParser) parseDiskUsage(output string) (interface{}, error) {
	return p.parseStorage(output) // Similar structure
}

// parseMountPoints parses "mount" output
func (p *JunOSParser) parseMountPoints(output string) (interface{}, error) {
	lines := strings.Split(output, "\n")
	mounts := make([]map[string]interface{}, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		mount := map[string]interface{}{
			"mount_info": line,
			"raw_line":   line,
		}
		mounts = append(mounts, mount)
	}

	return map[string]interface{}{
		"mount_points": mounts,
		"count":        len(mounts),
		"raw":          output,
	}, nil
}

// parseFileList parses file listing output
func (p *JunOSParser) parseFileList(output string) (interface{}, error) {
	lines := strings.Split(output, "\n")
	files := make([]map[string]interface{}, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		file := map[string]interface{}{
			"file_info": line,
			"raw_line":  line,
		}
		files = append(files, file)
	}

	return map[string]interface{}{
		"files": files,
		"count": len(files),
		"raw":   output,
	}, nil
}

// parseLogMessages parses log messages
func (p *JunOSParser) parseLogMessages(output string) (interface{}, error) {
	lines := strings.Split(output, "\n")
	messages := make([]map[string]interface{}, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		message := map[string]interface{}{
			"log_entry": line,
			"raw_line":  line,
		}

		// Try to extract timestamp if present
		if len(line) > 15 {
			timestamp := line[:15]
			if matched, _ := regexp.MatchString(`\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}`, timestamp); matched {
				message["timestamp"] = timestamp
				message["message"] = strings.TrimSpace(line[15:])
			}
		}

		messages = append(messages, message)
	}

	return map[string]interface{}{
		"log_messages": messages,
		"count":        len(messages),
		"raw":          output,
	}, nil
}

// parseSecurityLog parses security log
func (p *JunOSParser) parseSecurityLog(output string) (interface{}, error) {
	return p.parseLogMessages(output) // Similar structure
}

// parseChassisLog parses chassis daemon log
func (p *JunOSParser) parseChassisLog(output string) (interface{}, error) {
	return p.parseLogMessages(output) // Similar structure
}

// parseDCDLog parses DCD log
func (p *JunOSParser) parseDCDLog(output string) (interface{}, error) {
	return p.parseLogMessages(output) // Similar structure
}

// parseRPDLog parses RPD log
func (p *JunOSParser) parseRPDLog(output string) (interface{}, error) {
	return p.parseLogMessages(output) // Similar structure
}

// parseConfiguration parses configuration output
func (p *JunOSParser) parseConfiguration(output string) (interface{}, error) {
	return map[string]interface{}{
		"configuration": output,
		"raw":           output,
	}, nil
}

// parseCommitHistory parses commit history
func (p *JunOSParser) parseCommitHistory(output string) (interface{}, error) {
	lines := strings.Split(output, "\n")
	commits := make([]map[string]interface{}, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		commit := map[string]interface{}{
			"commit_info": line,
			"raw_line":    line,
		}
		commits = append(commits, commit)
	}

	return map[string]interface{}{
		"commit_history": commits,
		"count":          len(commits),
		"raw":            output,
	}, nil
}

// parseSoftware parses software information
func (p *JunOSParser) parseSoftware(output string) (interface{}, error) {
	return map[string]interface{}{
		"software_info": output,
		"raw":           output,
	}, nil
}

// parseLicense parses license information
func (p *JunOSParser) parseLicense(output string) (interface{}, error) {
	return map[string]interface{}{
		"license_info": output,
		"raw":          output,
	}, nil
}

// parseEnvironment parses environmental status
func (p *JunOSParser) parseEnvironment(output string) (interface{}, error) {
	return map[string]interface{}{
		"environment": output,
		"raw":         output,
	}, nil
}

// parseAlarms parses system alarms
func (p *JunOSParser) parseAlarms(output string) (interface{}, error) {
	lines := strings.Split(output, "\n")
	alarms := make([]map[string]interface{}, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "No alarms") {
			continue
		}

		alarm := map[string]interface{}{
			"alarm_info": line,
			"raw_line":   line,
		}
		alarms = append(alarms, alarm)
	}

	return map[string]interface{}{
		"alarms": alarms,
		"count":  len(alarms),
		"raw":    output,
	}, nil
}

// parsePICStatus parses PIC status information
func (p *JunOSParser) parsePICStatus(output string) (interface{}, error) {
	return map[string]interface{}{
		"pic_status": output,
		"raw":        output,
	}, nil
}

// parsePICInfo parses PIC information
func (p *JunOSParser) parsePICInfo(output string) (interface{}, error) {
	return map[string]interface{}{
		"pic_info": output,
		"raw":      output,
	}, nil
}

// parseLDPSessions parses LDP sessions
func (p *JunOSParser) parseLDPSessions(output string) (interface{}, error) {
	return map[string]interface{}{
		"ldp_sessions": output,
		"raw":          output,
	}, nil
}

// parseMPLSLSP parses MPLS LSPs
func (p *JunOSParser) parseMPLSLSP(output string) (interface{}, error) {
	return map[string]interface{}{
		"mpls_lsp": output,
		"raw":      output,
	}, nil
}

// parseRSVPSessions parses RSVP sessions
func (p *JunOSParser) parseRSVPSessions(output string) (interface{}, error) {
	return map[string]interface{}{
		"rsvp_sessions": output,
		"raw":           output,
	}, nil
}

// parseClusterStatus parses chassis cluster status
func (p *JunOSParser) parseClusterStatus(output string) (interface{}, error) {
	return map[string]interface{}{
		"cluster_status": output,
		"raw":            output,
	}, nil
}

// parseClusterInterfaces parses cluster interfaces
func (p *JunOSParser) parseClusterInterfaces(output string) (interface{}, error) {
	return map[string]interface{}{
		"cluster_interfaces": output,
		"raw":                output,
	}, nil
}
