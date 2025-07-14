package fortinet

import (
	"regexp"
	"strings"
	"time"

	"netdac/internal/core"
)

// FortiOSParser implements parsing logic for FortiOS command output
// Based on standard FortiOS CLI output formats from Fortinet FortiGate devices
type FortiOSParser struct {
	// No additional fields needed for stateless parsing
}

// NewFortiOSParser creates a new FortiOS parser instance
func NewFortiOSParser() *FortiOSParser {
	return &FortiOSParser{}
}

// ParseCommand parses FortiOS command output into structured data
func (p *FortiOSParser) ParseCommand(parserType string, output string) (interface{}, error) {
	switch parserType {
	case "system_status":
		return p.ParseSystemStatus(output)
	case "system_status_detailed":
		return p.ParseSystemStatusDetailed(output)
	case "interfaces":
		return p.ParseInterfaces(output)
	case "routes":
		return p.ParseRoutes(output)
	case "sessions":
		return p.ParseSessions(output)
	case "performance":
		return p.ParsePerformance(output)
	case "arp":
		return p.ParseARP(output)
	case "firewall_policies":
		return p.ParseFirewallPolicies(output)
	case "vpn_tunnels":
		return p.ParseVPNTunnels(output)
	case "ha_status":
		return p.ParseHAStatus(output)
	case "processes":
		return p.ParseProcesses(output)
	case "users":
		return p.ParseUsers(output)
	case "system_logs":
		return p.ParseSystemLogs(output)
	case "memory_logs":
		return p.ParseMemoryLogs(output)
	case "event_logs":
		return p.ParseEventLogs(output)
	case "hardware_info":
		return p.ParseHardwareInfo(output)
	case "detailed_sessions":
		return p.ParseDetailedSessions(output)
	case "physical_interfaces":
		return p.ParsePhysicalInterfaces(output)
	case "address_objects":
		return p.ParseAddressObjects(output)
	case "service_objects":
		return p.ParseServiceObjects(output)
	case "ssl_vpn_sessions":
		return p.ParseSSLVPNSessions(output)
	case "admin_users":
		return p.ParseAdminUsers(output)
	case "snmp_config":
		return p.ParseSNMPConfig(output)
	case "ntp_status":
		return p.ParseNTPStatus(output)
	case "debug_reset":
		return p.ParseDebugReset(output)
	case "dns_config":
		return p.ParseDNSConfig(output)
	case "fortianalyzer_config":
		return p.ParseFortiAnalyzerConfig(output)
	case "cpu_info":
		return p.ParseCPUInfo(output)
	case "memory_info":
		return p.ParseMemoryInfo(output)
	case "global_config":
		return p.ParseGlobalConfig(output)
	// Enhanced forensic parsing capabilities
	case "system_integrity":
		return p.ParseSystemIntegrity(output)
	case "system_checksum":
		return p.ParseSystemChecksum(output)
	case "fortiguard_status":
		return p.ParseFortiGuardStatus(output)
	case "process_summary":
		return p.ParseProcessSummary(output)
	case "detailed_processes":
		return p.ParseDetailedProcesses(output)
	case "config_backup":
		return p.ParseConfigBackup(output)
	case "flash_listing":
		return p.ParseFlashListing(output)
	case "boot_config":
		return p.ParseBootConfig(output)
	case "root_filesystem":
		return p.ParseRootFilesystem(output)
	case "disk_logs":
		return p.ParseDiskLogs(output)
	case "log_test":
		return p.ParseLogTest(output)
	case "session_statistics":
		return p.ParseSessionStatistics(output)
	case "netlink_interfaces":
		return p.ParseNetlinkInterfaces(output)
	case "arp_detailed":
		return p.ParseARPDetailed(output)
	case "firewall_policies_detailed":
		return p.ParseFirewallPoliciesDetailed(output)
	case "shaping_policies":
		return p.ParseShapingPolicies(output)
	case "snat_policies":
		return p.ParseSNATPolicies(output)
	case "vpn_tunnels_detailed":
		return p.ParseVPNTunnelsDetailed(output)
	case "ipsec_details":
		return p.ParseIPSecDetails(output)
	case "local_certificates":
		return p.ParseLocalCertificates(output)
	case "users_detailed":
		return p.ParseUsersDetailed(output)
	case "auth_servers":
		return p.ParseAuthServers(output)
	case "user_groups":
		return p.ParseUserGroups(output)
	case "radius_config":
		return p.ParseRadiusConfig(output)
	case "ntp_config":
		return p.ParseNTPConfig(output)
	case "static_routes":
		return p.ParseStaticRoutes(output)
	case "ospf_config":
		return p.ParseOSPFConfig(output)
	case "bgp_config":
		return p.ParseBGPConfig(output)
	case "app_signatures":
		return p.ParseAppSignatures(output)
	case "ips_signatures":
		return p.ParseIPSSignatures(output)
	case "antivirus_profiles":
		return p.ParseAntivirusProfiles(output)
	default:
		return map[string]interface{}{
			"raw_output": output,
			"parser":     parserType,
		}, nil
	}
}

// ParseSystemStatus parses "get system status" output
func (p *FortiOSParser) ParseSystemStatus(output string) (*core.DeviceInfo, error) {
	deviceInfo := &core.DeviceInfo{
		Vendor: "Fortinet",
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse hostname
		if strings.Contains(line, "Hostname:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				deviceInfo.Hostname = strings.TrimSpace(parts[1])
			}
		}
		// Parse version
		if strings.Contains(line, "Version:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				deviceInfo.Version = strings.TrimSpace(parts[1])
			}
		}
		// Parse model
		if strings.Contains(line, "Platform Type:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				deviceInfo.Model = strings.TrimSpace(parts[1])
			}
		}
		// Parse serial number
		if strings.Contains(line, "Serial Number:") || strings.Contains(line, "Serial-Number:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				deviceInfo.SerialNumber = strings.TrimSpace(parts[1])
			}
		}
		// Parse uptime
		if strings.Contains(line, "Uptime:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				deviceInfo.Uptime = strings.TrimSpace(strings.Join(parts[1:], ":"))
			}
		}
	}

	return deviceInfo, nil
}

// ParseInterfaces parses "get system interface" output
func (p *FortiOSParser) ParseInterfaces(output string) ([]core.Interface, error) {
	var interfaces []core.Interface

	// FortiOS interface output typically shows interface configuration
	lines := strings.Split(output, "\n")
	var currentInterface *core.Interface

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Look for interface name lines (usually start with "== [")
		if strings.Contains(line, "== [") && strings.Contains(line, "]") {
			if currentInterface != nil {
				interfaces = append(interfaces, *currentInterface)
			}

			// Extract interface name
			re := regexp.MustCompile(`== \[(.+?)\]`)
			matches := re.FindStringSubmatch(line)
			if len(matches) > 1 {
				currentInterface = &core.Interface{
					Name:   strings.TrimSpace(matches[1]),
					Status: "unknown",
				}
			}
		} else if currentInterface != nil {
			// Parse interface details
			if strings.Contains(line, "ip:") {
				parts := strings.Fields(line)
				for i, part := range parts {
					if part == "ip:" && i+1 < len(parts) {
						currentInterface.IPAddress = parts[i+1]
						break
					}
				}
			}
			if strings.Contains(line, "status:") {
				parts := strings.Fields(line)
				for i, part := range parts {
					if part == "status:" && i+1 < len(parts) {
						currentInterface.Status = parts[i+1]
						break
					}
				}
			}
		}
	}

	// Add the last interface
	if currentInterface != nil {
		interfaces = append(interfaces, *currentInterface)
	}

	return interfaces, nil
}

// ParseRoutes parses "get router info routing-table all" output
func (p *FortiOSParser) ParseRoutes(output string) ([]core.Route, error) {
	var routes []core.Route

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Codes:") || strings.HasPrefix(line, "Gateway") {
			continue
		}

		// FortiOS routing table format: destination/mask via gateway dev interface
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			route := core.Route{
				Destination: fields[0],
				Protocol:    "unknown",
			}

			// Parse gateway and interface
			for i, field := range fields {
				if field == "via" && i+1 < len(fields) {
					route.Gateway = fields[i+1]
				}
				if field == "dev" && i+1 < len(fields) {
					route.Interface = fields[i+1]
				}
			}

			routes = append(routes, route)
		}
	}

	return routes, nil
}

// ParseSessions parses "get system session list" output
func (p *FortiOSParser) ParseSessions(output string) ([]core.Session, error) {
	var sessions []core.Session

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "SESSION") || strings.HasPrefix(line, "PROTO") {
			continue
		}

		// Parse session information - format varies by FortiOS version
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			session := core.Session{
				Protocol: fields[0],
				User:     "system", // FortiOS sessions are typically system-level
			}

			// Try to extract source and destination info
			if len(fields) >= 5 {
				session.SourceIP = fields[1]
				session.Location = fields[2]
			}

			sessions = append(sessions, session)
		}
	}

	return sessions, nil
}

// ParsePerformance parses "get system performance status" output
func (p *FortiOSParser) ParsePerformance(output string) (*core.SystemInfo, error) {
	systemInfo := &core.SystemInfo{}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse CPU usage
		if strings.Contains(line, "CPU") && strings.Contains(line, "%") {
			re := regexp.MustCompile(`(\d+)%`)
			matches := re.FindStringSubmatch(line)
			if len(matches) > 1 {
				systemInfo.CPUUsage = matches[1] + "%"
			}
		}

		// Parse memory usage
		if strings.Contains(line, "Memory") || strings.Contains(line, "RAM") {
			re := regexp.MustCompile(`(\d+)%`)
			matches := re.FindStringSubmatch(line)
			if len(matches) > 1 {
				systemInfo.MemoryUsage = matches[1] + "%"
			}
		}
	}

	return systemInfo, nil
}

// ParseProcesses parses "diagnose sys top 1" output
func (p *FortiOSParser) ParseProcesses(output string) ([]core.Process, error) {
	var processes []core.Process

	lines := strings.Split(output, "\n")
	inProcessList := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Look for the process list header
		if strings.Contains(line, "PID") && strings.Contains(line, "CPU") {
			inProcessList = true
			continue
		}

		if inProcessList {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				process := core.Process{
					PID:  fields[0],
					Name: fields[len(fields)-1], // Process name is usually last
				}

				// Parse CPU if available
				if len(fields) >= 4 {
					process.CPU = fields[2]
				}

				processes = append(processes, process)
			}
		}
	}

	return processes, nil
}

// ParseARP parses "get system arp" output
func (p *FortiOSParser) ParseARP(output string) ([]map[string]interface{}, error) {
	var arpEntries []map[string]interface{}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Address") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 3 {
			entry := map[string]interface{}{
				"ip_address":  fields[0],
				"mac_address": fields[1],
				"interface":   fields[2],
			}
			arpEntries = append(arpEntries, entry)
		}
	}

	return arpEntries, nil
}

// ParseFirewallPolicies parses "get firewall policy" output
func (p *FortiOSParser) ParseFirewallPolicies(output string) ([]core.FirewallRule, error) {
	var policies []core.FirewallRule

	lines := strings.Split(output, "\n")
	var currentPolicy *core.FirewallRule

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Look for policy ID lines
		if strings.HasPrefix(line, "edit ") {
			if currentPolicy != nil {
				policies = append(policies, *currentPolicy)
			}

			policyID := strings.TrimPrefix(line, "edit ")
			currentPolicy = &core.FirewallRule{
				ID:      policyID,
				Enabled: true,
				Action:  "permit", // Default for FortiGate
			}
		} else if currentPolicy != nil {
			// Parse policy attributes
			if strings.Contains(line, "set srcintf") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					currentPolicy.Interface = strings.Trim(parts[2], "\"")
				}
			}
			if strings.Contains(line, "set srcaddr") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					currentPolicy.Source = strings.Trim(parts[2], "\"")
				}
			}
			if strings.Contains(line, "set dstaddr") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					currentPolicy.Destination = strings.Trim(parts[2], "\"")
				}
			}
			if strings.Contains(line, "set service") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					currentPolicy.Service = strings.Trim(parts[2], "\"")
				}
			}
			if strings.Contains(line, "set action") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					currentPolicy.Action = strings.Trim(parts[2], "\"")
				}
			}
		}
	}

	// Add the last policy
	if currentPolicy != nil {
		policies = append(policies, *currentPolicy)
	}

	return policies, nil
}

// ParseVPNTunnels parses "get vpn ipsec tunnel summary" output
func (p *FortiOSParser) ParseVPNTunnels(output string) ([]core.VPNSession, error) {
	var tunnels []core.VPNSession

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Name") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 3 {
			tunnel := core.VPNSession{
				Tunnel:   fields[0],
				Protocol: "IPSec",
			}

			if len(fields) >= 4 {
				tunnel.ClientIP = fields[2]
			}

			tunnels = append(tunnels, tunnel)
		}
	}

	return tunnels, nil
}

// ParseHAStatus parses "get system ha status" output
func (p *FortiOSParser) ParseHAStatus(output string) (map[string]interface{}, error) {
	haStatus := make(map[string]interface{})

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse HA information
		if strings.Contains(line, "Model:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				haStatus["model"] = strings.TrimSpace(parts[1])
			}
		}
		if strings.Contains(line, "Mode:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				haStatus["mode"] = strings.TrimSpace(parts[1])
			}
		}
		if strings.Contains(line, "Group:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				haStatus["group"] = strings.TrimSpace(parts[1])
			}
		}
	}

	return haStatus, nil
}

// ParseUsers parses "get user info" output
func (p *FortiOSParser) ParseUsers(output string) ([]map[string]interface{}, error) {
	var users []map[string]interface{}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse user information
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			user := map[string]interface{}{
				"username": fields[0],
				"status":   fields[1],
			}
			users = append(users, user)
		}
	}

	return users, nil
}

// ParseSystemLogs parses "execute log display" output
func (p *FortiOSParser) ParseSystemLogs(output string) ([]core.LogEntry, error) {
	var logs []core.LogEntry

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// FortiOS log format is typically structured
		if strings.Contains(line, "date=") {
			log := core.LogEntry{
				Message:   line,
				Severity:  "info",
				Facility:  "fortios",
				Timestamp: time.Now(),
				RawLine:   line,
			}

			// Extract log severity if present
			if strings.Contains(line, "level=") {
				re := regexp.MustCompile(`level=([^\s]+)`)
				matches := re.FindStringSubmatch(line)
				if len(matches) > 1 {
					log.Severity = matches[1]
				}
			}

			logs = append(logs, log)
		}
	}

	return logs, nil
}

// ParseMemoryLogs parses "get log memory" output
func (p *FortiOSParser) ParseMemoryLogs(output string) ([]core.LogEntry, error) {
	return p.ParseSystemLogs(output) // Similar format to system logs
}

// ParseEventLogs parses "get log eventtime" output
func (p *FortiOSParser) ParseEventLogs(output string) ([]core.LogEntry, error) {
	return p.ParseSystemLogs(output) // Similar format to system logs
}

// ParseHardwareInfo parses "diagnose hardware sysinfo shm" output
func (p *FortiOSParser) ParseHardwareInfo(output string) (map[string]interface{}, error) {
	hardwareInfo := make(map[string]interface{})

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse hardware information
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				hardwareInfo[key] = value
			}
		}
	}

	return hardwareInfo, nil
}

// ParseDetailedSessions parses "diagnose sys session list" output
func (p *FortiOSParser) ParseDetailedSessions(output string) ([]core.Session, error) {
	return p.ParseSessions(output) // Similar format but more detailed
}

// ParsePhysicalInterfaces parses "get system interface physical" output
func (p *FortiOSParser) ParsePhysicalInterfaces(output string) ([]core.Interface, error) {
	return p.ParseInterfaces(output) // Similar format to regular interfaces
}

// ParseAddressObjects parses "get firewall address" output
func (p *FortiOSParser) ParseAddressObjects(output string) ([]map[string]interface{}, error) {
	var addresses []map[string]interface{}

	lines := strings.Split(output, "\n")
	var currentAddress map[string]interface{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "edit ") {
			if currentAddress != nil {
				addresses = append(addresses, currentAddress)
			}

			addressName := strings.TrimPrefix(line, "edit ")
			currentAddress = map[string]interface{}{
				"name": strings.Trim(addressName, "\""),
			}
		} else if currentAddress != nil {
			if strings.Contains(line, "set subnet") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					currentAddress["subnet"] = parts[2]
				}
			}
			if strings.Contains(line, "set type") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					currentAddress["type"] = parts[2]
				}
			}
		}
	}

	if currentAddress != nil {
		addresses = append(addresses, currentAddress)
	}

	return addresses, nil
}

// ParseServiceObjects parses "get firewall service custom" output
func (p *FortiOSParser) ParseServiceObjects(output string) ([]map[string]interface{}, error) {
	var services []map[string]interface{}

	lines := strings.Split(output, "\n")
	var currentService map[string]interface{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "edit ") {
			if currentService != nil {
				services = append(services, currentService)
			}

			serviceName := strings.TrimPrefix(line, "edit ")
			currentService = map[string]interface{}{
				"name": strings.Trim(serviceName, "\""),
			}
		} else if currentService != nil {
			if strings.Contains(line, "set tcp-portrange") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					currentService["tcp_ports"] = parts[2]
				}
			}
			if strings.Contains(line, "set udp-portrange") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					currentService["udp_ports"] = parts[2]
				}
			}
		}
	}

	if currentService != nil {
		services = append(services, currentService)
	}

	return services, nil
}

// ParseSSLVPNSessions parses "get vpn ssl monitor" output
func (p *FortiOSParser) ParseSSLVPNSessions(output string) ([]core.VPNSession, error) {
	var sessions []core.VPNSession

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 3 {
			session := core.VPNSession{
				User:     fields[0],
				ClientIP: fields[1],
				Protocol: "SSL-VPN",
			}
			sessions = append(sessions, session)
		}
	}

	return sessions, nil
}

// ParseAdminUsers parses "get system admin" output
func (p *FortiOSParser) ParseAdminUsers(output string) ([]map[string]interface{}, error) {
	var admins []map[string]interface{}

	lines := strings.Split(output, "\n")
	var currentAdmin map[string]interface{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "edit ") {
			if currentAdmin != nil {
				admins = append(admins, currentAdmin)
			}

			adminName := strings.TrimPrefix(line, "edit ")
			currentAdmin = map[string]interface{}{
				"name": strings.Trim(adminName, "\""),
			}
		} else if currentAdmin != nil {
			if strings.Contains(line, "set accprofile") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					currentAdmin["profile"] = strings.Trim(parts[2], "\"")
				}
			}
		}
	}

	if currentAdmin != nil {
		admins = append(admins, currentAdmin)
	}

	return admins, nil
}

// ParseSNMPConfig parses "get system snmp community" output
func (p *FortiOSParser) ParseSNMPConfig(output string) (map[string]interface{}, error) {
	snmpConfig := make(map[string]interface{})

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.Contains(line, "set name") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				snmpConfig["community"] = strings.Trim(parts[2], "\"")
			}
		}
	}

	return snmpConfig, nil
}

// ParseNTPStatus parses "diagnose sys ntp status" output
func (p *FortiOSParser) ParseNTPStatus(output string) (map[string]interface{}, error) {
	ntpStatus := make(map[string]interface{})

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.Contains(line, "synchronized:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				ntpStatus["synchronized"] = strings.TrimSpace(parts[1])
			}
		}
	}

	return ntpStatus, nil
}

// ParseDebugReset parses "diagnose debug reset" output
func (p *FortiOSParser) ParseDebugReset(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"status": "debug reset executed",
		"output": output,
	}, nil
}

// ParseDNSConfig parses "get system dns" output
func (p *FortiOSParser) ParseDNSConfig(output string) (map[string]interface{}, error) {
	dnsConfig := make(map[string]interface{})

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.Contains(line, "set primary") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				dnsConfig["primary"] = parts[2]
			}
		}
		if strings.Contains(line, "set secondary") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				dnsConfig["secondary"] = parts[2]
			}
		}
	}

	return dnsConfig, nil
}

// ParseFortiAnalyzerConfig parses "get log fortianalyzer setting" output
func (p *FortiOSParser) ParseFortiAnalyzerConfig(output string) (map[string]interface{}, error) {
	config := make(map[string]interface{})

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.Contains(line, "set status") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				config["status"] = parts[2]
			}
		}
		if strings.Contains(line, "set server") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				config["server"] = strings.Trim(parts[2], "\"")
			}
		}
	}

	return config, nil
}

// ParseCPUInfo parses "diagnose sys cpuinfo" output
func (p *FortiOSParser) ParseCPUInfo(output string) (map[string]interface{}, error) {
	cpuInfo := make(map[string]interface{})

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				cpuInfo[key] = value
			}
		}
	}

	return cpuInfo, nil
}

// ParseMemoryInfo parses "diagnose hardware sysinfo memory" output
func (p *FortiOSParser) ParseMemoryInfo(output string) (map[string]interface{}, error) {
	memoryInfo := make(map[string]interface{})

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse memory statistics
		if strings.Contains(line, "MemTotal:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				memoryInfo["total"] = parts[1]
			}
		}
		if strings.Contains(line, "MemFree:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				memoryInfo["free"] = parts[1]
			}
		}
		if strings.Contains(line, "MemAvailable:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				memoryInfo["available"] = parts[1]
			}
		}
	}

	return memoryInfo, nil
}

// ParseGlobalConfig parses "get system global" output
func (p *FortiOSParser) ParseGlobalConfig(output string) (map[string]interface{}, error) {
	globalConfig := make(map[string]interface{})

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "set ") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				key := parts[1]
				value := strings.Join(parts[2:], " ")
				globalConfig[key] = strings.Trim(value, "\"")
			}
		}
	}

	return globalConfig, nil
}

// Enhanced forensic parsers for comprehensive FortiGate analysis

// ParseSystemStatusDetailed parses detailed system status
func (p *FortiOSParser) ParseSystemStatusDetailed(output string) (*core.DeviceInfo, error) {
	// Reuse existing system status parser
	return p.ParseSystemStatus(output)
}

// ParseSystemIntegrity parses system integrity scan results
func (p *FortiOSParser) ParseSystemIntegrity(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output": output,
		"timestamp":  time.Now().Format(time.RFC3339),
		"type":       "system_integrity",
	}, nil
}

// ParseSystemChecksum parses system file checksums
func (p *FortiOSParser) ParseSystemChecksum(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output": output,
		"timestamp":  time.Now().Format(time.RFC3339),
		"type":       "system_checksum",
	}, nil
}

// ParseFortiGuardStatus parses FortiGuard service status
func (p *FortiOSParser) ParseFortiGuardStatus(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output": output,
		"timestamp":  time.Now().Format(time.RFC3339),
		"type":       "fortiguard_status",
	}, nil
}

// ParseProcessSummary parses process summary
func (p *FortiOSParser) ParseProcessSummary(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output": output,
		"timestamp":  time.Now().Format(time.RFC3339),
		"type":       "process_summary",
	}, nil
}

// ParseDetailedProcesses parses detailed process list
func (p *FortiOSParser) ParseDetailedProcesses(output string) ([]core.Process, error) {
	// Reuse existing process parser
	return p.ParseProcesses(output)
}

// ParseConfigBackup parses configuration backup
func (p *FortiOSParser) ParseConfigBackup(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output": output,
		"timestamp":  time.Now().Format(time.RFC3339),
		"type":       "config_backup",
	}, nil
}

// ParseFlashListing parses flash file system listing
func (p *FortiOSParser) ParseFlashListing(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output": output,
		"timestamp":  time.Now().Format(time.RFC3339),
		"type":       "flash_listing",
	}, nil
}

// ParseBootConfig parses boot configuration
func (p *FortiOSParser) ParseBootConfig(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output": output,
		"timestamp":  time.Now().Format(time.RFC3339),
		"type":       "boot_config",
	}, nil
}

// ParseRootFilesystem parses root filesystem listing
func (p *FortiOSParser) ParseRootFilesystem(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output": output,
		"timestamp":  time.Now().Format(time.RFC3339),
		"type":       "root_filesystem",
	}, nil
}

// ParseDiskLogs parses disk log entries
func (p *FortiOSParser) ParseDiskLogs(output string) ([]core.LogEntry, error) {
	var logs []core.LogEntry
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		log := core.LogEntry{
			Timestamp: time.Now(),
			Severity:  "info",
			Message:   line,
			Category:  "disk",
		}
		logs = append(logs, log)
	}

	return logs, nil
}

// ParseLogTest parses log system test
func (p *FortiOSParser) ParseLogTest(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output": output,
		"timestamp":  time.Now().Format(time.RFC3339),
		"type":       "log_test",
	}, nil
}

// ParseSessionStatistics parses session statistics
func (p *FortiOSParser) ParseSessionStatistics(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output": output,
		"timestamp":  time.Now().Format(time.RFC3339),
		"type":       "session_statistics",
	}, nil
}

// ParseNetlinkInterfaces parses netlink interface details
func (p *FortiOSParser) ParseNetlinkInterfaces(output string) ([]core.Interface, error) {
	// Reuse existing interface parser
	return p.ParseInterfaces(output)
}

// ParseARPDetailed parses detailed ARP table
func (p *FortiOSParser) ParseARPDetailed(output string) ([]map[string]interface{}, error) {
	// Reuse existing ARP parser
	return p.ParseARP(output)
}

// ParseFirewallPoliciesDetailed parses detailed firewall policies
func (p *FortiOSParser) ParseFirewallPoliciesDetailed(output string) ([]core.FirewallRule, error) {
	// Reuse existing firewall policy parser
	return p.ParseFirewallPolicies(output)
}

// ParseShapingPolicies parses traffic shaping policies
func (p *FortiOSParser) ParseShapingPolicies(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output": output,
		"timestamp":  time.Now().Format(time.RFC3339),
		"type":       "shaping_policies",
	}, nil
}

// ParseSNATPolicies parses SNAT policies
func (p *FortiOSParser) ParseSNATPolicies(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output": output,
		"timestamp":  time.Now().Format(time.RFC3339),
		"type":       "snat_policies",
	}, nil
}

// ParseVPNTunnelsDetailed parses detailed VPN tunnels
func (p *FortiOSParser) ParseVPNTunnelsDetailed(output string) ([]core.VPNSession, error) {
	// Reuse existing VPN tunnel parser
	return p.ParseVPNTunnels(output)
}

// ParseIPSecDetails parses IPSec tunnel details
func (p *FortiOSParser) ParseIPSecDetails(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output": output,
		"timestamp":  time.Now().Format(time.RFC3339),
		"type":       "ipsec_details",
	}, nil
}

// ParseLocalCertificates parses local certificates
func (p *FortiOSParser) ParseLocalCertificates(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output": output,
		"timestamp":  time.Now().Format(time.RFC3339),
		"type":       "local_certificates",
	}, nil
}

// ParseUsersDetailed parses detailed user information
func (p *FortiOSParser) ParseUsersDetailed(output string) ([]map[string]interface{}, error) {
	// Reuse existing users parser
	return p.ParseUsers(output)
}

// ParseAuthServers parses authentication server test
func (p *FortiOSParser) ParseAuthServers(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output": output,
		"timestamp":  time.Now().Format(time.RFC3339),
		"type":       "auth_servers",
	}, nil
}

// ParseUserGroups parses user groups
func (p *FortiOSParser) ParseUserGroups(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output": output,
		"timestamp":  time.Now().Format(time.RFC3339),
		"type":       "user_groups",
	}, nil
}

// ParseRadiusConfig parses RADIUS configuration
func (p *FortiOSParser) ParseRadiusConfig(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output": output,
		"timestamp":  time.Now().Format(time.RFC3339),
		"type":       "radius_config",
	}, nil
}

// ParseNTPConfig parses NTP configuration
func (p *FortiOSParser) ParseNTPConfig(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output": output,
		"timestamp":  time.Now().Format(time.RFC3339),
		"type":       "ntp_config",
	}, nil
}

// ParseStaticRoutes parses static routes
func (p *FortiOSParser) ParseStaticRoutes(output string) ([]core.Route, error) {
	// Reuse existing routes parser
	return p.ParseRoutes(output)
}

// ParseOSPFConfig parses OSPF configuration
func (p *FortiOSParser) ParseOSPFConfig(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output": output,
		"timestamp":  time.Now().Format(time.RFC3339),
		"type":       "ospf_config",
	}, nil
}

// ParseBGPConfig parses BGP configuration
func (p *FortiOSParser) ParseBGPConfig(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output": output,
		"timestamp":  time.Now().Format(time.RFC3339),
		"type":       "bgp_config",
	}, nil
}

// ParseAppSignatures parses application signature status
func (p *FortiOSParser) ParseAppSignatures(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output": output,
		"timestamp":  time.Now().Format(time.RFC3339),
		"type":       "app_signatures",
	}, nil
}

// ParseIPSSignatures parses IPS signature status
func (p *FortiOSParser) ParseIPSSignatures(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output": output,
		"timestamp":  time.Now().Format(time.RFC3339),
		"type":       "ips_signatures",
	}, nil
}

// ParseAntivirusProfiles parses antivirus profiles
func (p *FortiOSParser) ParseAntivirusProfiles(output string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"raw_output": output,
		"timestamp":  time.Now().Format(time.RFC3339),
		"type":       "antivirus_profiles",
	}, nil
}

// GetCommandType returns the data type that a command produces
func (p *FortiOSParser) GetCommandType(command string) string {
	commandMap := map[string]string{
		"get system status":                 "system_status",
		"get system interface":              "interfaces",
		"get router info routing-table all": "routes",
		"get system session list":           "sessions",
		"get system performance status":     "performance",
		"get system arp":                    "arp",
		"get firewall policy":               "firewall_policies",
		"get vpn ipsec tunnel summary":      "vpn_tunnels",
		"get system ha status":              "ha_status",
		"diagnose sys top 1":                "processes",
		"get user info":                     "users",
		"execute log display":               "system_logs",
		"get log memory":                    "memory_logs",
		"get log eventtime":                 "event_logs",
		"diagnose hardware sysinfo shm":     "hardware_info",
		"diagnose sys session list":         "detailed_sessions",
		"get system interface physical":     "physical_interfaces",
		"get firewall address":              "address_objects",
		"get firewall service custom":       "service_objects",
		"get vpn ssl monitor":               "ssl_vpn_sessions",
		"get system admin":                  "admin_users",
		"get system snmp community":         "snmp_config",
		"diagnose sys ntp status":           "ntp_status",
		"diagnose debug reset":              "debug_reset",
		"get system dns":                    "dns_config",
		"get log fortianalyzer setting":     "fortianalyzer_config",
		"diagnose sys cpuinfo":              "cpu_info",
		"diagnose hardware sysinfo memory":  "memory_info",
		"get system global":                 "global_config",
	}

	if commandType, exists := commandMap[command]; exists {
		return commandType
	}
	return "generic"
}

// SupportedCommands returns the list of commands this parser can handle
func (p *FortiOSParser) SupportedCommands() []string {
	return []string{
		"get system status",
		"get system interface",
		"get router info routing-table all",
		"get system session list",
		"get system performance status",
		"get system arp",
		"get firewall policy",
		"get vpn ipsec tunnel summary",
		"get system ha status",
		"diagnose sys top 1",
		"get user info",
		"execute log display",
		"get log memory",
		"get log eventtime",
		"diagnose hardware sysinfo shm",
		"diagnose sys session list",
		"get system interface physical",
		"get firewall address",
		"get firewall service custom",
		"get vpn ssl monitor",
		"get system admin",
		"get system snmp community",
		"diagnose sys ntp status",
		"diagnose debug reset",
		"get system dns",
		"get log fortianalyzer setting",
		"diagnose sys cpuinfo",
		"diagnose hardware sysinfo memory",
		"get system global",
	}
}
