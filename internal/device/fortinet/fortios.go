package fortinet

import (
	"fmt"
	"strings"
	"time"

	"netdac/internal/core"

	"golang.org/x/crypto/ssh"
)

// FortiOSCollector implements live state analysis for Fortinet FortiGate devices
// Based on standard FortiOS CLI commands from Fortinet CLI Reference Guides
// Note: No official forensic procedures published by Fortinet
// Live state analysis relies on FortiAnalyzer integration and standard operational commands
type FortiOSCollector struct {
	Target     string
	Username   string
	Password   string
	Timeout    time.Duration
	CommandSet string

	client    *ssh.Client
	session   *ssh.Session
	parser    *FortiOSParser
	connected bool
}

// FortiOSCommand represents a FortiOS command with its execution parameters
type FortiOSCommand struct {
	Command     string
	Parser      string
	Timeout     time.Duration
	Description string
	Critical    bool // Critical commands for basic device state
}

// NewFortiOSCollector creates a new Fortinet FortiOS collector
func NewFortiOSCollector(target, username, password string, timeout time.Duration) *FortiOSCollector {
	return &FortiOSCollector{
		Target:    target,
		Username:  username,
		Password:  password,
		Timeout:   timeout,
		parser:    NewFortiOSParser(),
		connected: false,
	}
}

// Collect performs comprehensive live state analysis from FortiGate device
// Based on standard FortiOS operational commands for state collection
func (c *FortiOSCollector) Collect() (*core.DeviceState, error) {
	if err := c.Connect(); err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer c.Disconnect()

	startTime := time.Now()

	// Initialize device state
	deviceState := &core.DeviceState{
		Timestamp:   time.Now(),
		RawCommands: []core.RawCommand{},
		Metadata: core.CollectionMetadata{
			CollectionTime:     startTime,
			CommandSet:         c.CommandSet,
			SuccessfulCommands: 0,
			FailedCommands:     0,
			Errors:             []string{},
			Warnings:           []string{},
		},
		ForensicData: make(map[string]interface{}),
	}

	// Get command set based on configuration
	commands := c.getCommandSet()
	deviceState.Metadata.TotalCommands = len(commands)

	// Execute commands and collect data
	for _, cmd := range commands {
		cmdStartTime := time.Now()

		if output, err := c.executeCommand(cmd.Command, cmd.Timeout); err != nil {
			deviceState.Metadata.FailedCommands++
			deviceState.Metadata.Errors = append(deviceState.Metadata.Errors,
				fmt.Sprintf("Command '%s' failed: %v", cmd.Command, err))

			// Add failed command to raw commands
			deviceState.RawCommands = append(deviceState.RawCommands, core.RawCommand{
				Command:     cmd.Command,
				Output:      "",
				ErrorOutput: err.Error(),
				Timestamp:   cmdStartTime,
				Duration:    time.Since(cmdStartTime).String(),
				ExitCode:    1,
			})

			// Skip critical command failures
			if cmd.Critical {
				return nil, fmt.Errorf("critical command failed: %s - %v", cmd.Command, err)
			}
			continue
		} else {
			deviceState.Metadata.SuccessfulCommands++

			// Add successful command to raw commands
			deviceState.RawCommands = append(deviceState.RawCommands, core.RawCommand{
				Command:   cmd.Command,
				Output:    output,
				Timestamp: cmdStartTime,
				Duration:  time.Since(cmdStartTime).String(),
				ExitCode:  0,
			})

			// Parse command output using appropriate parser
			if parsedData, err := c.parser.ParseCommand(cmd.Parser, output); err != nil {
				deviceState.Metadata.Warnings = append(deviceState.Metadata.Warnings,
					fmt.Sprintf("Parse warning for '%s': %v", cmd.Command, err))
			} else {
				deviceState.ForensicData[cmd.Parser] = parsedData

				// Update structured data based on parser type
				c.updateDeviceState(deviceState, cmd.Parser, parsedData)
			}
		}
	}

	// Set collection duration
	deviceState.Metadata.CollectionDuration = time.Since(startTime).String()

	return deviceState, nil
}

// Connect establishes SSH connection to the FortiGate device
func (c *FortiOSCollector) Connect() error {
	if c.connected {
		return nil
	}

	config := &ssh.ClientConfig{
		User: c.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(c.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         c.Timeout,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", c.Target), config)
	if err != nil {
		return fmt.Errorf("SSH connection failed: %w", err)
	}

	c.client = client
	c.connected = true
	return nil
}

// ValidateConnection tests if the connection is working properly
func (c *FortiOSCollector) ValidateConnection() error {
	if !c.connected {
		return fmt.Errorf("not connected to device")
	}

	// Test with a simple command
	if _, err := c.executeCommand("get system status", 10*time.Second); err != nil {
		return fmt.Errorf("connection validation failed: %w", err)
	}

	return nil
}

// Disconnect closes the SSH connection
func (c *FortiOSCollector) Disconnect() error {
	if c.client != nil {
		c.client.Close()
		c.client = nil
	}
	c.connected = false
	return nil
}

// executeCommand executes a single command on the FortiGate device
func (c *FortiOSCollector) executeCommand(command string, timeout time.Duration) (string, error) {
	if !c.connected {
		return "", fmt.Errorf("not connected to device")
	}

	session, err := c.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	// Set timeout for command execution
	done := make(chan error, 1)
	var output []byte

	go func() {
		output, err = session.CombinedOutput(command)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			return "", fmt.Errorf("command execution failed: %w", err)
		}
		return string(output), nil
	case <-time.After(timeout):
		session.Close()
		return "", fmt.Errorf("command timeout after %v", timeout)
	}
}

// getCommandSet returns the appropriate command set based on configuration
func (c *FortiOSCollector) getCommandSet() []FortiOSCommand {
	switch strings.ToLower(c.CommandSet) {
	case "minimal":
		return c.getMinimalCommandSet()
	case "full":
		return c.getFullCommandSet()
	default: // "standard"
		return c.getStandardCommandSet()
	}
}

// getMinimalCommandSet returns essential commands for basic device state
func (c *FortiOSCollector) getMinimalCommandSet() []FortiOSCommand {
	return []FortiOSCommand{
		{Command: "get system status", Parser: "system_status", Timeout: 30 * time.Second, Description: "System information", Critical: true},
		{Command: "get system interface", Parser: "interfaces", Timeout: 30 * time.Second, Description: "Interface status", Critical: true},
		{Command: "get system performance status", Parser: "performance", Timeout: 30 * time.Second, Description: "System performance", Critical: false},
	}
}

// getStandardCommandSet returns standard operational commands
func (c *FortiOSCollector) getStandardCommandSet() []FortiOSCommand {
	commands := c.getMinimalCommandSet()

	standardCommands := []FortiOSCommand{
		{Command: "get router info routing-table all", Parser: "routes", Timeout: 60 * time.Second, Description: "Routing table", Critical: false},
		{Command: "get system session list", Parser: "sessions", Timeout: 60 * time.Second, Description: "Active sessions", Critical: false},
		{Command: "get system arp", Parser: "arp", Timeout: 30 * time.Second, Description: "ARP table", Critical: false},
		{Command: "get firewall policy", Parser: "firewall_policies", Timeout: 60 * time.Second, Description: "Firewall policies", Critical: false},
		{Command: "get vpn ipsec tunnel summary", Parser: "vpn_tunnels", Timeout: 30 * time.Second, Description: "VPN tunnels", Critical: false},
		{Command: "get system ha status", Parser: "ha_status", Timeout: 30 * time.Second, Description: "HA status", Critical: false},
		{Command: "diagnose sys top 1", Parser: "processes", Timeout: 30 * time.Second, Description: "Process list", Critical: false},
		{Command: "get user info", Parser: "users", Timeout: 30 * time.Second, Description: "User information", Critical: false},
	}

	return append(commands, standardCommands...)
}

// getFullCommandSet returns comprehensive command set for detailed analysis
func (c *FortiOSCollector) getFullCommandSet() []FortiOSCommand {
	commands := c.getStandardCommandSet()

	fullCommands := []FortiOSCommand{
		// Enhanced system integrity and forensic analysis
		{Command: "get system status", Parser: "system_status_detailed", Timeout: 30 * time.Second, Description: "Detailed system status", Critical: false},
		{Command: "diagnose sys scanunit 1", Parser: "system_integrity", Timeout: 60 * time.Second, Description: "System integrity scan", Critical: false},
		{Command: "diagnose sys checksum all", Parser: "system_checksum", Timeout: 120 * time.Second, Description: "System file checksums", Critical: false},
		{Command: "get system fortiguard", Parser: "fortiguard_status", Timeout: 30 * time.Second, Description: "FortiGuard service status", Critical: false},

		// Process and memory analysis
		{Command: "diagnose sys top-summary", Parser: "process_summary", Timeout: 30 * time.Second, Description: "Process summary", Critical: false},
		{Command: "diagnose sys process-list", Parser: "detailed_processes", Timeout: 60 * time.Second, Description: "Detailed process list", Critical: false},
		{Command: "diagnose hardware sysinfo memory", Parser: "memory_info", Timeout: 30 * time.Second, Description: "Memory information", Critical: false},
		{Command: "diagnose sys cpuinfo", Parser: "cpu_info", Timeout: 30 * time.Second, Description: "CPU information", Critical: false},
		{Command: "diagnose hardware sysinfo shm", Parser: "hardware_info", Timeout: 60 * time.Second, Description: "Hardware information", Critical: false},

		// File system and integrity analysis
		{Command: "execute backup config flash CONFIG_BACKUP.conf", Parser: "config_backup", Timeout: 60 * time.Second, Description: "Configuration backup", Critical: false},
		{Command: "diagnose sys flash list", Parser: "flash_listing", Timeout: 60 * time.Second, Description: "Flash file system listing", Critical: false},
		{Command: "get system boot", Parser: "boot_config", Timeout: 30 * time.Second, Description: "Boot configuration", Critical: false},
		{Command: "fnsysctl ls /", Parser: "root_filesystem", Timeout: 60 * time.Second, Description: "Root filesystem listing", Critical: false},

		// Enhanced logging and audit data
		{Command: "execute log display", Parser: "system_logs", Timeout: 120 * time.Second, Description: "System logs", Critical: false},
		{Command: "get log memory", Parser: "memory_logs", Timeout: 120 * time.Second, Description: "Memory logs", Critical: false},
		{Command: "get log eventtime", Parser: "event_logs", Timeout: 120 * time.Second, Description: "Event logs", Critical: false},
		{Command: "execute log filter device disk start-line 1 end-line 1000", Parser: "disk_logs", Timeout: 120 * time.Second, Description: "Disk log entries", Critical: false},
		{Command: "diagnose log test", Parser: "log_test", Timeout: 30 * time.Second, Description: "Log system test", Critical: false},

		// Network connections and session analysis
		{Command: "diagnose sys session list", Parser: "detailed_sessions", Timeout: 120 * time.Second, Description: "Detailed session list", Critical: false},
		{Command: "diagnose sys session stat", Parser: "session_statistics", Timeout: 30 * time.Second, Description: "Session statistics", Critical: false},
		{Command: "diagnose netlink interface list", Parser: "netlink_interfaces", Timeout: 30 * time.Second, Description: "Netlink interface details", Critical: false},
		{Command: "get system interface physical", Parser: "physical_interfaces", Timeout: 30 * time.Second, Description: "Physical interface details", Critical: false},
		{Command: "diagnose ip arp list", Parser: "arp_detailed", Timeout: 30 * time.Second, Description: "Detailed ARP table", Critical: false},

		// Security policy and configuration analysis
		{Command: "get firewall policy", Parser: "firewall_policies_detailed", Timeout: 90 * time.Second, Description: "Detailed firewall policies", Critical: false},
		{Command: "get firewall address", Parser: "address_objects", Timeout: 60 * time.Second, Description: "Address objects", Critical: false},
		{Command: "get firewall service custom", Parser: "service_objects", Timeout: 60 * time.Second, Description: "Service objects", Critical: false},
		{Command: "get firewall shaping-policy", Parser: "shaping_policies", Timeout: 30 * time.Second, Description: "Traffic shaping policies", Critical: false},
		{Command: "get firewall central-snat-map", Parser: "snat_policies", Timeout: 30 * time.Second, Description: "SNAT policies", Critical: false},

		// VPN and encryption analysis
		{Command: "get vpn ipsec tunnel summary", Parser: "vpn_tunnels_detailed", Timeout: 60 * time.Second, Description: "Detailed VPN tunnels", Critical: false},
		{Command: "get vpn ssl monitor", Parser: "ssl_vpn_sessions", Timeout: 30 * time.Second, Description: "SSL VPN sessions", Critical: false},
		{Command: "get vpn ipsec tunnel details", Parser: "ipsec_details", Timeout: 60 * time.Second, Description: "IPSec tunnel details", Critical: false},
		{Command: "get vpn certificate local", Parser: "local_certificates", Timeout: 30 * time.Second, Description: "Local certificates", Critical: false},

		// User and authentication analysis
		{Command: "get user info", Parser: "users_detailed", Timeout: 30 * time.Second, Description: "Detailed user information", Critical: false},
		{Command: "get system admin", Parser: "admin_users", Timeout: 30 * time.Second, Description: "Administrator accounts", Critical: false},
		{Command: "diagnose test authserver all", Parser: "auth_servers", Timeout: 60 * time.Second, Description: "Authentication server test", Critical: false},
		{Command: "get user group", Parser: "user_groups", Timeout: 30 * time.Second, Description: "User groups", Critical: false},
		{Command: "get user radius", Parser: "radius_config", Timeout: 30 * time.Second, Description: "RADIUS configuration", Critical: false},

		// Management and monitoring analysis
		{Command: "get system snmp community", Parser: "snmp_config", Timeout: 30 * time.Second, Description: "SNMP configuration", Critical: false},
		{Command: "get system ntp", Parser: "ntp_config", Timeout: 30 * time.Second, Description: "NTP configuration", Critical: false},
		{Command: "diagnose sys ntp status", Parser: "ntp_status", Timeout: 30 * time.Second, Description: "NTP status", Critical: false},
		{Command: "get system dns", Parser: "dns_config", Timeout: 30 * time.Second, Description: "DNS configuration", Critical: false},
		{Command: "get log fortianalyzer setting", Parser: "fortianalyzer_config", Timeout: 30 * time.Second, Description: "FortiAnalyzer configuration", Critical: false},

		// Global configuration and environment
		{Command: "get system global", Parser: "global_config", Timeout: 30 * time.Second, Description: "Global configuration", Critical: false},
		{Command: "get router static", Parser: "static_routes", Timeout: 30 * time.Second, Description: "Static routes", Critical: false},
		{Command: "get router ospf", Parser: "ospf_config", Timeout: 30 * time.Second, Description: "OSPF configuration", Critical: false},
		{Command: "get router bgp", Parser: "bgp_config", Timeout: 30 * time.Second, Description: "BGP configuration", Critical: false},

		// Security and compliance checks
		{Command: "diagnose debug reset", Parser: "debug_reset", Timeout: 30 * time.Second, Description: "Debug reset status", Critical: false},
		{Command: "diagnose test application update", Parser: "app_signatures", Timeout: 60 * time.Second, Description: "Application signature status", Critical: false},
		{Command: "diagnose test application ips", Parser: "ips_signatures", Timeout: 60 * time.Second, Description: "IPS signature status", Critical: false},
		{Command: "get antivirus profile", Parser: "antivirus_profiles", Timeout: 30 * time.Second, Description: "Antivirus profiles", Critical: false},
	}

	return append(commands, fullCommands...)
}

// updateDeviceState updates the structured device state based on parsed data
func (c *FortiOSCollector) updateDeviceState(deviceState *core.DeviceState, parserType string, parsedData interface{}) {
	switch parserType {
	case "system_status":
		if deviceInfo, ok := parsedData.(*core.DeviceInfo); ok {
			deviceState.DeviceInfo = *deviceInfo
		}
	case "interfaces":
		if interfaces, ok := parsedData.([]core.Interface); ok {
			deviceState.Interfaces = interfaces
		}
	case "routes":
		if routes, ok := parsedData.([]core.Route); ok {
			deviceState.Routes = routes
		}
	case "sessions":
		if sessions, ok := parsedData.([]core.Session); ok {
			deviceState.Sessions = sessions
		}
	case "processes":
		if processes, ok := parsedData.([]core.Process); ok {
			deviceState.Processes = processes
		}
	case "performance":
		if systemInfo, ok := parsedData.(*core.SystemInfo); ok {
			deviceState.SystemInfo = *systemInfo
		}
	}
}

// GetSupportedCommands returns the list of commands supported by this collector
func (c *FortiOSCollector) GetSupportedCommands() []string {
	commands := []string{}
	for _, cmd := range c.getFullCommandSet() {
		commands = append(commands, cmd.Command)
	}
	return commands
}
