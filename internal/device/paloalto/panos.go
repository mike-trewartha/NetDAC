package paloalto

import (
	"fmt"
	"strings"
	"time"

	"netdac/internal/core"

	"golang.org/x/crypto/ssh"
)

// PANOSCollector implements live state analysis for Palo Alto PAN-OS devices
// Based on standard PAN-OS CLI commands from Palo Alto Networks CLI Reference Guides
// Note: No official forensic procedures published by Palo Alto Networks
// Live state analysis relies on standard operational commands
type PANOSCollector struct {
	Target     string
	Username   string
	Password   string
	Timeout    time.Duration
	CommandSet string

	client    *ssh.Client
	session   *ssh.Session
	parser    *PANOSParser
	connected bool
}

// PANOSCommand represents a PAN-OS command with its execution parameters
type PANOSCommand struct {
	Command     string
	Parser      string
	Timeout     time.Duration
	Description string
	Critical    bool // Critical commands for basic device state
}

// NewPANOSCollector creates a new Palo Alto PAN-OS collector
func NewPANOSCollector(target, username, password string, timeout time.Duration) *PANOSCollector {
	return &PANOSCollector{
		Target:    target,
		Username:  username,
		Password:  password,
		Timeout:   timeout,
		parser:    NewPANOSParser(),
		connected: false,
	}
}

// Collect performs comprehensive live state analysis from PAN-OS device
// Based on standard PAN-OS operational commands for state collection
func (c *PANOSCollector) Collect() (*core.DeviceState, error) {
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

// Connect establishes SSH connection to the PAN-OS device
func (c *PANOSCollector) Connect() error {
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
func (c *PANOSCollector) ValidateConnection() error {
	if !c.connected {
		return fmt.Errorf("not connected to device")
	}

	// Test with a simple command
	if _, err := c.executeCommand("show system info", 10*time.Second); err != nil {
		return fmt.Errorf("connection validation failed: %w", err)
	}

	return nil
}

// Disconnect closes the SSH connection
func (c *PANOSCollector) Disconnect() error {
	if c.client != nil {
		c.client.Close()
		c.client = nil
	}
	c.connected = false
	return nil
}

// executeCommand executes a single command on the PAN-OS device
func (c *PANOSCollector) executeCommand(command string, timeout time.Duration) (string, error) {
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
func (c *PANOSCollector) getCommandSet() []PANOSCommand {
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
func (c *PANOSCollector) getMinimalCommandSet() []PANOSCommand {
	return []PANOSCommand{
		{Command: "show system info", Parser: "system_info", Timeout: 30 * time.Second, Description: "System information", Critical: true},
		{Command: "show interface all", Parser: "interfaces", Timeout: 30 * time.Second, Description: "Interface status", Critical: true},
		{Command: "show system resources", Parser: "resources", Timeout: 30 * time.Second, Description: "System resources", Critical: false},
	}
}

// getStandardCommandSet returns standard operational commands
func (c *PANOSCollector) getStandardCommandSet() []PANOSCommand {
	commands := c.getMinimalCommandSet()

	standardCommands := []PANOSCommand{
		{Command: "show routing route", Parser: "routes", Timeout: 60 * time.Second, Description: "Routing table", Critical: false},
		{Command: "show session info", Parser: "session_info", Timeout: 30 * time.Second, Description: "Session statistics", Critical: false},
		{Command: "show arp all", Parser: "arp", Timeout: 30 * time.Second, Description: "ARP table", Critical: false},
		{Command: "show high-availability state", Parser: "ha_state", Timeout: 30 * time.Second, Description: "HA status", Critical: false},
		{Command: "show ntp", Parser: "ntp", Timeout: 30 * time.Second, Description: "NTP status", Critical: false},
		{Command: "show dns-proxy cache", Parser: "dns_cache", Timeout: 30 * time.Second, Description: "DNS cache", Critical: false},
		{Command: "show vpn tunnel", Parser: "vpn_tunnels", Timeout: 30 * time.Second, Description: "VPN tunnels", Critical: false},
	}

	return append(commands, standardCommands...)
}

// getFullCommandSet returns comprehensive command set for detailed analysis
func (c *PANOSCollector) getFullCommandSet() []PANOSCommand {
	commands := c.getStandardCommandSet()

	fullCommands := []PANOSCommand{
		// Enhanced forensic and integrity checks
		{Command: "show system info", Parser: "system_info_detailed", Timeout: 30 * time.Second, Description: "Detailed system information", Critical: false},
		{Command: "show system software status", Parser: "software_status", Timeout: 30 * time.Second, Description: "Software status and versions", Critical: false},
		{Command: "show system files", Parser: "system_files", Timeout: 60 * time.Second, Description: "System file listing", Critical: false},
		{Command: "show config running", Parser: "running_config", Timeout: 120 * time.Second, Description: "Complete running configuration", Critical: false},
		{Command: "show config candidate", Parser: "candidate_config", Timeout: 60 * time.Second, Description: "Candidate configuration", Critical: false},

		// Process and system analysis
		{Command: "show system processes", Parser: "processes", Timeout: 60 * time.Second, Description: "System processes", Critical: false},
		{Command: "show system memory", Parser: "memory_info", Timeout: 30 * time.Second, Description: "Memory utilization", Critical: false},
		{Command: "show system disk-space", Parser: "disk_space", Timeout: 30 * time.Second, Description: "Disk space usage", Critical: false},
		{Command: "show system environment", Parser: "environment", Timeout: 30 * time.Second, Description: "Environmental status", Critical: false},

		// Enhanced logging and audit data
		{Command: "show log system", Parser: "system_logs", Timeout: 120 * time.Second, Description: "System logs", Critical: false},
		{Command: "show log traffic", Parser: "traffic_logs", Timeout: 120 * time.Second, Description: "Traffic logs", Critical: false},
		{Command: "show log threat", Parser: "threat_logs", Timeout: 120 * time.Second, Description: "Threat logs", Critical: false},
		{Command: "show log auth", Parser: "auth_logs", Timeout: 60 * time.Second, Description: "Authentication logs", Critical: false},
		{Command: "show log config", Parser: "config_logs", Timeout: 60 * time.Second, Description: "Configuration change logs", Critical: false},

		// Network state and connections analysis
		{Command: "show session all", Parser: "all_sessions", Timeout: 120 * time.Second, Description: "All active sessions", Critical: false},
		{Command: "show session id all filter state active", Parser: "active_sessions", Timeout: 90 * time.Second, Description: "Active session details", Critical: false},
		{Command: "show mac all", Parser: "mac_table", Timeout: 60 * time.Second, Description: "MAC address table", Critical: false},
		{Command: "show counter global filter delta yes", Parser: "global_counters", Timeout: 60 * time.Second, Description: "Global counters", Critical: false},
		{Command: "show counter interface all", Parser: "interface_counters", Timeout: 60 * time.Second, Description: "Interface counters", Critical: false},

		// Security policies and configuration
		{Command: "show running security-policy", Parser: "security_policies", Timeout: 60 * time.Second, Description: "Security policies", Critical: false},
		{Command: "show running nat-policy", Parser: "nat_policies", Timeout: 60 * time.Second, Description: "NAT policies", Critical: false},
		{Command: "show running application", Parser: "application_config", Timeout: 60 * time.Second, Description: "Application configuration", Critical: false},
		{Command: "show application-custom", Parser: "custom_applications", Timeout: 30 * time.Second, Description: "Custom application definitions", Critical: false},

		// User and authentication analysis
		{Command: "show user ip-user-mapping all", Parser: "user_mappings", Timeout: 60 * time.Second, Description: "User IP mappings", Critical: false},
		{Command: "show user group list", Parser: "user_groups", Timeout: 30 * time.Second, Description: "User groups", Critical: false},
		{Command: "show admins", Parser: "admins", Timeout: 30 * time.Second, Description: "Administrator accounts", Critical: false},
		{Command: "show authentication profile", Parser: "auth_profiles", Timeout: 30 * time.Second, Description: "Authentication profiles", Critical: false},

		// Management and operational security
		{Command: "show jobs all", Parser: "jobs", Timeout: 30 * time.Second, Description: "System jobs", Critical: false},
		{Command: "show cli config-lock", Parser: "config_locks", Timeout: 30 * time.Second, Description: "Configuration locks", Critical: false},
		{Command: "show management-clients", Parser: "mgmt_clients", Timeout: 30 * time.Second, Description: "Management clients", Critical: false},
		{Command: "show certificate", Parser: "certificates", Timeout: 60 * time.Second, Description: "SSL certificates", Critical: false},

		// File system and integrity analysis
		{Command: "request export configuration from candidate to file CONFIG_BACKUP.xml", Parser: "config_export", Timeout: 60 * time.Second, Description: "Configuration backup", Critical: false},
		{Command: "show file", Parser: "file_listing", Timeout: 60 * time.Second, Description: "File system listing", Critical: false},
		{Command: "show url-database", Parser: "url_database", Timeout: 30 * time.Second, Description: "URL database status", Critical: false},

		// Hardware and platform security
		{Command: "show chassis status", Parser: "chassis_status", Timeout: 30 * time.Second, Description: "Chassis status", Critical: false},
		{Command: "show chassis-ready", Parser: "chassis_ready", Timeout: 30 * time.Second, Description: "Chassis ready status", Critical: false},
		{Command: "show panorama status", Parser: "panorama_status", Timeout: 30 * time.Second, Description: "Panorama connection status", Critical: false},
	}

	return append(commands, fullCommands...)
}

// GetSupportedCommands returns the list of commands supported by this collector
func (c *PANOSCollector) GetSupportedCommands() []string {
	commands := []string{}
	for _, cmd := range c.getFullCommandSet() {
		commands = append(commands, cmd.Command)
	}
	return commands
}

// updateDeviceState updates the structured device state based on parsed data
func (c *PANOSCollector) updateDeviceState(deviceState *core.DeviceState, parserType string, parsedData interface{}) {
	switch parserType {
	case "system_info":
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
	case "session_info":
		if sessions, ok := parsedData.([]core.Session); ok {
			deviceState.Sessions = sessions
		}
	case "resources":
		if systemInfo, ok := parsedData.(*core.SystemInfo); ok {
			deviceState.SystemInfo = *systemInfo
		}
	}
}
