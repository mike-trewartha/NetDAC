package juniper

import (
	"fmt"
	"strings"
	"time"

	"netdac/internal/core"

	"golang.org/x/crypto/ssh"
)

// JunOSCollector implements live state analysis for Juniper Networks devices
// Based on standard Junos CLI commands from Juniper Networks CLI Reference Guides
// Note: No official forensic procedures published by Juniper Networks
// Live state analysis relies on standard operational commands and UNIX shell access
type JunOSCollector struct {
	Target                  string
	Username                string
	Password                string
	SSHKey                  []byte
	Timeout                 time.Duration
	CommandSet              string
	SkipHostKeyVerification bool

	client    *ssh.Client
	session   *ssh.Session
	parser    *JunOSParser
	connected bool
}

// JunOSCommand represents a Junos command with its execution parameters
type JunOSCommand struct {
	Command     string
	Parser      string
	Timeout     time.Duration
	Description string
	Critical    bool   // Critical commands for basic device state
	Context     string // cli, shell, or both
}

// NewJunOSCollector creates a new Juniper Junos collector
func NewJunOSCollector(target, username, password string, timeout time.Duration) *JunOSCollector {
	return &JunOSCollector{
		Target:    target,
		Username:  username,
		Password:  password,
		SSHKey:    nil,
		Timeout:   timeout,
		parser:    NewJunOSParser(),
		connected: false,
	}
}

// SetSSHKey sets the SSH private key bytes for authentication
func (c *JunOSCollector) SetSSHKey(key []byte) {
	c.SSHKey = key
}

// SetSkipHostKeyVerification sets whether to skip SSH host key verification
func (c *JunOSCollector) SetSkipHostKeyVerification(skip bool) {
	c.SkipHostKeyVerification = skip
}

// Collect performs comprehensive live state analysis from Junos device
// Based on standard Junos operational commands for state collection
func (c *JunOSCollector) Collect() (*core.DeviceState, error) {
	if !c.connected {
		if err := c.Connect(); err != nil {
			return nil, fmt.Errorf("connection failed: %w", err)
		}
		defer c.Disconnect()
	}

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

	// Get device information first
	deviceInfo, err := c.GetDeviceInfo()
	if err != nil {
		deviceState.Metadata.Warnings = append(deviceState.Metadata.Warnings,
			fmt.Sprintf("Could not retrieve device info: %v", err))
	} else {
		deviceState.DeviceInfo = *deviceInfo
	}

	// Get command set based on configuration
	commands := c.getCommandSet()
	deviceState.Metadata.TotalCommands = len(commands)

	// Execute commands and collect data
	for _, cmd := range commands {
		cmdStartTime := time.Now()

		output, err := c.executeCommand(cmd.Command, cmd.Timeout, cmd.Context)

		if err != nil {
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
		}

		// Add successful command to raw commands
		deviceState.RawCommands = append(deviceState.RawCommands, core.RawCommand{
			Command:   cmd.Command,
			Output:    output,
			Timestamp: cmdStartTime,
			Duration:  time.Since(cmdStartTime).String(),
			ExitCode:  0,
		})

		// Parse command output
		if cmd.Parser != "" && c.parser != nil {
			if parsed, parseErr := c.parser.ParseCommand(cmd.Command, output); parseErr != nil {
				deviceState.Metadata.Warnings = append(deviceState.Metadata.Warnings,
					fmt.Sprintf("Failed to parse command '%s': %v", cmd.Command, parseErr))
			} else if parsed != nil {
				// Store parsed data in ForensicData map using command as key
				deviceState.ForensicData[cmd.Command] = parsed
			}
		}

		deviceState.Metadata.SuccessfulCommands++
	}

	// Calculate final metadata
	deviceState.Metadata.CollectionDuration = time.Since(startTime).String()

	return deviceState, nil
}

// Connect establishes SSH connection to the Junos device
func (c *JunOSCollector) Connect() error {
	if c.connected {
		return nil
	}

	// Create authentication methods
	authMethods, err := core.CreateSSHAuthMethods(c.SSHKey, c.Password)
	if err != nil {
		return fmt.Errorf("SSH auth methods creation failed: %w", err)
	}

	config := &ssh.ClientConfig{
		User:            c.Username,
		Auth:            authMethods,
		HostKeyCallback: core.CreateHostKeyCallback(c.SkipHostKeyVerification, c.Target),
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

// Disconnect closes the SSH connection
func (c *JunOSCollector) Disconnect() error {
	if c.session != nil {
		c.session.Close()
		c.session = nil
	}
	if c.client != nil {
		c.client.Close()
		c.client = nil
	}
	c.connected = false
	return nil
}

// IsConnected returns the connection status
func (c *JunOSCollector) IsConnected() bool {
	return c.connected
}

// ValidateConnection validates the SSH connection to the device
func (c *JunOSCollector) ValidateConnection() error {
	if !c.connected {
		return fmt.Errorf("not connected to device")
	}

	// Test basic connectivity with a simple command
	_, err := c.executeCommand("show version brief", 10*time.Second, "cli")
	if err != nil {
		return fmt.Errorf("connection validation failed: %w", err)
	}

	return nil
}

// GetDeviceInfo retrieves basic device information
func (c *JunOSCollector) GetDeviceInfo() (*core.DeviceInfo, error) {
	if !c.connected {
		return nil, fmt.Errorf("not connected to device")
	}

	// Get basic device information
	versionOutput, err := c.executeCommand("show version", 15*time.Second, "cli")
	if err != nil {
		return nil, fmt.Errorf("failed to get version info: %w", err)
	}

	hostnameOutput, err := c.executeCommand("show system hostname", 10*time.Second, "cli")
	if err != nil {
		// Try alternative command
		hostnameOutput, err = c.executeCommand("show chassis hostname", 10*time.Second, "cli")
		if err != nil {
			hostnameOutput = "unknown"
		}
	}

	// Get chassis hardware info
	chassisOutput, err := c.executeCommand("show chassis hardware", 15*time.Second, "cli")
	if err != nil {
		chassisOutput = "unavailable"
	}

	return &core.DeviceInfo{
		Hostname:     strings.TrimSpace(hostnameOutput),
		IPAddress:    c.Target,
		Vendor:       "Juniper Networks",
		Model:        c.extractModel(chassisOutput),
		SerialNumber: c.extractSerial(chassisOutput),
		Version:      c.extractOSVersion(versionOutput),
		Uptime:       c.extractUptime(versionOutput),
	}, nil
}

// GetSupportedCommands returns the list of commands supported by this collector
func (c *JunOSCollector) GetSupportedCommands() []string {
	commands := c.getCommandSet()
	supportedCommands := make([]string, len(commands))
	for i, cmd := range commands {
		supportedCommands[i] = cmd.Command
	}
	return supportedCommands
}

// executeCommand executes a command on the device with context awareness
func (c *JunOSCollector) executeCommand(command string, timeout time.Duration, context string) (string, error) {
	if !c.connected {
		return "", fmt.Errorf("not connected to device")
	}

	session, err := c.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	// Set timeout for command execution
	if timeout == 0 {
		timeout = c.Timeout
	}

	// Prepare command based on context
	var fullCommand string
	switch context {
	case "shell":
		// Start shell and execute command
		fullCommand = fmt.Sprintf("start shell pfe execute \"%s\"", command)
	case "cli":
		// Standard CLI command
		fullCommand = command
	case "both":
		// Try CLI first, fallback to shell if needed
		fullCommand = command
	default:
		fullCommand = command
	}

	// Create channel for command completion
	done := make(chan error, 1)
	var output []byte

	go func() {
		var err error
		output, err = session.CombinedOutput(fullCommand)
		done <- err
	}()

	// Wait for command completion or timeout
	select {
	case err := <-done:
		if err != nil {
			return "", fmt.Errorf("command execution failed: %w", err)
		}
		return string(output), nil
	case <-time.After(timeout):
		session.Signal(ssh.SIGKILL)
		return "", fmt.Errorf("command timed out after %v", timeout)
	}
}

// getCommandSet returns the appropriate command set based on configuration
func (c *JunOSCollector) getCommandSet() []JunOSCommand {
	switch strings.ToLower(c.CommandSet) {
	case "minimal":
		return c.getMinimalCommandSet()
	case "full":
		return c.getFullCommandSet()
	default: // standard
		return c.getStandardCommandSet()
	}
}

// getMinimalCommandSet returns minimal commands for basic device state
func (c *JunOSCollector) getMinimalCommandSet() []JunOSCommand {
	return []JunOSCommand{
		{Command: "show version", Parser: "version", Timeout: 15 * time.Second, Description: "System version and hardware info", Critical: true, Context: "cli"},
		{Command: "show system hostname", Parser: "hostname", Timeout: 10 * time.Second, Description: "System hostname", Critical: false, Context: "cli"},
		{Command: "show chassis hardware", Parser: "hardware", Timeout: 15 * time.Second, Description: "Chassis hardware information", Critical: false, Context: "cli"},
		{Command: "show system processes", Parser: "processes", Timeout: 20 * time.Second, Description: "Running processes", Critical: false, Context: "cli"},
		{Command: "show interfaces terse", Parser: "interfaces", Timeout: 15 * time.Second, Description: "Interface status summary", Critical: false, Context: "cli"},
		{Command: "show route summary", Parser: "routing", Timeout: 15 * time.Second, Description: "Routing table summary", Critical: false, Context: "cli"},
		{Command: "show system users", Parser: "users", Timeout: 10 * time.Second, Description: "Current user sessions", Critical: false, Context: "cli"},
		{Command: "show system uptime", Parser: "uptime", Timeout: 10 * time.Second, Description: "System uptime", Critical: false, Context: "cli"},
	}
}

// getStandardCommandSet returns standard commands for comprehensive analysis
func (c *JunOSCollector) getStandardCommandSet() []JunOSCommand {
	commands := c.getMinimalCommandSet()

	// Add standard forensic commands
	standardCommands := []JunOSCommand{
		{Command: "show log messages | last 100", Parser: "logs", Timeout: 20 * time.Second, Description: "Recent system log messages", Critical: false, Context: "cli"},
		{Command: "show security policies", Parser: "security", Timeout: 25 * time.Second, Description: "Security policies", Critical: false, Context: "cli"},
		{Command: "show security zones", Parser: "security", Timeout: 15 * time.Second, Description: "Security zones", Critical: false, Context: "cli"},
		{Command: "show security nat", Parser: "security", Timeout: 20 * time.Second, Description: "NAT rules and sessions", Critical: false, Context: "cli"},
		{Command: "show security flow session", Parser: "sessions", Timeout: 30 * time.Second, Description: "Active security sessions", Critical: false, Context: "cli"},
		{Command: "show interfaces extensive", Parser: "interfaces", Timeout: 30 * time.Second, Description: "Detailed interface information", Critical: false, Context: "cli"},
		{Command: "show route extensive", Parser: "routing", Timeout: 25 * time.Second, Description: "Detailed routing information", Critical: false, Context: "cli"},
		{Command: "show system storage", Parser: "storage", Timeout: 15 * time.Second, Description: "File system usage", Critical: false, Context: "cli"},
		{Command: "show system memory", Parser: "memory", Timeout: 15 * time.Second, Description: "Memory utilization", Critical: false, Context: "cli"},
		{Command: "show chassis environment", Parser: "environment", Timeout: 20 * time.Second, Description: "Environmental status", Critical: false, Context: "cli"},
		{Command: "show system alarms", Parser: "alarms", Timeout: 15 * time.Second, Description: "System alarms", Critical: false, Context: "cli"},
		{Command: "show configuration | display set", Parser: "configuration", Timeout: 45 * time.Second, Description: "Running configuration", Critical: false, Context: "cli"},
		{Command: "show system license", Parser: "license", Timeout: 15 * time.Second, Description: "License information", Critical: false, Context: "cli"},
		{Command: "show chassis fpc pic-status", Parser: "hardware", Timeout: 20 * time.Second, Description: "PIC status information", Critical: false, Context: "cli"},
		{Command: "show system software", Parser: "software", Timeout: 20 * time.Second, Description: "Installed software packages", Critical: false, Context: "cli"},
	}

	return append(commands, standardCommands...)
}

// getFullCommandSet returns comprehensive commands for detailed forensic analysis
func (c *JunOSCollector) getFullCommandSet() []JunOSCommand {
	commands := c.getStandardCommandSet()

	// Add comprehensive forensic commands
	fullCommands := []JunOSCommand{
		// Advanced security and forensic commands
		{Command: "show security ike security-associations", Parser: "security", Timeout: 25 * time.Second, Description: "IKE security associations", Critical: false, Context: "cli"},
		{Command: "show security ipsec security-associations", Parser: "security", Timeout: 25 * time.Second, Description: "IPSec security associations", Critical: false, Context: "cli"},
		{Command: "show security log", Parser: "logs", Timeout: 30 * time.Second, Description: "Security logs", Critical: false, Context: "cli"},
		{Command: "show system commit", Parser: "commits", Timeout: 20 * time.Second, Description: "Configuration commit history", Critical: false, Context: "cli"},
		{Command: "show log chassisd | last 50", Parser: "logs", Timeout: 20 * time.Second, Description: "Chassis daemon logs", Critical: false, Context: "cli"},
		{Command: "show log dcd | last 50", Parser: "logs", Timeout: 20 * time.Second, Description: "DCD logs", Critical: false, Context: "cli"},
		{Command: "show log rpd | last 50", Parser: "logs", Timeout: 20 * time.Second, Description: "Routing protocol daemon logs", Critical: false, Context: "cli"},

		// Network and protocol analysis
		{Command: "show bgp summary", Parser: "routing", Timeout: 20 * time.Second, Description: "BGP summary", Critical: false, Context: "cli"},
		{Command: "show ospf neighbor", Parser: "routing", Timeout: 15 * time.Second, Description: "OSPF neighbors", Critical: false, Context: "cli"},
		{Command: "show isis adjacency", Parser: "routing", Timeout: 15 * time.Second, Description: "ISIS adjacencies", Critical: false, Context: "cli"},
		{Command: "show ldp session", Parser: "mpls", Timeout: 15 * time.Second, Description: "LDP sessions", Critical: false, Context: "cli"},
		{Command: "show mpls lsp", Parser: "mpls", Timeout: 20 * time.Second, Description: "MPLS LSPs", Critical: false, Context: "cli"},
		{Command: "show rsvp session", Parser: "mpls", Timeout: 15 * time.Second, Description: "RSVP sessions", Critical: false, Context: "cli"},

		// System-level forensic commands
		{Command: "show system connections", Parser: "connections", Timeout: 25 * time.Second, Description: "Network connections", Critical: false, Context: "cli"},
		{Command: "show system statistics", Parser: "statistics", Timeout: 20 * time.Second, Description: "System statistics", Critical: false, Context: "cli"},
		{Command: "show chassis pic fpc-slot 0 pic-slot 0", Parser: "hardware", Timeout: 15 * time.Second, Description: "PIC information", Critical: false, Context: "cli"},
		{Command: "show system boot-messages", Parser: "boot", Timeout: 20 * time.Second, Description: "Boot messages", Critical: false, Context: "cli"},
		{Command: "show system core-dumps", Parser: "cores", Timeout: 15 * time.Second, Description: "Core dump information", Critical: false, Context: "cli"},
		{Command: "show system snapshot media internal", Parser: "snapshots", Timeout: 20 * time.Second, Description: "System snapshots", Critical: false, Context: "cli"},

		// File system and security analysis
		{Command: "file list /var/log/", Parser: "files", Timeout: 20 * time.Second, Description: "Log file listing", Critical: false, Context: "cli"},
		{Command: "file list /var/tmp/", Parser: "files", Timeout: 15 * time.Second, Description: "Temporary file listing", Critical: false, Context: "cli"},
		{Command: "file list /config/", Parser: "files", Timeout: 15 * time.Second, Description: "Configuration file listing", Critical: false, Context: "cli"},
		{Command: "show system authentication-order", Parser: "auth", Timeout: 10 * time.Second, Description: "Authentication order", Critical: false, Context: "cli"},
		{Command: "show system radius", Parser: "auth", Timeout: 15 * time.Second, Description: "RADIUS configuration", Critical: false, Context: "cli"},
		{Command: "show system tacplus", Parser: "auth", Timeout: 15 * time.Second, Description: "TACACS+ configuration", Critical: false, Context: "cli"},
		{Command: "show system login", Parser: "auth", Timeout: 15 * time.Second, Description: "Login configuration", Critical: false, Context: "cli"},

		// Advanced monitoring and troubleshooting
		{Command: "show task replication", Parser: "tasks", Timeout: 15 * time.Second, Description: "Task replication status", Critical: false, Context: "cli"},
		{Command: "show task memory", Parser: "memory", Timeout: 15 * time.Second, Description: "Task memory usage", Critical: false, Context: "cli"},
		{Command: "show system virtual-memory", Parser: "memory", Timeout: 15 * time.Second, Description: "Virtual memory usage", Critical: false, Context: "cli"},
		{Command: "show chassis cluster status", Parser: "cluster", Timeout: 20 * time.Second, Description: "Cluster status (if applicable)", Critical: false, Context: "cli"},
		{Command: "show chassis cluster interfaces", Parser: "cluster", Timeout: 15 * time.Second, Description: "Cluster interfaces", Critical: false, Context: "cli"},

		// Shell commands for deeper system analysis
		{Command: "ps aux", Parser: "processes", Timeout: 20 * time.Second, Description: "Detailed process list", Critical: false, Context: "shell"},
		{Command: "netstat -an", Parser: "connections", Timeout: 25 * time.Second, Description: "Network socket information", Critical: false, Context: "shell"},
		{Command: "df -h", Parser: "storage", Timeout: 15 * time.Second, Description: "Disk space usage", Critical: false, Context: "shell"},
		{Command: "mount", Parser: "storage", Timeout: 10 * time.Second, Description: "Mounted file systems", Critical: false, Context: "shell"},
		{Command: "ls -la /tmp/", Parser: "files", Timeout: 15 * time.Second, Description: "Temporary directory contents", Critical: false, Context: "shell"},
		{Command: "ls -la /var/tmp/", Parser: "files", Timeout: 15 * time.Second, Description: "Variable temporary directory", Critical: false, Context: "shell"},
		{Command: "uptime", Parser: "uptime", Timeout: 10 * time.Second, Description: "System uptime and load", Critical: false, Context: "shell"},
		{Command: "who", Parser: "users", Timeout: 10 * time.Second, Description: "Current users", Critical: false, Context: "shell"},
		{Command: "last | head -20", Parser: "users", Timeout: 15 * time.Second, Description: "Recent user logins", Critical: false, Context: "shell"},

		// File system enumeration for malicious file detection
		{Command: "file list /var/tmp", Parser: "filesystem", Timeout: 30 * time.Second, Description: "Temporary directory contents for uploaded files", Critical: false, Context: "cli"},
		{Command: "file list /var/log", Parser: "filesystem", Timeout: 30 * time.Second, Description: "Log directory contents", Critical: false, Context: "cli"},
		{Command: "file list /cf/var/db/config/", Parser: "filesystem", Timeout: 25 * time.Second, Description: "Configuration file directory", Critical: false, Context: "cli"},
		{Command: "file show /cf/var/db/config/juniper.conf*", Parser: "filesystem", Timeout: 30 * time.Second, Description: "Configuration file history", Critical: false, Context: "cli"},
		{Command: "ls -la /tmp", Parser: "filesystem", Timeout: 20 * time.Second, Description: "Shell temp directory listing", Critical: false, Context: "shell"},
		{Command: "find /var -type f -newer /var/log/messages -ls", Parser: "filesystem", Timeout: 60 * time.Second, Description: "Recently modified files in /var", Critical: false, Context: "shell"},
		{Command: "find /tmp -type f -ls", Parser: "filesystem", Timeout: 30 * time.Second, Description: "All files in temp directories", Critical: false, Context: "shell"},
		{Command: "ls -latr /var/tmp/ | tail -20", Parser: "filesystem", Timeout: 20 * time.Second, Description: "Recently modified files in /var/tmp", Critical: false, Context: "shell"},
		{Command: "file list /var/db/ | match \"\\.sh|\\.py|\\.pl|\\.exe\"", Parser: "filesystem", Timeout: 30 * time.Second, Description: "Suspicious executable files", Critical: false, Context: "cli"},

		// Network connection monitoring for C2 detection
		{Command: "show system connections", Parser: "connections", Timeout: 25 * time.Second, Description: "System network connections", Critical: false, Context: "cli"},
		{Command: "show security flow session", Parser: "sessions", Timeout: 30 * time.Second, Description: "Security flow sessions for traffic analysis", Critical: false, Context: "cli"},
		{Command: "show security flow session summary", Parser: "sessions", Timeout: 20 * time.Second, Description: "Flow session summary", Critical: false, Context: "cli"},
		{Command: "show interfaces statistics detail", Parser: "interfaces", Timeout: 40 * time.Second, Description: "Detailed interface statistics", Critical: false, Context: "cli"},
		{Command: "netstat -anp", Parser: "connections", Timeout: 25 * time.Second, Description: "Network connections with PIDs", Critical: false, Context: "shell"},
		{Command: "ss -tulpn", Parser: "connections", Timeout: 20 * time.Second, Description: "Socket statistics with processes", Critical: false, Context: "shell"},
		{Command: "lsof -i", Parser: "connections", Timeout: 30 * time.Second, Description: "Open network files by process", Critical: false, Context: "shell"},
		{Command: "netstat -rn", Parser: "routing", Timeout: 15 * time.Second, Description: "Routing table for traffic analysis", Critical: false, Context: "shell"},
		{Command: "arp -a", Parser: "network", Timeout: 15 * time.Second, Description: "ARP table entries", Critical: false, Context: "shell"},

		// Enhanced process analysis for privilege escalation detection
		{Command: "show system processes extensive", Parser: "processes", Timeout: 30 * time.Second, Description: "Detailed process information", Critical: false, Context: "cli"},
		{Command: "show system processes summary", Parser: "processes", Timeout: 20 * time.Second, Description: "Process summary with CPU usage", Critical: false, Context: "cli"},
		{Command: "ps -auxww", Parser: "processes", Timeout: 25 * time.Second, Description: "Full process list with command lines", Critical: false, Context: "shell"},
		{Command: "ps -eo pid,ppid,uid,gid,cmd", Parser: "processes", Timeout: 25 * time.Second, Description: "Process hierarchy with user/group IDs", Critical: false, Context: "shell"},
		{Command: "ps -eo pid,ppid,user,group,args", Parser: "processes", Timeout: 25 * time.Second, Description: "Process list with user context", Critical: false, Context: "shell"},
		{Command: "top -n 1 -b", Parser: "processes", Timeout: 20 * time.Second, Description: "Process CPU and memory snapshot", Critical: false, Context: "shell"},
		{Command: "pstree -p", Parser: "processes", Timeout: 15 * time.Second, Description: "Process tree with PIDs", Critical: false, Context: "shell"},
		{Command: "ls -la /proc/*/exe 2>/dev/null | head -50", Parser: "processes", Timeout: 30 * time.Second, Description: "Process executable paths", Critical: false, Context: "shell"},
		{Command: "cat /proc/*/stat 2>/dev/null | head -20", Parser: "processes", Timeout: 25 * time.Second, Description: "Process statistics", Critical: false, Context: "shell"},
		{Command: "lsof -p 1", Parser: "processes", Timeout: 20 * time.Second, Description: "Files opened by init process", Critical: false, Context: "shell"},
	}

	return append(commands, fullCommands...)
}

// Helper functions for parsing device information

func (c *JunOSCollector) extractModel(chassisOutput string) string {
	lines := strings.Split(chassisOutput, "\n")
	for _, line := range lines {
		// Look for chassis line in hardware inventory
		if strings.Contains(strings.ToLower(line), "chassis") {
			// Split by multiple spaces to handle tabular format
			parts := strings.Split(line, "  ")
			cleanedParts := make([]string, 0)

			for _, part := range parts {
				trimmed := strings.TrimSpace(part)
				if trimmed != "" {
					cleanedParts = append(cleanedParts, trimmed)
				}
			}

			// Look for description field which contains model info
			// Format: Chassis   ABC123456   MX480 Base Chassis
			if len(cleanedParts) >= 3 {
				description := cleanedParts[2] // Description field
				words := strings.Fields(description)
				if len(words) > 0 {
					return words[0] // Return first word which is usually the model (MX480)
				}
			}
		}
	}
	return "unknown"
}

func (c *JunOSCollector) extractSerial(chassisOutput string) string {
	lines := strings.Split(chassisOutput, "\n")
	for _, line := range lines {
		// Look for chassis line in hardware inventory
		if strings.Contains(strings.ToLower(line), "chassis") {
			fields := strings.Fields(line)
			// In the format: "Chassis                                ABC123456         MX480 Base Chassis"
			// The serial number is typically in the 4th position (index 3)
			if len(fields) >= 4 {
				// Check if the field looks like a serial number (alphanumeric)
				for _, field := range fields[1:] {
					if len(field) > 5 && isAlphaNumeric(field) {
						return field
					}
				}
			}
		}
	}
	return "unknown"
}

// isAlphaNumeric checks if a string contains only alphanumeric characters
func isAlphaNumeric(s string) bool {
	for _, r := range s {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

func (c *JunOSCollector) extractOSVersion(versionOutput string) string {
	lines := strings.Split(versionOutput, "\n")
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), "junos") {
			fields := strings.Fields(line)
			for i, field := range fields {
				if strings.Contains(strings.ToLower(field), "junos") && i+1 < len(fields) {
					return fields[i+1]
				}
			}
		}
	}
	return "unknown"
}

func (c *JunOSCollector) extractUptime(versionOutput string) string {
	lines := strings.Split(versionOutput, "\n")
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), "uptime") {
			// Extract uptime information - handle different formats
			if strings.Contains(line, ":") {
				parts := strings.Split(line, ":")
				if len(parts) > 1 {
					return strings.TrimSpace(strings.Join(parts[1:], ":"))
				}
			}
		}
	}
	return "unknown"
}
