package cisco

import (
	"fmt"
	"strings"
	"time"

	"netdac/internal/core"

	"golang.org/x/crypto/ssh"
)

// IOSXRCollector implements forensically sound data collection for Cisco IOS XR devices
// based on official Cisco IOS XR Software Forensic Data Collection Procedures
// https://sec.cloudapps.cisco.com/security/center/resources/forensic_guides/ios_xr_forensic_investigation.html
type IOSXRCollector struct {
	Target     string
	Username   string
	Password   string
	SSHKey     []byte
	Timeout    time.Duration
	CommandSet string

	client    *ssh.Client
	session   *ssh.Session
	parser    *IOSXRParser
	connected bool
}

// NewIOSXRCollector creates a new IOS XR collector instance
func NewIOSXRCollector(target, username, password string, timeout time.Duration) *IOSXRCollector {
	return &IOSXRCollector{
		Target:    target,
		Username:  username,
		Password:  password,
		Timeout:   timeout,
		parser:    NewIOSXRParser(),
		connected: false,
	}
}

// SetSSHKey sets the SSH private key bytes for authentication
func (c *IOSXRCollector) SetSSHKey(key []byte) {
	c.SSHKey = key
}

// Collect performs comprehensive forensic data collection from IOS XR device
// Following Cisco IOS XR Software Forensic Data Collection Procedures
func (c *IOSXRCollector) Collect() (*core.DeviceState, error) {
	if err := c.Connect(); err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer c.Disconnect()

	// Enable privileged mode - required for all forensic commands
	if err := c.EnablePrivilegedMode(); err != nil {
		return nil, fmt.Errorf("failed to enter privileged mode: %w", err)
	}

	result := &core.DeviceState{
		DeviceInfo: core.DeviceInfo{
			IPAddress: c.Target,
			Vendor:    "cisco",
			Model:     "Unknown", // Will be populated from show version
			Version:   "Unknown", // Will be populated from show version
		},
		Timestamp:   time.Now(),
		RawCommands: make([]core.RawCommand, 0),
		Metadata: core.CollectionMetadata{
			CollectorVersion: "1.0.0",
			CollectionTime:   time.Now(),
			CommandSet:       c.CommandSet,
		},
		ForensicData: make(map[string]interface{}),
	}

	// Add forensic collection warnings specific to IOS XR
	result.Metadata.Warnings = []string{
		"FORENSIC COLLECTION: Following Cisco IOS XR Software Forensic Data Collection Procedures",
		"CRITICAL: Do NOT reboot device during investigation - volatile data will be lost",
		"RECOMMENDED: Device should be isolated from network prior to examination",
		"IOS XR Investigation: Process enumeration and memory analysis required",
		"Container Enumeration: Check both native hosting and third-party containers",
	}

	// Execute all forensic commands in sequence
	commands := c.getCommandSet()
	result.Metadata.TotalCommands = len(commands)
	successCount := 0

	for _, cmd := range commands {
		startTime := time.Now()

		if output, err := c.ExecuteCommand(cmd.Command); err != nil {
			// Log error but continue with other commands
			result.RawCommands = append(result.RawCommands, core.RawCommand{
				Command:     cmd.Command,
				Output:      "",
				ErrorOutput: err.Error(),
				Timestamp:   time.Now(),
				Duration:    time.Since(startTime).String(),
				ExitCode:    1,
			})
			result.Metadata.Errors = append(result.Metadata.Errors, fmt.Sprintf("%s: %v", cmd.Command, err))
		} else {
			result.RawCommands = append(result.RawCommands, core.RawCommand{
				Command:   cmd.Command,
				Output:    output,
				Timestamp: time.Now(),
				Duration:  time.Since(startTime).String(),
				ExitCode:  0,
			})
			successCount++

			// Parse command output into structured data
			if parsed, parseErr := c.parser.ParseCommand(cmd.Command, output); parseErr == nil {
				if cmd.Parser != "" {
					result.ForensicData[cmd.Parser] = parsed
				}
			}
		}
	}

	result.Metadata.SuccessfulCommands = successCount
	result.Metadata.FailedCommands = len(commands) - successCount

	// Parse core device information from show version output
	if versionOutput := c.findCommandOutput(result.RawCommands, "show version"); versionOutput != "" {
		if deviceInfo, err := c.parser.ParseVersion(versionOutput); err == nil {
			result.DeviceInfo = *deviceInfo
		}
	}

	// Parse additional structured data from command outputs
	c.parseCollectedData(result)

	// Print manual procedures after collection
	c.printManualProcedures(result.DeviceInfo.Hostname)

	return result, nil
}

// printManualProcedures displays IOS XR-specific manual forensic procedures
func (c *IOSXRCollector) printManualProcedures(hostname string) {
	fmt.Println("\n=== IOS XR MANUAL FORENSIC PROCEDURES ===")
	fmt.Printf("Device: %s\n", hostname)
	fmt.Println("The following manual steps should be performed by the forensic investigator:")
	fmt.Println()

	fmt.Println("1. CORE FILE ANALYSIS:")
	fmt.Println("   - Verify core files: show system dump")
	fmt.Println("   - Generate new core if needed: system dump all")
	fmt.Println("   - Download core files via SCP/TFTP")
	fmt.Println("   - Note: Core files may be large (>1GB)")
	fmt.Println()

	fmt.Println("2. ROM MONITOR VERIFICATION:")
	fmt.Println("   - Access ROM monitor if possible (reload and interrupt)")
	fmt.Println("   - Verify ROM monitor version: show version")
	fmt.Println("   - Check boot variables: show boot")
	fmt.Println("   - Document any ROM monitor modifications")
	fmt.Println()

	fmt.Println("3. LINE CARD ANALYSIS:")
	fmt.Println("   - Check line card status: show platform")
	fmt.Println("   - Verify line card software: show install summary")
	fmt.Println("   - Document any non-standard line card configurations")
	fmt.Println()

	fmt.Println("4. SYSTEM INTEGRITY:")
	fmt.Println("   - Verify image signatures: show install verify")
	fmt.Println("   - Check for unauthorized modifications")
	fmt.Println("   - Document any integrity violations")
	fmt.Println()

	fmt.Println("5. MEMORY ANALYSIS:")
	fmt.Println("   - Capture memory dumps if investigation requires")
	fmt.Println("   - Note: IOS XR uses distributed architecture")
	fmt.Println("   - Each node may require separate analysis")
	fmt.Println()

	fmt.Println("IMPORTANT: All procedures should follow your organization's forensic guidelines.")
	fmt.Println("Document all actions taken during the investigation.")
	fmt.Println("=== END IOS XR MANUAL PROCEDURES ===")
}

// Connect establishes SSH connection to the IOS XR device
func (c *IOSXRCollector) Connect() error {
	if c.connected {
		return nil
	}

	authMethods, err := core.CreateSSHAuthMethods(c.SSHKey, c.Password)
	if err != nil {
		return fmt.Errorf("failed to create SSH auth methods: %w", err)
	}

	config := &ssh.ClientConfig{
		User:            c.Username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         c.Timeout,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", c.Target), config)
	if err != nil {
		return fmt.Errorf("failed to connect to %s:22: %w", c.Target, err)
	}

	c.client = client
	c.connected = true
	return nil
}

// EnablePrivilegedMode enters enable mode if not already in privileged mode
func (c *IOSXRCollector) EnablePrivilegedMode() error {
	// Test if already in privileged mode
	if output, err := c.ExecuteCommand("show privilege"); err == nil {
		if strings.Contains(output, "Current privilege level is 15") ||
			strings.Contains(output, "privilege level is 15") {
			return nil // Already in privileged mode
		}
	}

	// Attempt to enable
	if _, err := c.ExecuteCommand("enable"); err != nil {
		return fmt.Errorf("failed to enable privileged mode: %w", err)
	}

	return nil
}

// ExecuteCommand runs a single command on the device
func (c *IOSXRCollector) ExecuteCommand(command string) (string, error) {
	if !c.connected {
		return "", fmt.Errorf("not connected to device")
	}

	session, err := c.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(command)
	if err != nil {
		return string(output), fmt.Errorf("command execution failed: %w", err)
	}

	return string(output), nil
}

// Disconnect closes the SSH connection
func (c *IOSXRCollector) Disconnect() error {
	if c.client != nil {
		err := c.client.Close()
		c.connected = false
		return err
	}
	return nil
}

// GetSupportedCommands returns list of commands supported by this collector
func (c *IOSXRCollector) GetSupportedCommands() []string {
	commands := c.getCommandSet()
	result := make([]string, len(commands))
	for i, cmd := range commands {
		result[i] = cmd.Command
	}
	return result
}

// ValidateConnection tests if the connection is working properly
func (c *IOSXRCollector) ValidateConnection() error {
	if !c.connected {
		return fmt.Errorf("not connected")
	}

	_, err := c.ExecuteCommand("show version | include Cisco")
	return err
}

// getCommandSet returns the appropriate command set based on the specified level
func (c *IOSXRCollector) getCommandSet() []core.Command {
	// Set terminal length to 0 to avoid pagination
	terminalCmd := core.Command{Name: "terminal_config", Command: "terminal length 0", Parser: "terminal", Required: true, Description: "Set terminal length to avoid pagination"}

	switch c.CommandSet {
	case "minimal":
		return append([]core.Command{terminalCmd}, c.getMinimalCommands()...)
	case "full":
		return append([]core.Command{terminalCmd}, c.getFullCommands()...)
	default: // "standard"
		return append([]core.Command{terminalCmd}, c.getStandardCommands()...)
	}
}

// getMinimalCommands returns essential forensic triage commands for IOS XR
// These are the most critical commands for quick assessment (Step 2 subset)
func (c *IOSXRCollector) getMinimalCommands() []core.Command {
	return []core.Command{
		// Core system identification
		{Name: "version_info", Command: "show version", Parser: "version", Required: true, Description: "Device version information"},
		{Name: "running_config", Command: "show running-config", Parser: "config", Required: true, Description: "Current running configuration"},
		{Name: "install_info", Command: "show install active summary", Parser: "install", Required: true, Description: "Active software packages"},
		{Name: "processes", Command: "show processes all", Parser: "processes", Required: true, Description: "All running processes"},
		{Name: "system_logs", Command: "show logging", Parser: "logs", Required: true, Description: "System log messages"},

		// Critical volatile data
		{Name: "tcp_connections", Command: "show tcp brief", Parser: "tcp", Required: true, Description: "TCP connections"},
		{Name: "udp_connections", Command: "show udp brief", Parser: "udp", Required: true, Description: "UDP connections"},
		{Name: "interfaces", Command: "show ip interface brief", Parser: "interfaces", Required: true, Description: "Interface status"},
	}
}

// getStandardCommands returns standard forensic collection commands for IOS XR
// Implements core requirements from Step 2 of the forensic procedures
func (c *IOSXRCollector) getStandardCommands() []core.Command {
	return []core.Command{
		// Step 2 - Core system-level commands (official forensic procedures)
		{Name: "tech_support", Command: "show tech-support", Parser: "tech_support", Required: true, Description: "Complete system information"},
		{Name: "version_info", Command: "show version", Parser: "version", Required: true, Description: "Device version information"},
		{Name: "tcp_connections", Command: "show tcp brief", Parser: "tcp", Required: true, Description: "TCP connections"},
		{Name: "udp_connections", Command: "show udp brief", Parser: "udp", Required: true, Description: "UDP connections"},
		{Name: "install_info", Command: "show install active summary", Parser: "install", Required: true, Description: "Active software packages"},
		{Name: "sdr_info", Command: "show sdr detail", Parser: "sdr", Required: false, Description: "Secure Domain Router information"},
		{Name: "platform_info", Command: "admin show platform", Parser: "platform", Required: false, Description: "Platform information"},
		{Name: "redundancy_info", Command: "show redundancy", Parser: "redundancy", Required: false, Description: "Redundancy status"},
		{Name: "system_logs", Command: "show logging", Parser: "logs", Required: true, Description: "System log messages"},
		{Name: "placement_info", Command: "show placement", Parser: "placement", Required: false, Description: "Process placement information"},
		{Name: "running_config", Command: "show running-config", Parser: "config", Required: true, Description: "Current running configuration"},
		{Name: "filesystem_info", Command: "show filesystem", Parser: "filesystem", Required: true, Description: "Filesystem information"},
		{Name: "interfaces", Command: "show ip interface brief", Parser: "interfaces", Required: true, Description: "Interface status"},

		// Directory listings (modified as needed for accessibility)
		{Name: "dir_apphost", Command: "dir /recurse apphost:", Parser: "directory", Required: false, Description: "Application host directory"},
		{Name: "dir_config", Command: "dir /recurse config:", Parser: "directory", Required: false, Description: "Configuration directory"},
		{Name: "dir_disk0", Command: "dir /recurse disk0:", Parser: "directory", Required: false, Description: "Disk0 directory"},
		{Name: "dir_harddisk", Command: "dir /recurse harddisk:", Parser: "directory", Required: false, Description: "Hard disk directory"},

		// Command history
		{Name: "history_detail", Command: "show history detail", Parser: "history", Required: false, Description: "Command history details"},
		{Name: "history_console", Command: "show history run-mode console", Parser: "history", Required: false, Description: "Console command history"},
		{Name: "history_vty", Command: "show history run-mode vty", Parser: "history", Required: false, Description: "VTY command history"},

		// CPU and process-level commands
		{Name: "processes", Command: "show processes all", Parser: "processes", Required: true, Description: "All running processes"},
		{Name: "processes_startup", Command: "show processes startup", Parser: "processes", Required: false, Description: "Startup processes"},
		{Name: "processes_aborts", Command: "show processes aborts", Parser: "processes", Required: false, Description: "Aborted processes"},
		{Name: "process_memory", Command: "show process memory", Parser: "memory", Required: true, Description: "Process memory usage"},

		// Platform integrity commands
		{Name: "secure_boot_status", Command: "show platform security integrity log secure-boot status", Parser: "integrity", Required: true, Description: "Secure boot status"},
		{Name: "platform_integrity", Command: "show platform security integrity dossier include packages reboot-history rollback-history system-integrity-snapshot filesystem-inventory system-inventory nonce 1580", Parser: "integrity", Required: true, Description: "Platform integrity dossier"},
	}
}

// getFullCommands returns comprehensive forensic analysis commands for IOS XR
// Includes all Step 2 commands plus additional forensic analysis commands
func (c *IOSXRCollector) getFullCommands() []core.Command {
	commands := c.getStandardCommands()

	// Add comprehensive forensic analysis commands
	additionalCommands := []core.Command{
		// Extended directory listings
		{Name: "dir_rootfs", Command: "dir /recurse rootfs:", Parser: "directory", Required: false, Description: "Root filesystem directory"},

		// Process enumeration for forensic analysis (Step A1)
		{Name: "netio_clients", Command: "show netio clients", Parser: "netio_clients", Required: true, Description: "NetIO clients (critical for forensics)"},
		{Name: "packet_memory_clients", Command: "show packet-memory clients", Parser: "packet_memory", Required: true, Description: "Packet memory clients (critical for forensics)"},

		// Linux system information
		{Name: "uname", Command: "run uname -s", Parser: "uname", Required: false, Description: "Operating system type"},
		{Name: "uname_all", Command: "run uname -a", Parser: "uname", Required: false, Description: "Complete system information"},

		// Additional platform security
		{Name: "integrity_log", Command: "show platform security integrity log", Parser: "integrity", Required: false, Description: "Platform integrity log"},

		// Extended process information
		{Name: "processes_detail", Command: "show processes all detail", Parser: "processes", Required: false, Description: "Detailed process information"},
		{Name: "processes_blocked", Command: "show processes blocked", Parser: "processes", Required: false, Description: "Blocked processes"},
		{Name: "processes_cpu", Command: "show processes cpu-time", Parser: "processes", Required: false, Description: "Process CPU time"},

		// Memory and core information
		{Name: "memory_summary", Command: "show memory summary", Parser: "memory", Required: false, Description: "Memory usage summary"},
		{Name: "memory_heap", Command: "show memory heap summary", Parser: "memory", Required: false, Description: "Heap memory summary"},

		// Network state
		{Name: "arp_table", Command: "show arp", Parser: "arp", Required: false, Description: "ARP table"},
		{Name: "routing_table", Command: "show route", Parser: "routes", Required: false, Description: "Routing table"},
		{Name: "interface_details", Command: "show interfaces", Parser: "interfaces", Required: false, Description: "Detailed interface information"},

		// Security and authentication
		{Name: "users", Command: "show users", Parser: "users", Required: false, Description: "Current users"},
		{Name: "aaa_servers", Command: "show aaa servers", Parser: "aaa", Required: false, Description: "AAA servers"},

		// Additional system information
		{Name: "environment", Command: "show environment", Parser: "environment", Required: false, Description: "Environmental status"},
		{Name: "inventory", Command: "show inventory", Parser: "inventory", Required: false, Description: "Hardware inventory"},
		{Name: "license_info", Command: "show license", Parser: "license", Required: false, Description: "License information"},

		// Container enumeration preparation commands
		{Name: "app_hosting", Command: "show application-hosting list", Parser: "containers", Required: false, Description: "Application hosting list"},

		// Additional logging
		{Name: "logging_events", Command: "show logging events", Parser: "logs", Required: false, Description: "Logging events"},
		{Name: "logging_correlator", Command: "show logging correlator", Parser: "logs", Required: false, Description: "Logging correlator"},
	}

	return append(commands, additionalCommands...)
}

// parseCollectedData parses specific command outputs into structured data
func (c *IOSXRCollector) parseCollectedData(result *core.DeviceState) {
	for _, rawCmd := range result.RawCommands {
		switch {
		case strings.Contains(rawCmd.Command, "show interfaces"):
			if interfaces, err := c.parser.ParseInterfaces(rawCmd.Output); err == nil {
				result.Interfaces = interfaces
			}
		case strings.Contains(rawCmd.Command, "show processes"):
			if processes, err := c.parser.ParseProcesses(rawCmd.Output); err == nil {
				result.Processes = processes
			}
		case strings.Contains(rawCmd.Command, "show tcp brief"):
			if connections, err := c.parser.ParseTCPConnections(rawCmd.Output); err == nil {
				result.Connections = append(result.Connections, connections...)
			}
		case strings.Contains(rawCmd.Command, "show udp brief"):
			if connections, err := c.parser.ParseUDPConnections(rawCmd.Output); err == nil {
				result.Connections = append(result.Connections, connections...)
			}
		case strings.Contains(rawCmd.Command, "show route"):
			if routes, err := c.parser.ParseRoutes(rawCmd.Output); err == nil {
				result.Routes = routes
			}
		case strings.Contains(rawCmd.Command, "show users"):
			if sessions, err := c.parser.ParseSessions(rawCmd.Output); err == nil {
				result.Sessions = sessions
			}
		}
	}
}

// findCommandOutput finds the output of a specific command in the raw commands
func (c *IOSXRCollector) findCommandOutput(commands []core.RawCommand, targetCommand string) string {
	for _, cmd := range commands {
		if strings.Contains(cmd.Command, targetCommand) {
			return cmd.Output
		}
	}
	return ""
}
