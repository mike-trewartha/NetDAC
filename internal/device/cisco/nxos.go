package cisco

import (
	"fmt"
	"strings"
	"time"

	"netdac/internal/core"

	"golang.org/x/crypto/ssh"
)

// NXOSCollector implements forensically sound data collection for Cisco NX-OS devices
// based on official Cisco NX-OS Software Forensic Data Collection Procedures
// https://sec.cloudapps.cisco.com/security/center/resources/forensic_guides/nx-os_forensic_investigation.html
type NXOSCollector struct {
	Target     string
	Username   string
	Password   string
	SSHKey     []byte
	Timeout    time.Duration
	CommandSet string

	client    *ssh.Client
	session   *ssh.Session
	parser    *NXOSParser
	connected bool
}

// NewNXOSCollector creates a new NX-OS collector instance
func NewNXOSCollector(target, username, password string, timeout time.Duration) *NXOSCollector {
	return &NXOSCollector{
		Target:    target,
		Username:  username,
		Password:  password,
		Timeout:   timeout,
		parser:    NewNXOSParser(),
		connected: false,
	}
}

// SetSSHKey sets the SSH private key for authentication
func (c *NXOSCollector) SetSSHKey(key []byte) {
	c.SSHKey = key
}

// Collect performs comprehensive forensic data collection from NX-OS device
// Following Cisco NX-OS Software Forensic Data Collection Procedures
func (c *NXOSCollector) Collect() (*core.DeviceState, error) {
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

	// Add forensic collection warnings specific to NX-OS
	result.Metadata.Warnings = []string{
		"FORENSIC COLLECTION: Following Cisco NX-OS Software Forensic Data Collection Procedures",
		"CRITICAL: Do NOT reboot device during investigation - volatile data will be lost",
		"RECOMMENDED: Device should be isolated from network prior to examination",
		"NX-OS Investigation: VDC isolation and process enumeration required",
		"Storage Analysis: Check both volatile and persistent storage locations",
	}

	// Execute all forensic commands in sequence
	commands := c.getCommandSet()
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
	c.parseAndPopulateData(result)

	// Print manual forensic procedures if full command set was used
	if c.CommandSet == "full" {
		c.printManualProcedures()
	}

	return result, nil
}

// Connect establishes SSH connection to the NX-OS device
func (c *NXOSCollector) Connect() error {
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

	c.client, err = ssh.Dial("tcp", fmt.Sprintf("%s:22", c.Target), config)
	if err != nil {
		return fmt.Errorf("failed to connect to %s:22: %w", c.Target, err)
	}

	c.connected = true
	return nil
}

// EnablePrivilegedMode enables privileged mode on the device
func (c *NXOSCollector) EnablePrivilegedMode() error {
	// Check if already in privileged mode
	if output, err := c.ExecuteCommand("show privilege"); err == nil {
		if strings.Contains(output, "privilege level is 15") {
			return nil
		}
	}

	// Enable privileged mode
	if _, err := c.ExecuteCommand("enable"); err != nil {
		return fmt.Errorf("failed to enable privileged mode: %w", err)
	}

	return nil
}

// ExecuteCommand runs a single command on the device
func (c *NXOSCollector) ExecuteCommand(command string) (string, error) {
	if !c.connected {
		return "", fmt.Errorf("not connected to device")
	}

	session, err := c.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	// Set up terminal
	if err := session.RequestPty("vt100", 80, 24, ssh.TerminalModes{}); err != nil {
		return "", fmt.Errorf("failed to request pty: %w", err)
	}

	output, err := session.CombinedOutput(command)
	if err != nil {
		return "", fmt.Errorf("command failed: %w", err)
	}

	return string(output), nil
}

// Disconnect closes the SSH connection
func (c *NXOSCollector) Disconnect() error {
	if c.connected && c.client != nil {
		c.connected = false
		return c.client.Close()
	}
	return nil
}

// ValidateConnection tests if the connection is working properly
func (c *NXOSCollector) ValidateConnection() error {
	_, err := c.ExecuteCommand("show version | include Cisco")
	return err
}

// GetSupportedCommands returns the list of commands this collector can execute
func (c *NXOSCollector) GetSupportedCommands() []string {
	commands := c.getCommandSet()
	result := make([]string, len(commands))
	for i, cmd := range commands {
		result[i] = cmd.Command
	}
	return result
}

// parseAndPopulateData parses collected command outputs into structured data
func (c *NXOSCollector) parseAndPopulateData(state *core.DeviceState) {
	// Parse device info from show version
	for _, rawCmd := range state.RawCommands {
		if strings.Contains(rawCmd.Command, "show version") && rawCmd.ExitCode == 0 {
			if deviceInfo, err := c.parser.ParseVersion(rawCmd.Output); err == nil {
				state.DeviceInfo = *deviceInfo
			}
			break
		}
	}

	// Initialize forensic data structure if not already done
	if state.ForensicData == nil {
		state.ForensicData = make(map[string]interface{})
	}

	// Parse all structured data from raw command outputs
	for _, rawCmd := range state.RawCommands {
		if rawCmd.ExitCode != 0 {
			continue // Skip failed commands
		}

		// Parse based on command type
		var parsedData interface{}
		var err error
		var dataKey string

		switch {
		// Process Information
		case strings.Contains(rawCmd.Command, "show processes"):
			if parsedData, err = c.parser.ParseProcesses(rawCmd.Output); err == nil {
				if strings.Contains(rawCmd.Command, "cpu") {
					dataKey = "processes_cpu"
				} else if strings.Contains(rawCmd.Command, "memory") {
					dataKey = "processes_memory"
				} else {
					dataKey = "processes"
				}
			}

		// Network Connections
		case strings.Contains(rawCmd.Command, "show socket connection") || strings.Contains(rawCmd.Command, "show system internal tcp"):
			if parsedData, err = c.parser.ParseSocketConnections(rawCmd.Output); err == nil {
				dataKey = "network_connections"
			}

		// Interface Information
		case strings.Contains(rawCmd.Command, "show interface"):
			if parsedData, err = c.parser.ParseInterfaces(rawCmd.Output); err == nil {
				if strings.Contains(rawCmd.Command, "brief") {
					dataKey = "interfaces_brief"
				} else if strings.Contains(rawCmd.Command, "status") {
					dataKey = "interfaces_status"
				} else {
					dataKey = "interfaces"
				}
			}

		// VDC Information
		case strings.Contains(rawCmd.Command, "show vdc"):
			if parsedData, err = c.parser.ParseVDC(rawCmd.Output); err == nil {
				if strings.Contains(rawCmd.Command, "membership") {
					dataKey = "vdc_membership"
				} else if strings.Contains(rawCmd.Command, "resource") {
					dataKey = "vdc_resources"
				} else {
					dataKey = "vdc_info"
				}
			}

		// Virtual Services and Guest Shell
		case strings.Contains(rawCmd.Command, "show virtual-service"):
			if parsedData, err = c.parser.ParseVirtualServices(rawCmd.Output); err == nil {
				dataKey = "virtual_services"
			}

		case strings.Contains(rawCmd.Command, "show guestshell"):
			if parsedData, err = c.parser.ParseGuestShell(rawCmd.Output); err == nil {
				dataKey = "guestshell"
			}

		// Core Files
		case strings.Contains(rawCmd.Command, "show cores"):
			if parsedData, err = c.parser.ParseCoreFiles(rawCmd.Output); err == nil {
				dataKey = "core_files"
			}

		// Features
		case strings.Contains(rawCmd.Command, "show feature"):
			if parsedData, err = c.parser.ParseFeatures(rawCmd.Output); err == nil {
				dataKey = "features"
			}

		// Modules
		case strings.Contains(rawCmd.Command, "show module"):
			if parsedData, err = c.parser.ParseModules(rawCmd.Output); err == nil {
				dataKey = "modules"
			}

		// System Logs
		case strings.Contains(rawCmd.Command, "show logging"):
			if parsedData, err = c.parser.ParseSystemLogs(rawCmd.Output); err == nil {
				if strings.Contains(rawCmd.Command, "logfile") {
					dataKey = "system_logs"
				} else if strings.Contains(rawCmd.Command, "last") {
					dataKey = "recent_logs"
				} else {
					dataKey = "logging"
				}
			}

		// User Sessions
		case strings.Contains(rawCmd.Command, "show users"):
			if parsedData, err = c.parser.ParseSessions(rawCmd.Output); err == nil {
				dataKey = "user_sessions"
			}

		// Routing Information
		case strings.Contains(rawCmd.Command, "show ip route"):
			if parsedData, err = c.parser.ParseRoutes(rawCmd.Output); err == nil {
				if strings.Contains(rawCmd.Command, "summary") {
					dataKey = "route_summary"
				} else {
					dataKey = "routes"
				}
			}

		// Software Authenticity
		case strings.Contains(rawCmd.Command, "show software authenticity running"):
			if parsedData, err = c.parser.ParseSoftwareAuthenticity(rawCmd.Output); err == nil {
				dataKey = "software_authenticity"
			}

		case strings.Contains(rawCmd.Command, "show software authenticity keys"):
			if parsedData, err = c.parser.ParseAuthenticityKeys(rawCmd.Output); err == nil {
				dataKey = "authenticity_keys"
			}

		// Boot Information
		case strings.Contains(rawCmd.Command, "show boot"):
			if parsedData, err = c.parser.ParseBootInfo(rawCmd.Output); err == nil {
				dataKey = "boot_info"
			}

		// Install Information
		case strings.Contains(rawCmd.Command, "show install"):
			if parsedData, err = c.parser.ParseInstallInfo(rawCmd.Output); err == nil {
				dataKey = "install_info"
			}

		// Directory Listings
		case strings.Contains(rawCmd.Command, "dir"):
			if parsedData, err = c.parser.ParseDirectoryListing(rawCmd.Output); err == nil {
				if strings.Contains(rawCmd.Command, "volatile:") {
					dataKey = "volatile_storage"
				} else if strings.Contains(rawCmd.Command, "bootflash:") {
					dataKey = "bootflash_storage"
				} else if strings.Contains(rawCmd.Command, "recursive") {
					dataKey = "directory_recursive"
				} else {
					dataKey = "directory_listing"
				}
			}

		// System Internal Commands
		case strings.Contains(rawCmd.Command, "show system internal"):
			if parsedData, err = c.parser.ParseSystemInternal(rawCmd.Output); err == nil {
				if strings.Contains(rawCmd.Command, "kernel") {
					dataKey = "kernel_info"
				} else if strings.Contains(rawCmd.Command, "platform") {
					dataKey = "platform_info"
				} else if strings.Contains(rawCmd.Command, "event-history") {
					if strings.Contains(rawCmd.Command, "errors") {
						dataKey = "error_history"
					} else if strings.Contains(rawCmd.Command, "cli") {
						dataKey = "cli_history"
					} else {
						dataKey = "event_history"
					}
				} else {
					dataKey = "system_internal"
				}
			}

		// Tech Support
		case strings.Contains(rawCmd.Command, "show tech-support"):
			if parsedData, err = c.parser.ParseTechSupport(rawCmd.Output); err == nil {
				dataKey = "tech_support"
			}

		// Configuration Commands
		case strings.Contains(rawCmd.Command, "show running-config"):
			// Store as raw data for configuration analysis
			parsedData = map[string]interface{}{
				"config_type": "running",
				"content":     rawCmd.Output,
				"size":        len(rawCmd.Output),
				"parsed_at":   time.Now(),
			}
			dataKey = "running_config"

		case strings.Contains(rawCmd.Command, "show startup-config"):
			// Store as raw data for configuration analysis
			parsedData = map[string]interface{}{
				"config_type": "startup",
				"content":     rawCmd.Output,
				"size":        len(rawCmd.Output),
				"parsed_at":   time.Now(),
			}
			dataKey = "startup_config"

		// Default: Store as raw data with metadata
		default:
			// Create a generic parsed data structure for unspecified commands
			parsedData = map[string]interface{}{
				"command":      rawCmd.Command,
				"output":       rawCmd.Output,
				"timestamp":    rawCmd.Timestamp,
				"duration":     rawCmd.Duration,
				"output_size":  len(rawCmd.Output),
				"forensic_raw": true,
			}
			// Create a safe key name from the command
			dataKey = strings.ReplaceAll(strings.ReplaceAll(rawCmd.Command, " ", "_"), ":", "_")
		}

		// Store parsed data if successful
		if err == nil && parsedData != nil && dataKey != "" {
			state.ForensicData[dataKey] = parsedData
		} else if err != nil {
			// Log parsing errors but don't fail collection
			state.Metadata.Warnings = append(state.Metadata.Warnings,
				fmt.Sprintf("Failed to parse command '%s': %v", rawCmd.Command, err))
		}
	}

	// Add forensic summary
	state.ForensicData["collection_summary"] = map[string]interface{}{
		"total_commands_executed": len(state.RawCommands),
		"successful_commands":     state.Metadata.SuccessfulCommands,
		"failed_commands":         state.Metadata.FailedCommands,
		"parsed_data_fields":      len(state.ForensicData),
		"collection_time":         state.Metadata.CollectionTime,
		"forensic_compliance":     "Cisco NX-OS Software Forensic Data Collection Procedures",
	}
}

// Command represents a forensic command to execute
type Command struct {
	Command string
	Parser  string
	Timeout time.Duration
}

// getCommandSet returns the complete set of forensic commands based on configuration
func (c *NXOSCollector) getCommandSet() []Command {
	// Core forensic commands based on Cisco NX-OS Forensic Data Collection Procedures
	coreCommands := []Command{
		// Device Information and State
		{Command: "show version", Parser: "version", Timeout: 30 * time.Second},
		{Command: "show inventory", Parser: "inventory", Timeout: 30 * time.Second},
		{Command: "show module", Parser: "modules", Timeout: 30 * time.Second},
		{Command: "show environment", Parser: "environment", Timeout: 30 * time.Second},
		{Command: "show clock", Parser: "clock", Timeout: 10 * time.Second},

		// System and Process Information
		{Command: "show system internal kernel info", Parser: "kernel_info", Timeout: 60 * time.Second},
		{Command: "show system internal processes", Parser: "processes", Timeout: 60 * time.Second},
		{Command: "show system internal platform software process list", Parser: "platform_processes", Timeout: 60 * time.Second},
		{Command: "show processes", Parser: "user_processes", Timeout: 30 * time.Second},
		{Command: "show processes cpu", Parser: "process_cpu", Timeout: 30 * time.Second},
		{Command: "show processes memory", Parser: "process_memory", Timeout: 30 * time.Second},

		// Network and Interface Information
		{Command: "show interface brief", Parser: "interfaces", Timeout: 30 * time.Second},
		{Command: "show interface status", Parser: "interface_status", Timeout: 30 * time.Second},
		{Command: "show ip interface brief", Parser: "ip_interfaces", Timeout: 30 * time.Second},
		{Command: "show mac address-table", Parser: "mac_table", Timeout: 30 * time.Second},
		{Command: "show arp", Parser: "arp_table", Timeout: 30 * time.Second},

		// Routing and Network State
		{Command: "show ip route", Parser: "routes", Timeout: 60 * time.Second},
		{Command: "show ip route summary", Parser: "route_summary", Timeout: 30 * time.Second},
		{Command: "show forwarding adjacency", Parser: "adjacencies", Timeout: 60 * time.Second},
		{Command: "show forwarding route", Parser: "forwarding_table", Timeout: 60 * time.Second},

		// Security and Access Information
		{Command: "show users", Parser: "sessions", Timeout: 30 * time.Second},
		{Command: "show ssh server", Parser: "ssh_config", Timeout: 30 * time.Second},
		{Command: "show aaa accounting log", Parser: "aaa_logs", Timeout: 30 * time.Second},
		{Command: "show role", Parser: "roles", Timeout: 30 * time.Second},

		// File System and Storage
		{Command: "dir", Parser: "directory", Timeout: 60 * time.Second},
		{Command: "dir volatile:", Parser: "volatile_storage", Timeout: 60 * time.Second},
		{Command: "dir bootflash:", Parser: "bootflash", Timeout: 60 * time.Second},
		{Command: "show cores", Parser: "core_files", Timeout: 30 * time.Second},

		// System Logs and Events
		{Command: "show logging logfile", Parser: "system_logs", Timeout: 120 * time.Second},
		{Command: "show logging last 1000", Parser: "recent_logs", Timeout: 60 * time.Second},
		{Command: "show system internal event-history errors", Parser: "error_history", Timeout: 60 * time.Second},
		{Command: "show system internal event-history cli", Parser: "cli_history", Timeout: 60 * time.Second},

		// VDC and Virtualization (if applicable)
		{Command: "show vdc", Parser: "vdc_info", Timeout: 30 * time.Second},
		{Command: "show vdc membership", Parser: "vdc_membership", Timeout: 30 * time.Second},
		{Command: "show vdc resource", Parser: "vdc_resources", Timeout: 30 * time.Second},

		// Hardware and System Health
		{Command: "show hardware", Parser: "hardware_info", Timeout: 60 * time.Second},
		{Command: "show system resources", Parser: "system_resources", Timeout: 30 * time.Second},
		{Command: "show system uptime", Parser: "uptime", Timeout: 10 * time.Second},

		// Configuration and Management
		{Command: "show running-config", Parser: "running_config", Timeout: 120 * time.Second},
		{Command: "show startup-config", Parser: "startup_config", Timeout: 60 * time.Second},
		{Command: "show configuration session summary", Parser: "config_sessions", Timeout: 30 * time.Second},

		// Network Services and Protocols
		{Command: "show ip arp inspection log", Parser: "arp_inspection", Timeout: 30 * time.Second},
		{Command: "show ip dhcp snooping", Parser: "dhcp_snooping", Timeout: 30 * time.Second},
		{Command: "show spanning-tree", Parser: "spanning_tree", Timeout: 60 * time.Second},

		// Feature and License Information
		{Command: "show feature", Parser: "features", Timeout: 30 * time.Second},
		{Command: "show license", Parser: "licenses", Timeout: 30 * time.Second},
		{Command: "show install all", Parser: "install_history", Timeout: 60 * time.Second},

		// File system enumeration for malicious file detection
		{Command: "dir /recursive", Parser: "directory_recursive", Timeout: 120 * time.Second},
		{Command: "dir /recursive bootflash: | include .sh|.py|.pl|.exe|.bin", Parser: "suspicious_files", Timeout: 90 * time.Second},
		{Command: "dir volatile: /recursive", Parser: "volatile_recursive", Timeout: 90 * time.Second},
		{Command: "dir logflash: /recursive", Parser: "logflash_recursive", Timeout: 90 * time.Second},
		{Command: "show file systems", Parser: "filesystems", Timeout: 30 * time.Second},
		{Command: "dir slot0: /recursive", Parser: "slot0_recursive", Timeout: 90 * time.Second},
		{Command: "show system internal platform software mount", Parser: "mount_points", Timeout: 30 * time.Second},

		// Network connection monitoring for C2 detection
		{Command: "show socket connection all", Parser: "socket_connections", Timeout: 60 * time.Second},
		{Command: "show system internal tcp brief", Parser: "tcp_connections", Timeout: 45 * time.Second},
		{Command: "show system internal udp brief", Parser: "udp_connections", Timeout: 45 * time.Second},
		{Command: "show ip socket", Parser: "ip_sockets", Timeout: 45 * time.Second},
		{Command: "show system internal netstat -an", Parser: "netstat_all", Timeout: 60 * time.Second},
		{Command: "show ip arp", Parser: "arp_table", Timeout: 30 * time.Second},
		{Command: "show mac address-table", Parser: "mac_table", Timeout: 45 * time.Second},
		{Command: "show interface brief", Parser: "interface_brief", Timeout: 30 * time.Second},

		// Enhanced process analysis for privilege escalation detection
		{Command: "show system internal processes all", Parser: "all_processes", Timeout: 90 * time.Second},
		{Command: "show processes cpu sorted", Parser: "cpu_sorted_processes", Timeout: 45 * time.Second},
		{Command: "show processes memory sorted", Parser: "memory_sorted_processes", Timeout: 45 * time.Second},
		{Command: "show system internal platform software process list detail", Parser: "detailed_processes", Timeout: 90 * time.Second},
		{Command: "show system internal kernel process", Parser: "kernel_processes", Timeout: 60 * time.Second},
		{Command: "show system internal platform software process summary", Parser: "process_summary", Timeout: 45 * time.Second},
		{Command: "show processes log", Parser: "process_logs", Timeout: 60 * time.Second},
		{Command: "show system internal sysmgr service all", Parser: "system_services", Timeout: 60 * time.Second},

		// ...existing code...
	}

	switch c.CommandSet {
	case "minimal":
		// Return only essential forensic commands for quick collection
		return []Command{
			{Command: "show version", Parser: "version", Timeout: 30 * time.Second},
			{Command: "show processes", Parser: "processes", Timeout: 30 * time.Second},
			{Command: "show users", Parser: "sessions", Timeout: 30 * time.Second},
			{Command: "show logging last 100", Parser: "recent_logs", Timeout: 30 * time.Second},
			{Command: "dir", Parser: "directory", Timeout: 30 * time.Second},
		}
	case "standard":
		// Return standard forensic command set
		return coreCommands[:len(coreCommands)/2] // First half of commands
	case "full":
		fallthrough
	default:
		// Return all forensic commands for thorough investigation
		return coreCommands
	}
}

// printManualProcedures displays additional manual forensic procedures required for NX-OS
func (c *NXOSCollector) printManualProcedures() {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("🔧 MANUAL FORENSIC PROCEDURES REQUIRED FOR CISCO NX-OS")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("The following procedures require manual execution to complete")
	fmt.Println("forensic compliance per official Cisco NX-OS procedures:")
	fmt.Println()

	fmt.Println("1. CORE FILE GENERATION")
	fmt.Println("   Command: system cores save")
	fmt.Println("   ℹ️  Impact: Minimal impact on running system")
	fmt.Println("   📋 Evidence: Process and kernel memory analysis")
	fmt.Println()

	fmt.Println("2. GUEST SHELL MEMORY ANALYSIS")
	fmt.Println("   Commands:")
	fmt.Println("     run bash sudo")
	fmt.Println("     ps aux")
	fmt.Println("     cat /proc/*/maps")
	fmt.Println("   🔌 Access: Guest shell access required")
	fmt.Println("   📋 Evidence: Container security analysis")
	fmt.Println()

	fmt.Println("3. VDC CONTEXT ANALYSIS")
	fmt.Println("   Commands:")
	fmt.Println("     switchto vdc [vdc-name]")
	fmt.Println("     show vdc membership")
	fmt.Println("   📋 Evidence: Virtual Device Context isolation verification")
	fmt.Println()

	fmt.Println("4. SOFTWARE AUTHENTICITY VERIFICATION")
	fmt.Println("   Commands:")
	fmt.Println("     show software authenticity running")
	fmt.Println("     show software authenticity bootflash:")
	fmt.Println("   📋 Evidence: Digital signature and image integrity")
	fmt.Println()

	fmt.Println("⚠️  CRITICAL REMINDERS:")
	fmt.Println("   • Guest shell analysis requires bash access")
	fmt.Println("   • VDC context switching may be required")
	fmt.Println("   • Verify container isolation integrity")
	fmt.Println("   • Document all manual procedures in chain of custody")
	fmt.Println(strings.Repeat("=", 80) + "\n")
}
