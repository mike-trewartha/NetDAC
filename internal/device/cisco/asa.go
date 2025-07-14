package cisco

import (
	"fmt"
	"strings"
	"time"

	"netdac/internal/core"

	"golang.org/x/crypto/ssh"
)

// ASACollector implements forensically sound data collection for Cisco ASA devices
// following the official Cisco ASA Forensic Data Collection Procedures
// https://sec.cloudapps.cisco.com/security/center/resources/forensic_guides/asa_forensic_investigation.html
type ASACollector struct {
	Target     string
	Username   string
	Password   string
	Timeout    time.Duration
	CommandSet string

	client    *ssh.Client
	session   *ssh.Session
	parser    *ASAParser
	connected bool
}

// NewASACollector creates a new ASA collector instance
func NewASACollector(target, username, password string, timeout time.Duration) *ASACollector {
	return &ASACollector{
		Target:    target,
		Username:  username,
		Password:  password,
		Timeout:   timeout,
		parser:    NewASAParser(),
		connected: false,
	}
}

// Collect performs comprehensive forensic data collection from ASA device
// Following Cisco ASA Software Forensic Data Collection Procedures (7 Steps)
func (c *ASACollector) Collect() (*core.DeviceState, error) {
	if err := c.Connect(); err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer c.Disconnect()

	// Enable privileged mode - required for all ASA forensic commands
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

	// Add forensic collection warnings specific to ASA
	result.Metadata.Warnings = []string{
		"FORENSIC COLLECTION: Following Cisco ASA Software Forensic Data Collection Procedures",
		"CRITICAL: Do NOT reboot device during investigation - volatile data will be lost",
		"RECOMMENDED: Device should be isolated from network prior to examination",
		"ASA Investigation: Image integrity verification and digital signature validation required",
		"CAUTION: Core dump collection (Step 5) will trigger device reload",
		"ROM Monitor: Check for unauthorized boot sequence modifications",
		"SSL VPN: Verify portal configuration and plugin integrity if enabled",
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

	// Print manual forensic procedures if comprehensive command set was used
	if c.CommandSet == "full" {
		c.printManualProcedures()
	}

	return result, nil
}

// Connect establishes SSH connection to the ASA device
func (c *ASACollector) Connect() error {
	if c.connected {
		return nil
	}

	config := &ssh.ClientConfig{
		User:            c.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(c.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         c.Timeout,
	}

	var err error
	c.client, err = ssh.Dial("tcp", fmt.Sprintf("%s:22", c.Target), config)
	if err != nil {
		return fmt.Errorf("failed to connect to %s:22: %w", c.Target, err)
	}

	c.connected = true
	return nil
}

// EnablePrivilegedMode enables privileged mode on the ASA device
func (c *ASACollector) EnablePrivilegedMode() error {
	// Enable privileged mode
	if _, err := c.ExecuteCommand("enable"); err != nil {
		return fmt.Errorf("failed to enable privileged mode: %w", err)
	}

	// Disable terminal pager for consistent output
	if _, err := c.ExecuteCommand("terminal pager 0"); err != nil {
		return fmt.Errorf("failed to disable terminal pager: %w", err)
	}

	return nil
}

// ExecuteCommand runs a single command on the device
func (c *ASACollector) ExecuteCommand(command string) (string, error) {
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
func (c *ASACollector) Disconnect() error {
	if c.connected && c.client != nil {
		c.connected = false
		return c.client.Close()
	}
	return nil
}

// ValidateConnection tests if the connection is working properly
func (c *ASACollector) ValidateConnection() error {
	_, err := c.ExecuteCommand("show version | include Cisco")
	return err
}

// GetSupportedCommands returns the list of commands this collector can execute
func (c *ASACollector) GetSupportedCommands() []string {
	commands := c.getCommandSet()
	result := make([]string, len(commands))
	for i, cmd := range commands {
		result[i] = cmd.Command
	}
	return result
}

// parseAndPopulateData parses collected command outputs into structured data
func (c *ASACollector) parseAndPopulateData(state *core.DeviceState) {
	// Parse device info from show version
	for _, rawCmd := range state.RawCommands {
		if strings.Contains(rawCmd.Command, "show version") && rawCmd.ExitCode == 0 {
			if deviceInfo, err := c.parser.ParseVersion(rawCmd.Output); err == nil {
				state.DeviceInfo = *deviceInfo
			}
			break
		}
	}

	// Parse other structured data...
	// This would parse connections, processes, interfaces, etc. from the raw command outputs
}

// ASACommand represents a forensic command to execute
type ASACommand struct {
	Command string
	Parser  string
	Timeout time.Duration
}

// getCommandSet returns the complete set of forensic commands based on configuration
// Following Cisco ASA Software Forensic Data Collection Procedures (7 Steps)
func (c *ASACollector) getCommandSet() []ASACommand {
	// Core forensic commands based on Cisco ASA Forensic Data Collection Procedures
	coreCommands := []ASACommand{
		// Step 2: ASA Runtime Environment Collection (CRITICAL)
		{Command: "show tech-support detail", Parser: "tech_support", Timeout: 300 * time.Second},
		{Command: "dir /recursive all-filesystems", Parser: "filesystem_all", Timeout: 120 * time.Second},
		{Command: "dir /recursive cache:", Parser: "filesystem_cache", Timeout: 60 * time.Second},

		// Step 2: Additional runtime environment (optional but recommended)
		{Command: "show history", Parser: "command_history", Timeout: 30 * time.Second},
		{Command: "show clock detail", Parser: "clock", Timeout: 10 * time.Second},
		{Command: "show startup-config", Parser: "startup_config", Timeout: 60 * time.Second},
		{Command: "show reload", Parser: "reload_info", Timeout: 30 * time.Second},
		{Command: "show processes", Parser: "processes", Timeout: 30 * time.Second},
		{Command: "show kernel process detail", Parser: "kernel_processes", Timeout: 30 * time.Second},
		{Command: "show kernel ifconfig", Parser: "kernel_interfaces", Timeout: 30 * time.Second},
		{Command: "show kernel module", Parser: "kernel_modules", Timeout: 30 * time.Second},
		{Command: "show logging", Parser: "system_logs", Timeout: 60 * time.Second},
		{Command: "show route", Parser: "routes", Timeout: 30 * time.Second},
		{Command: "show arp", Parser: "arp", Timeout: 30 * time.Second},
		{Command: "show ip address", Parser: "ip_addresses", Timeout: 30 * time.Second},
		{Command: "show interface ip brief", Parser: "interfaces", Timeout: 30 * time.Second},
		{Command: "show nat detail", Parser: "nat_translations", Timeout: 30 * time.Second},
		{Command: "show conn all", Parser: "connections", Timeout: 60 * time.Second},
		{Command: "show xlate", Parser: "xlate_table", Timeout: 30 * time.Second},
		{Command: "show aaa login-history", Parser: "login_history", Timeout: 30 * time.Second},

		// Step 3: ASA Image File Hash Verification
		{Command: "show version", Parser: "version", Timeout: 30 * time.Second},
		// Note: verify commands are dynamic based on detected images from show version

		// Step 4: Digitally Signed Image Verification
		{Command: "show software authenticity running", Parser: "auth_running", Timeout: 30 * time.Second},
		{Command: "show software authenticity keys", Parser: "auth_keys", Timeout: 30 * time.Second},
		// Note: show software authenticity file commands are dynamic

		// Step 5: Memory .text Segment Verification (for memory dump)
		{Command: "verify /sha-512 system:memory/text", Parser: "memory_text_hash", Timeout: 60 * time.Second},

		// Step 7: SSL VPN Configuration Integrity Check
		{Command: "show run | begin webvpn", Parser: "webvpn_config", Timeout: 30 * time.Second},
		{Command: "show import webvpn plug-in detail", Parser: "webvpn_plugins", Timeout: 30 * time.Second},

		// Additional system information for forensic analysis
		{Command: "show hostname", Parser: "hostname", Timeout: 10 * time.Second},
		{Command: "show memory", Parser: "memory", Timeout: 30 * time.Second},
		{Command: "show cpu usage", Parser: "cpu", Timeout: 30 * time.Second},
		{Command: "show snmp-server user", Parser: "snmp_users", Timeout: 30 * time.Second},
		{Command: "show snmp-server group", Parser: "snmp_groups", Timeout: 30 * time.Second},
		{Command: "show ipv6 interface brief", Parser: "ipv6_interfaces", Timeout: 30 * time.Second},
		{Command: "show ipv6 route", Parser: "ipv6_routes", Timeout: 30 * time.Second},

		// File system analysis
		{Command: "dir all-filesystems", Parser: "filesystem_basic", Timeout: 60 * time.Second},
		{Command: "dir disk0:", Parser: "disk0_listing", Timeout: 30 * time.Second},
		{Command: "dir bootflash:", Parser: "bootflash_listing", Timeout: 30 * time.Second},

		// Security and access control
		{Command: "show access-list", Parser: "access_lists", Timeout: 60 * time.Second},
		{Command: "show running-config", Parser: "running_config", Timeout: 120 * time.Second},
		{Command: "show users", Parser: "sessions", Timeout: 30 * time.Second},
		{Command: "show ssh", Parser: "ssh_sessions", Timeout: 30 * time.Second},

		// Hardware and environment (if supported)
		{Command: "show module", Parser: "modules", Timeout: 30 * time.Second},
		{Command: "show environment", Parser: "environment", Timeout: 30 * time.Second},
		{Command: "show inventory", Parser: "inventory", Timeout: 30 * time.Second},
		{Command: "show hardware", Parser: "hardware", Timeout: 30 * time.Second},

		// Routing protocol neighbors
		{Command: "show eigrp neighbor", Parser: "eigrp_neighbors", Timeout: 30 * time.Second},
		{Command: "show ospf neighbor", Parser: "ospf_neighbors", Timeout: 30 * time.Second},
		{Command: "show bgp summary", Parser: "bgp_summary", Timeout: 30 * time.Second},

		// File system enumeration for malicious file detection
		{Command: "dir /recursive disk0: | include .sh|.py|.pl|.exe|.bin", Parser: "suspicious_files_disk0", Timeout: 90 * time.Second},
		{Command: "dir /recursive flash: | include .sh|.py|.pl|.exe|.bin", Parser: "suspicious_files_flash", Timeout: 90 * time.Second},
		{Command: "show file systems", Parser: "available_filesystems", Timeout: 30 * time.Second},
		{Command: "dir coredumpinfo:", Parser: "coredump_files", Timeout: 30 * time.Second},
		{Command: "dir /recursive system:", Parser: "system_files", Timeout: 60 * time.Second},
		{Command: "show file descriptors", Parser: "open_files", Timeout: 30 * time.Second},
		{Command: "show module all", Parser: "loaded_modules", Timeout: 30 * time.Second},

		// Network connection monitoring for C2 detection
		{Command: "show conn detail all", Parser: "connections_detailed", Timeout: 90 * time.Second},
		{Command: "show conn count", Parser: "connection_counts", Timeout: 30 * time.Second},
		{Command: "show local-host all", Parser: "local_hosts", Timeout: 60 * time.Second},
		{Command: "show route summary", Parser: "route_summary", Timeout: 30 * time.Second},
		{Command: "show vpn-sessiondb summary", Parser: "vpn_sessions", Timeout: 30 * time.Second},
		{Command: "show vpn-sessiondb detail anyconnect", Parser: "anyconnect_sessions", Timeout: 45 * time.Second},
		{Command: "show socket all", Parser: "socket_connections", Timeout: 45 * time.Second},
		{Command: "show tcp-map", Parser: "tcp_mappings", Timeout: 30 * time.Second},

		// Enhanced process analysis for privilege escalation detection
		{Command: "show processes cpu-usage sorted", Parser: "processes_cpu_sorted", Timeout: 45 * time.Second},
		{Command: "show processes memory-usage sorted", Parser: "processes_memory_sorted", Timeout: 45 * time.Second},
		{Command: "show kernel process all", Parser: "kernel_processes_all", Timeout: 60 * time.Second},
		{Command: "show kernel module detail", Parser: "kernel_modules_detail", Timeout: 45 * time.Second},
		{Command: "show kernel route", Parser: "kernel_routing", Timeout: 30 * time.Second},
		{Command: "show blocks old 0", Parser: "memory_blocks", Timeout: 45 * time.Second},
		{Command: "show memory detail", Parser: "memory_detail", Timeout: 45 * time.Second},
		{Command: "show resource usage", Parser: "resource_usage", Timeout: 30 * time.Second},

		// ...existing code...
	}

	switch c.CommandSet {
	case "minimal":
		// Return only essential forensic commands for quick collection
		return []ASACommand{
			{Command: "show version", Parser: "version", Timeout: 30 * time.Second},
			{Command: "show tech-support detail", Parser: "tech_support", Timeout: 180 * time.Second},
			{Command: "show software authenticity running", Parser: "auth_running", Timeout: 30 * time.Second},
			{Command: "show processes", Parser: "processes", Timeout: 30 * time.Second},
			{Command: "show conn all", Parser: "connections", Timeout: 30 * time.Second},
			{Command: "show logging | tail 100", Parser: "recent_logs", Timeout: 30 * time.Second},
			{Command: "dir all-filesystems", Parser: "filesystem_basic", Timeout: 60 * time.Second},
		}
	case "standard":
		// Return standard forensic command set (Steps 2-4 of official procedures)
		return []ASACommand{
			// Step 2: Runtime Environment (Core)
			{Command: "show version", Parser: "version", Timeout: 30 * time.Second},
			{Command: "show tech-support detail", Parser: "tech_support", Timeout: 300 * time.Second},
			{Command: "dir /recursive all-filesystems", Parser: "filesystem_all", Timeout: 120 * time.Second},
			{Command: "dir /recursive cache:", Parser: "filesystem_cache", Timeout: 60 * time.Second},

			// Step 4: Digital Signature Verification
			{Command: "show software authenticity running", Parser: "auth_running", Timeout: 30 * time.Second},
			{Command: "show software authenticity keys", Parser: "auth_keys", Timeout: 30 * time.Second},

			// Essential System State
			{Command: "show processes", Parser: "processes", Timeout: 30 * time.Second},
			{Command: "show conn all", Parser: "connections", Timeout: 60 * time.Second},
			{Command: "show interface ip brief", Parser: "interfaces", Timeout: 30 * time.Second},
			{Command: "show route", Parser: "routes", Timeout: 30 * time.Second},
			{Command: "show logging", Parser: "system_logs", Timeout: 60 * time.Second},
			{Command: "show users", Parser: "sessions", Timeout: 30 * time.Second},
			{Command: "show access-list", Parser: "access_lists", Timeout: 60 * time.Second},
			{Command: "show running-config", Parser: "running_config", Timeout: 120 * time.Second},
			{Command: "show nat detail", Parser: "nat_translations", Timeout: 30 * time.Second},

			// SSL VPN Check (if applicable)
			{Command: "show run | begin webvpn", Parser: "webvpn_config", Timeout: 30 * time.Second},
		}
	case "full":
		fallthrough
	default:
		// Return all forensic commands for thorough investigation (Full Steps 2-7)
		return coreCommands
	}
}

// printManualProcedures displays additional manual forensic procedures required
func (c *ASACollector) printManualProcedures() {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("🔧 MANUAL FORENSIC PROCEDURES REQUIRED FOR CISCO ASA")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("The following procedures require manual execution to complete")
	fmt.Println("forensic compliance per official Cisco ASA procedures:")
	fmt.Println()

	fmt.Println("1. CORE DUMP COLLECTION (Step 5)")
	fmt.Println("   Command: write core disk0:asa-core-dump.bin")
	fmt.Println("   ⚠️  CAUTION: Device reload required (~5-10 minutes downtime)")
	fmt.Println("   📋 Evidence: Complete memory dump for advanced malware analysis")
	fmt.Println()

	fmt.Println("2. ROM MONITOR VERIFICATION (Console Access Required)")
	fmt.Println("   Commands: confreg, boot")
	fmt.Println("   🔌 Access: Serial console port required")
	fmt.Println("   📋 Evidence: Boot sequence integrity verification")
	fmt.Println()

	fmt.Println("3. SSL VPN CONFIGURATION FILE INTEGRITY")
	fmt.Println("   Commands:")
	fmt.Println("     more disk0:sdeskmgr/")
	fmt.Println("     verify /md5 disk0:sdeskmgr/*")
	fmt.Println("   📋 Evidence: SSL VPN plugin integrity verification")
	fmt.Println()

	fmt.Println("⚠️  CRITICAL REMINDERS:")
	fmt.Println("   • Plan core dump collection during maintenance windows")
	fmt.Println("   • Console access required for ROM monitor verification")
	fmt.Println("   • Document all manual procedures in chain of custody")
	fmt.Println("   • Verify device isolation before advanced procedures")
	fmt.Println(strings.Repeat("=", 80) + "\n")
}
