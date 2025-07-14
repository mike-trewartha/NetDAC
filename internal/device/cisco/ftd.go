package cisco

import (
	"fmt"
	"strings"
	"time"

	"netdac/internal/core"

	"golang.org/x/crypto/ssh"
)

// FTDCollector implements forensically sound data collection for Cisco ASA 5500-X series firewalls
// running Firepower Threat Defense (FTD) Software based on official Cisco FTD forensic procedures
// https://sec.cloudapps.cisco.com/security/center/resources/forensic_guides/ftd_forensic_investigation.html
type FTDCollector struct {
	Target     string
	Username   string
	Password   string
	Timeout    time.Duration
	CommandSet string

	client    *ssh.Client
	parser    *FTDParser
	connected bool
}

// NewFTDCollector creates a new FTD collector instance
func NewFTDCollector(target, username, password string, timeout time.Duration) *FTDCollector {
	return &FTDCollector{
		Target:    target,
		Username:  username,
		Password:  password,
		Timeout:   timeout,
		parser:    NewFTDParser(),
		connected: false,
	}
}

// Collect performs comprehensive forensic data collection from FTD device
// Following Cisco FTD Software Forensic Data Collection Procedures (7 Steps)
func (c *FTDCollector) Collect() (*core.DeviceState, error) {
	if err := c.Connect(); err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer c.Disconnect()

	// Enter diagnostic CLI mode - required for all forensic commands
	if err := c.EnterDiagnosticCLI(); err != nil {
		return nil, fmt.Errorf("failed to enter diagnostic CLI: %w", err)
	}

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

	// Add forensic collection warnings specific to FTD
	result.Metadata.Warnings = []string{
		"FORENSIC COLLECTION: Following Cisco FTD Software Forensic Data Collection Procedures",
		"CRITICAL: Do NOT reboot device during investigation - volatile data will be lost",
		"RECOMMENDED: Device should be isolated from network prior to examination",
		"FTD Investigation: Secure Boot and Trust Anchor verification required",
		"CAUTION: Crashinfo/Core dump collection (Step 6) will trigger device reload",
		"ROM Monitor: Check for unauthorized boot sequence modifications",
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

// Connect establishes SSH connection to the FTD device
func (c *FTDCollector) Connect() error {
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

// EnterDiagnosticCLI enters the FTD diagnostic CLI mode required for forensic commands
func (c *FTDCollector) EnterDiagnosticCLI() error {
	// Execute "system support diagnostic-cli" to enter diagnostic mode
	if _, err := c.ExecuteCommand("system support diagnostic-cli"); err != nil {
		return fmt.Errorf("failed to enter diagnostic CLI: %w", err)
	}
	return nil
}

// EnablePrivilegedMode enables privileged mode on the device
func (c *FTDCollector) EnablePrivilegedMode() error {
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
func (c *FTDCollector) ExecuteCommand(command string) (string, error) {
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
func (c *FTDCollector) Disconnect() error {
	if c.connected && c.client != nil {
		c.connected = false
		return c.client.Close()
	}
	return nil
}

// ValidateConnection tests if the connection is working properly
func (c *FTDCollector) ValidateConnection() error {
	_, err := c.ExecuteCommand("show version | include Cisco")
	return err
}

// GetSupportedCommands returns the list of commands this collector can execute
func (c *FTDCollector) GetSupportedCommands() []string {
	commands := c.getCommandSet()
	result := make([]string, len(commands))
	for i, cmd := range commands {
		result[i] = cmd.Command
	}
	return result
}

// parseAndPopulateData parses collected command outputs into structured data
func (c *FTDCollector) parseAndPopulateData(state *core.DeviceState) {
	// Parse device info from show version
	for _, rawCmd := range state.RawCommands {
		if strings.Contains(rawCmd.Command, "show version") && rawCmd.ExitCode == 0 {
			if deviceInfo, err := c.parser.ParseVersion(rawCmd.Output); err == nil {
				state.DeviceInfo = *deviceInfo
			}
			break
		}
	}

	// Parse other structured data from command outputs
	for _, rawCmd := range state.RawCommands {
		if rawCmd.ExitCode != 0 {
			continue // Skip failed commands
		}

		switch {
		case strings.Contains(rawCmd.Command, "show connection"):
			if connections, err := c.parser.ParseConnections(rawCmd.Output); err == nil {
				state.Connections = connections
			}

		case strings.Contains(rawCmd.Command, "show processes"):
			if processes, err := c.parser.ParseProcesses(rawCmd.Output); err == nil {
				state.Processes = processes
			}

		case strings.Contains(rawCmd.Command, "show interface"):
			if interfaces, err := c.parser.ParseInterfaces(rawCmd.Output); err == nil {
				state.Interfaces = interfaces
			}

		case strings.Contains(rawCmd.Command, "show route"):
			if routes, err := c.parser.ParseRoutes(rawCmd.Output); err == nil {
				state.Routes = routes
			}

		case strings.Contains(rawCmd.Command, "show users"):
			if sessions, err := c.parser.ParseSessions(rawCmd.Output); err == nil {
				state.Sessions = append(state.Sessions, sessions...)
			}

		case strings.Contains(rawCmd.Command, "show ssh"):
			if sshSessions, err := c.parser.ParseSSHSessions(rawCmd.Output); err == nil {
				state.Sessions = append(state.Sessions, sshSessions...)
			}

		case strings.Contains(rawCmd.Command, "show memory"):
			if memoryInfo, err := c.parser.ParseMemory(rawCmd.Output); err == nil {
				// Map memory information to SystemInfo fields
				if totalMem, ok := memoryInfo["total"].(string); ok {
					state.SystemInfo.MemoryTotal = totalMem
				}
				if freeMem, ok := memoryInfo["free"].(string); ok {
					state.SystemInfo.MemoryFree = freeMem
				}
				if usedMem, ok := memoryInfo["used"].(string); ok {
					state.SystemInfo.MemoryUsage = usedMem
				}
			}

		case strings.Contains(rawCmd.Command, "show access-list"):
			if accessLists, err := c.parser.ParseAccessLists(rawCmd.Output); err == nil {
				state.Security.AccessLists = append(state.Security.AccessLists, accessLists...)
			}

		case strings.Contains(rawCmd.Command, "show logging"):
			if logEntries, err := c.parser.ParseSystemLogs(rawCmd.Output); err == nil {
				state.Security.Logs = append(state.Security.Logs, logEntries...)
			}
		}
	}
}

// FTDCommand represents a forensic command to execute
type FTDCommand struct {
	Command string
	Parser  string
	Timeout time.Duration
}

// getCommandSet returns the complete set of forensic commands based on configuration
// Following Cisco FTD Software Forensic Data Collection Procedures (7 Steps)
func (c *FTDCollector) getCommandSet() []FTDCommand {
	// Core forensic commands based on Cisco FTD Forensic Data Collection Procedures
	coreCommands := []FTDCommand{
		// Step 2: FTD Runtime Environment Collection (CRITICAL)
		{Command: "show tech-support detail", Parser: "tech_support", Timeout: 300 * time.Second},
		{Command: "dir /recursive all-filesystems", Parser: "filesystem_all", Timeout: 120 * time.Second},
		{Command: "dir /recursive cache:", Parser: "filesystem_cache", Timeout: 60 * time.Second},

		// Step 3: FTD Image File Hash Verification
		{Command: "show version", Parser: "version", Timeout: 30 * time.Second},
		// Note: verify commands are dynamic based on detected images

		// Step 4: Digitally Signed Image Verification
		{Command: "show software authenticity running", Parser: "auth_running", Timeout: 30 * time.Second},
		{Command: "show software authenticity keys", Parser: "auth_keys", Timeout: 30 * time.Second},
		// Note: show software authenticity file commands are dynamic

		// Step 5: Memory .text Segment Verification
		{Command: "verify /sha-512 system:memory/text", Parser: "memory_text_hash", Timeout: 60 * time.Second},

		// Additional System Information
		{Command: "show clock", Parser: "clock", Timeout: 10 * time.Second},
		{Command: "show hostname", Parser: "hostname", Timeout: 10 * time.Second},
		{Command: "show processes", Parser: "processes", Timeout: 30 * time.Second},
		{Command: "show memory", Parser: "memory", Timeout: 30 * time.Second},
		{Command: "show cpu usage", Parser: "cpu", Timeout: 30 * time.Second},

		// Network State Collection
		{Command: "show interface", Parser: "interfaces", Timeout: 30 * time.Second},
		{Command: "show route", Parser: "routes", Timeout: 30 * time.Second},
		{Command: "show arp", Parser: "arp", Timeout: 30 * time.Second},
		{Command: "show connection", Parser: "connections", Timeout: 60 * time.Second},
		{Command: "show xlate", Parser: "nat_translations", Timeout: 30 * time.Second},

		// Security State Collection
		{Command: "show access-list", Parser: "access_lists", Timeout: 60 * time.Second},
		{Command: "show logging", Parser: "system_logs", Timeout: 60 * time.Second},
		{Command: "show users", Parser: "sessions", Timeout: 30 * time.Second},
		{Command: "show ssh", Parser: "ssh_sessions", Timeout: 30 * time.Second},

		// Configuration and Management
		{Command: "show running-config", Parser: "running_config", Timeout: 120 * time.Second},
		{Command: "show startup-config", Parser: "startup_config", Timeout: 60 * time.Second},
		{Command: "show configuration session", Parser: "config_sessions", Timeout: 30 * time.Second},

		// Hardware and Platform Information
		{Command: "show module", Parser: "modules", Timeout: 30 * time.Second},
		{Command: "show environment", Parser: "environment", Timeout: 30 * time.Second},
		{Command: "show inventory", Parser: "inventory", Timeout: 30 * time.Second},
		{Command: "show hardware", Parser: "hardware", Timeout: 30 * time.Second},

		// FTD-Specific Forensic Commands
		{Command: "show firewall", Parser: "firewall_status", Timeout: 30 * time.Second},
		{Command: "show threat-detection", Parser: "threat_detection", Timeout: 30 * time.Second},
		{Command: "show vpn-sessiondb", Parser: "vpn_sessions", Timeout: 30 * time.Second},
		{Command: "show failover", Parser: "failover_status", Timeout: 30 * time.Second},

		// File System Analysis
		{Command: "dir disk0:", Parser: "disk0_listing", Timeout: 30 * time.Second},
		{Command: "dir bootflash:", Parser: "bootflash_listing", Timeout: 30 * time.Second},
		{Command: "show disk0 | include crashinfo", Parser: "crashinfo_files", Timeout: 30 * time.Second},
		{Command: "show file systems", Parser: "filesystems", Timeout: 30 * time.Second},

		// Advanced Diagnostics (for full mode)
		{Command: "show cpu detailed", Parser: "cpu_detailed", Timeout: 30 * time.Second},
		{Command: "show memory detail", Parser: "memory_detail", Timeout: 30 * time.Second},
		{Command: "show processes memory", Parser: "process_memory", Timeout: 30 * time.Second},
		{Command: "show traffic", Parser: "traffic_stats", Timeout: 30 * time.Second},
		{Command: "show counters", Parser: "interface_counters", Timeout: 30 * time.Second},
	}

	switch c.CommandSet {
	case "minimal":
		// Return only essential forensic commands for quick collection
		return []FTDCommand{
			{Command: "show version", Parser: "version", Timeout: 30 * time.Second},
			{Command: "show tech-support detail", Parser: "tech_support", Timeout: 180 * time.Second},
			{Command: "show software authenticity running", Parser: "auth_running", Timeout: 30 * time.Second},
			{Command: "show processes", Parser: "processes", Timeout: 30 * time.Second},
			{Command: "show connection", Parser: "connections", Timeout: 30 * time.Second},
			{Command: "show logging | tail 100", Parser: "recent_logs", Timeout: 30 * time.Second},
			{Command: "dir all-filesystems", Parser: "filesystem_basic", Timeout: 60 * time.Second},
		}
	case "standard":
		// Return standard forensic command set (Steps 2-4 of official procedures)
		return []FTDCommand{
			// Step 2: Runtime Environment
			{Command: "show version", Parser: "version", Timeout: 30 * time.Second},
			{Command: "show tech-support detail", Parser: "tech_support", Timeout: 300 * time.Second},
			{Command: "dir /recursive all-filesystems", Parser: "filesystem_all", Timeout: 120 * time.Second},

			// Step 4: Digital Signature Verification
			{Command: "show software authenticity running", Parser: "auth_running", Timeout: 30 * time.Second},
			{Command: "show software authenticity keys", Parser: "auth_keys", Timeout: 30 * time.Second},

			// Essential System State
			{Command: "show processes", Parser: "processes", Timeout: 30 * time.Second},
			{Command: "show connection", Parser: "connections", Timeout: 60 * time.Second},
			{Command: "show interface", Parser: "interfaces", Timeout: 30 * time.Second},
			{Command: "show route", Parser: "routes", Timeout: 30 * time.Second},
			{Command: "show logging", Parser: "system_logs", Timeout: 60 * time.Second},
			{Command: "show users", Parser: "sessions", Timeout: 30 * time.Second},
			{Command: "show access-list", Parser: "access_lists", Timeout: 60 * time.Second},
			{Command: "show running-config", Parser: "running_config", Timeout: 120 * time.Second},
		}
	case "full":
		fallthrough
	default:
		// Return all forensic commands for thorough investigation (Full Steps 2-5)
		return coreCommands
	}
}

// printManualProcedures displays additional manual forensic procedures required for FTD
func (c *FTDCollector) printManualProcedures() {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("🔧 MANUAL FORENSIC PROCEDURES REQUIRED FOR CISCO FTD")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("The following procedures require manual execution to complete")
	fmt.Println("forensic compliance per official Cisco FTD procedures:")
	fmt.Println()

	fmt.Println("1. CRASHINFO/CORE DUMP COLLECTION (Step 6)")
	fmt.Println("   Commands:")
	fmt.Println("     system support diagnostic-cli")
	fmt.Println("     write crashinfo bootflash:")
	fmt.Println("   ⚠️  CRITICAL: Device reload required (~10-15 minutes downtime)")
	fmt.Println("   📋 Evidence: Crash analysis and memory forensics")
	fmt.Println()

	fmt.Println("2. ROM MONITOR BOOT SEQUENCE VERIFICATION")
	fmt.Println("   Commands:")
	fmt.Println("     show rom-monitor")
	fmt.Println("   🔌 Access: Console connection required during boot")
	fmt.Println("   📋 Evidence: Trust anchor and secure boot verification")
	fmt.Println()

	fmt.Println("3. ADVANCED THREAT DETECTION MEMORY ANALYSIS")
	fmt.Println("   Commands:")
	fmt.Println("     show threat-detection memory")
	fmt.Println("     show threat-detection scanning")
	fmt.Println("   📋 Evidence: Threat detection engine integrity analysis")
	fmt.Println()

	fmt.Println("⚠️  CRITICAL REMINDERS:")
	fmt.Println("   • Plan crashinfo collection during maintenance windows")
	fmt.Println("   • Console access required for ROM monitor verification")
	fmt.Println("   • Verify Trust Anchor integrity manually")
	fmt.Println("   • Document all manual procedures in chain of custody")
	fmt.Println(strings.Repeat("=", 80) + "\n")
}
