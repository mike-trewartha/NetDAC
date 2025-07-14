package cisco

import (
	"fmt"
	"strings"
	"time"

	"netdac/internal/core"

	"golang.org/x/crypto/ssh"
)

// FXOSCollector implements forensically sound data collection for Cisco Firepower 1000/2100 Series appliances
// running Cisco Firepower eXtensible Operating System (FXOS) Software based on official forensic procedures
// https://sec.cloudapps.cisco.com/security/center/resources/forensic_guides/firepower1000_2100_forensic_investigation.html
type FXOSCollector struct {
	Target     string
	Username   string
	Password   string
	Timeout    time.Duration
	CommandSet string

	client    *ssh.Client
	session   *ssh.Session
	parser    *FXOSParser
	connected bool
}

// FXOSCommand represents a command to be executed during forensic collection
type FXOSCommand struct {
	Command string
	Parser  string
	Timeout time.Duration
	CLI     string // "fxos" or "ftd" - specifies which CLI context
}

// NewFXOSCollector creates a new FXOS collector instance
func NewFXOSCollector(target, username, password string, timeout time.Duration) *FXOSCollector {
	return &FXOSCollector{
		Target:     target,
		Username:   username,
		Password:   password,
		Timeout:    timeout,
		CommandSet: "standard", // Default to standard forensic collection
		parser:     NewFXOSParser(),
		connected:  false,
	}
}

// SetCommandSet configures the forensic command set to execute
func (c *FXOSCollector) SetCommandSet(commandSet string) {
	c.CommandSet = commandSet
}

// Collect performs comprehensive forensic data collection from FXOS device
// Following Cisco Firepower 1000/2100 Series Forensic Data Collection Procedures (7 Steps)
func (c *FXOSCollector) Collect() (*core.DeviceState, error) {
	if err := c.Connect(); err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer c.Disconnect()

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

	// Add forensic collection warnings specific to FXOS Firepower 1000/2100 Series
	result.Metadata.Warnings = []string{
		"FORENSIC COLLECTION: Following Cisco Firepower 1000/2100 Series Forensic Data Collection Procedures",
		"CRITICAL: Do NOT reboot device during investigation - volatile data will be lost",
		"RECOMMENDED: Device should be isolated from network prior to examination",
		"FXOS/FTD Investigation: Requires both FXOS CLI and FTD CLI access",
		"Step 2: Document FXOS and FTD runtime environments",
		"Step 3: Verify FTD system file integrity",
		"Step 4: Verify digitally signed image authenticity",
		"Step 5: Verify FTD .text memory segment integrity",
		"CAUTION: Step 6 (crashinfo/core dump) will trigger device reload",
		"Step 7: Check ROM monitor settings (requires console access)",
	}

	// Execute all forensic commands in sequence
	commands := c.getCommandSet()
	successCount := 0

	for _, cmd := range commands {
		startTime := time.Now()

		// Switch to appropriate CLI context if needed
		if err := c.switchCLIContext(cmd.CLI); err != nil {
			result.RawCommands = append(result.RawCommands, core.RawCommand{
				Command:     cmd.Command,
				Output:      "",
				ErrorOutput: fmt.Sprintf("Failed to switch to %s CLI: %v", cmd.CLI, err),
				Timestamp:   time.Now(),
				Duration:    time.Since(startTime).String(),
			})
			continue
		}

		if output, err := c.ExecuteCommand(cmd.Command); err != nil {
			// Log error but continue with other commands
			result.RawCommands = append(result.RawCommands, core.RawCommand{
				Command:     cmd.Command,
				Output:      "",
				ErrorOutput: err.Error(),
				Timestamp:   time.Now(),
				Duration:    time.Since(startTime).String(),
			})
		} else {
			result.RawCommands = append(result.RawCommands, core.RawCommand{
				Command:   cmd.Command,
				Output:    output,
				Timestamp: time.Now(),
				Duration:  time.Since(startTime).String(),
			})
			successCount++

			// Parse command output and populate device state
			if parsedData, err := c.parser.ParseCommand(cmd.Command, output); err == nil && parsedData != nil {
				c.populateDeviceState(result, cmd.Command, parsedData)
			}
		}
	}

	// Calculate collection statistics
	result.Metadata.TotalCommands = len(commands)
	result.Metadata.SuccessfulCommands = successCount
	result.Metadata.FailedCommands = len(commands) - successCount

	if successCount == 0 {
		return result, fmt.Errorf("all commands failed - device may be unresponsive or credentials invalid")
	}

	// Print manual forensic procedures if full command set was used
	if c.CommandSet == "full" {
		c.printManualProcedures()
	}

	return result, nil
}

// switchCLIContext switches between FXOS CLI and FTD CLI contexts
func (c *FXOSCollector) switchCLIContext(targetCLI string) error {
	switch targetCLI {
	case "fxos":
		// For FXOS CLI, connect to local-mgmt scope if not already there
		if _, err := c.ExecuteCommand("connect local-mgmt"); err != nil {
			return fmt.Errorf("failed to connect to FXOS local-mgmt: %w", err)
		}
	case "ftd":
		// For FTD CLI, connect to FTD module and enter diagnostic CLI
		if _, err := c.ExecuteCommand("connect ftd"); err != nil {
			return fmt.Errorf("failed to connect to FTD: %w", err)
		}
		if _, err := c.ExecuteCommand("system support diagnostic-cli"); err != nil {
			return fmt.Errorf("failed to enter FTD diagnostic CLI: %w", err)
		}
		if _, err := c.ExecuteCommand("enable"); err != nil {
			return fmt.Errorf("failed to enable privileged mode in FTD: %w", err)
		}
		// Disable terminal pager for automated collection
		c.ExecuteCommand("terminal pager 0")
	default:
		// No specific CLI context required
	}
	return nil
}

// GetAvailableCommandSets returns the available command sets
func (c *FXOSCollector) GetAvailableCommandSets() []string {
	return []string{"minimal", "standard", "full"}
}

// GetCommandSet returns the currently configured command set
func (c *FXOSCollector) GetCommandSet() string {
	return c.CommandSet
}

// ListCommands returns the list of commands that would be executed for the current command set
func (c *FXOSCollector) ListCommands() []string {
	commands := c.getCommandSet()
	var commandList []string
	for _, cmd := range commands {
		if cmd.CLI != "" {
			commandList = append(commandList, fmt.Sprintf("[%s] %s", strings.ToUpper(cmd.CLI), cmd.Command))
		} else {
			commandList = append(commandList, cmd.Command)
		}
	}
	return commandList
}

// GetSupportedCommands returns the list of commands supported by this collector
func (c *FXOSCollector) GetSupportedCommands() []string {
	commands := c.getCommandSet()
	var cmdList []string
	for _, cmd := range commands {
		cmdList = append(cmdList, cmd.Command)
	}
	return cmdList
}

// getCommandSet returns the complete set of forensic commands based on configuration
// Following Cisco Firepower 1000/2100 Series Forensic Data Collection Procedures (7 Steps)
func (c *FXOSCollector) getCommandSet() []FXOSCommand {
	// Core forensic commands based on Cisco Firepower 1000/2100 Series Forensic Procedures
	coreCommands := []FXOSCommand{
		// Step 2: Document the Firepower Runtime Environment

		// FXOS CLI Commands (Platform Management)
		{Command: "show tech-support fprm detail", Parser: "fxos_tech_support", Timeout: 300 * time.Second, CLI: "fxos"},
		{Command: "show version", Parser: "fxos_version", Timeout: 30 * time.Second, CLI: "fxos"},
		{Command: "show hardware", Parser: "fxos_hardware", Timeout: 30 * time.Second, CLI: "fxos"},
		{Command: "show environment", Parser: "fxos_environment", Timeout: 30 * time.Second, CLI: "fxos"},
		{Command: "show clock", Parser: "fxos_clock", Timeout: 10 * time.Second, CLI: "fxos"},
		{Command: "show running-config", Parser: "fxos_running_config", Timeout: 60 * time.Second, CLI: "fxos"},

		// Step 4: Verify Digitally Signed Image Authenticity (FXOS CLI)
		{Command: "cd bootflash:/", Parser: "change_directory", Timeout: 10 * time.Second, CLI: "fxos"},
		{Command: "show file .boot_string", Parser: "boot_string", Timeout: 10 * time.Second, CLI: "fxos"},
		{Command: "show software authenticity running", Parser: "fxos_auth_running", Timeout: 30 * time.Second, CLI: "fxos"},
		{Command: "show software authenticity keys", Parser: "fxos_auth_keys", Timeout: 30 * time.Second, CLI: "fxos"},

		// FTD CLI Commands (Application Layer)
		{Command: "show tech-support detail", Parser: "ftd_tech_support", Timeout: 300 * time.Second, CLI: "ftd"},
		{Command: "show version", Parser: "ftd_version", Timeout: 30 * time.Second, CLI: "ftd"},
		{Command: "show processes", Parser: "ftd_processes", Timeout: 30 * time.Second, CLI: "ftd"},
		{Command: "show memory", Parser: "ftd_memory", Timeout: 30 * time.Second, CLI: "ftd"},
		{Command: "show interface", Parser: "ftd_interfaces", Timeout: 30 * time.Second, CLI: "ftd"},
		{Command: "show route", Parser: "ftd_routes", Timeout: 30 * time.Second, CLI: "ftd"},
		{Command: "show connection", Parser: "ftd_connections", Timeout: 60 * time.Second, CLI: "ftd"},
		{Command: "show logging", Parser: "ftd_logs", Timeout: 60 * time.Second, CLI: "ftd"},
		{Command: "show users", Parser: "ftd_users", Timeout: 30 * time.Second, CLI: "ftd"},
		{Command: "show running-config", Parser: "ftd_running_config", Timeout: 120 * time.Second, CLI: "ftd"},

		// Step 5: Verify FTD .text Memory Segment Integrity
		{Command: "verify /sha-512 system:memory/text", Parser: "ftd_memory_text_hash", Timeout: 60 * time.Second, CLI: "ftd"},

		// File System Analysis
		{Command: "dir /recursive all-filesystems", Parser: "ftd_filesystem_all", Timeout: 120 * time.Second, CLI: "ftd"},
		{Command: "dir disk0:", Parser: "ftd_disk0_listing", Timeout: 30 * time.Second, CLI: "ftd"},
		{Command: "dir bootflash:", Parser: "ftd_bootflash_listing", Timeout: 30 * time.Second, CLI: "ftd"},

		// Additional Security State
		{Command: "show access-list", Parser: "ftd_access_lists", Timeout: 60 * time.Second, CLI: "ftd"},
		{Command: "show arp", Parser: "ftd_arp", Timeout: 30 * time.Second, CLI: "ftd"},
		{Command: "show inventory", Parser: "ftd_inventory", Timeout: 30 * time.Second, CLI: "ftd"},
		{Command: "show module", Parser: "ftd_modules", Timeout: 30 * time.Second, CLI: "ftd"},
		{Command: "show failover", Parser: "ftd_failover", Timeout: 30 * time.Second, CLI: "ftd"},

		// Advanced Diagnostics
		{Command: "show cpu usage", Parser: "ftd_cpu", Timeout: 30 * time.Second, CLI: "ftd"},
		{Command: "show traffic", Parser: "ftd_traffic", Timeout: 30 * time.Second, CLI: "ftd"},
		{Command: "show file systems", Parser: "ftd_filesystems", Timeout: 30 * time.Second, CLI: "ftd"},
	}

	switch c.CommandSet {
	case "minimal":
		// Return only essential forensic commands for quick collection
		return []FXOSCommand{
			{Command: "show version", Parser: "fxos_version", Timeout: 30 * time.Second, CLI: "fxos"},
			{Command: "show hardware", Parser: "fxos_hardware", Timeout: 30 * time.Second, CLI: "fxos"},
			{Command: "show software authenticity running", Parser: "fxos_auth_running", Timeout: 30 * time.Second, CLI: "fxos"},
			{Command: "show version", Parser: "ftd_version", Timeout: 30 * time.Second, CLI: "ftd"},
			{Command: "show processes", Parser: "ftd_processes", Timeout: 30 * time.Second, CLI: "ftd"},
			{Command: "show connection", Parser: "ftd_connections", Timeout: 30 * time.Second, CLI: "ftd"},
			{Command: "show logging | tail 100", Parser: "ftd_recent_logs", Timeout: 30 * time.Second, CLI: "ftd"},
		}
	case "standard":
		// Return standard forensic command set (Steps 2-4 of official procedures)
		return []FXOSCommand{
			// FXOS Platform Commands
			{Command: "show tech-support fprm detail", Parser: "fxos_tech_support", Timeout: 180 * time.Second, CLI: "fxos"},
			{Command: "show version", Parser: "fxos_version", Timeout: 30 * time.Second, CLI: "fxos"},
			{Command: "show software authenticity running", Parser: "fxos_auth_running", Timeout: 30 * time.Second, CLI: "fxos"},
			{Command: "show software authenticity keys", Parser: "fxos_auth_keys", Timeout: 30 * time.Second, CLI: "fxos"},
			{Command: "show hardware", Parser: "fxos_hardware", Timeout: 30 * time.Second, CLI: "fxos"},

			// FTD Application Commands
			{Command: "show tech-support detail", Parser: "ftd_tech_support", Timeout: 180 * time.Second, CLI: "ftd"},
			{Command: "show version", Parser: "ftd_version", Timeout: 30 * time.Second, CLI: "ftd"},
			{Command: "show processes", Parser: "ftd_processes", Timeout: 30 * time.Second, CLI: "ftd"},
			{Command: "show interface", Parser: "ftd_interfaces", Timeout: 30 * time.Second, CLI: "ftd"},
			{Command: "show connection", Parser: "ftd_connections", Timeout: 60 * time.Second, CLI: "ftd"},
			{Command: "show logging", Parser: "ftd_logs", Timeout: 60 * time.Second, CLI: "ftd"},
			{Command: "show running-config", Parser: "ftd_running_config", Timeout: 60 * time.Second, CLI: "ftd"},
			{Command: "verify /sha-512 system:memory/text", Parser: "ftd_memory_text_hash", Timeout: 60 * time.Second, CLI: "ftd"},
		}
	case "full":
		fallthrough
	default:
		// Return all forensic commands for thorough investigation (Steps 2-5)
		return coreCommands
	}
}

// Connect establishes SSH connection to FXOS device
func (c *FXOSCollector) Connect() error {
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

	var err error
	c.client, err = ssh.Dial("tcp", c.Target+":22", config)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", c.Target, err)
	}

	c.session, err = c.client.NewSession()
	if err != nil {
		c.client.Close()
		return fmt.Errorf("failed to create session: %w", err)
	}

	c.connected = true
	return nil
}

// Disconnect closes the SSH connection
func (c *FXOSCollector) Disconnect() error {
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

// ExecuteCommand executes a single command on the FXOS device
func (c *FXOSCollector) ExecuteCommand(command string) (string, error) {
	if !c.connected {
		return "", fmt.Errorf("not connected to device")
	}

	// Create a new session for each command
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

// ValidateConnection tests the connection and basic authentication
func (c *FXOSCollector) ValidateConnection() error {
	if !c.connected {
		return fmt.Errorf("not connected to device")
	}

	// Test basic command execution
	_, err := c.ExecuteCommand("show version | head -5")
	if err != nil {
		return fmt.Errorf("connection validation failed: %v", err)
	}

	return nil
}

// populateDeviceState updates the device state with parsed command output
func (c *FXOSCollector) populateDeviceState(state *core.DeviceState, command string, data interface{}) {
	switch {
	case strings.Contains(command, "show version"):
		if deviceInfo, ok := data.(*core.DeviceInfo); ok {
			state.DeviceInfo.Model = deviceInfo.Model
			state.DeviceInfo.Version = deviceInfo.Version
			state.DeviceInfo.Hostname = deviceInfo.Hostname
			state.DeviceInfo.SerialNumber = deviceInfo.SerialNumber
			state.DeviceInfo.Uptime = deviceInfo.Uptime
		}
	case strings.Contains(command, "show processes"):
		if processes, ok := data.([]core.Process); ok {
			state.Processes = processes
		}
	case strings.Contains(command, "show interface"):
		if interfaces, ok := data.([]core.Interface); ok {
			state.Interfaces = interfaces
		}
	case strings.Contains(command, "show route"):
		if routes, ok := data.([]core.Route); ok {
			state.Routes = routes
		}
	case strings.Contains(command, "show connection"):
		if connections, ok := data.([]core.Connection); ok {
			state.Connections = connections
		}
	default:
		// Store in forensic data for specialized FXOS data
		state.ForensicData[command] = data
	}
}

// printManualProcedures displays additional manual forensic procedures required for FXOS
func (c *FXOSCollector) printManualProcedures() {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("🔧 MANUAL FORENSIC PROCEDURES REQUIRED FOR CISCO FXOS")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("The following procedures require manual execution to complete")
	fmt.Println("forensic compliance per official Cisco FXOS procedures:")
	fmt.Println()

	fmt.Println("1. CRASHINFO/CORE DUMP COLLECTION (Step 6)")
	fmt.Println("   Commands:")
	fmt.Println("     scope system")
	fmt.Println("     create core-dump")
	fmt.Println("   ⚠️  CAUTION: Device reload required (~10-15 minutes)")
	fmt.Println("   📋 Evidence: Complete system memory dump")
	fmt.Println()

	fmt.Println("2. ROM MONITOR SETTINGS VERIFICATION (Step 7)")
	fmt.Println("   Commands:")
	fmt.Println("     show rom-variables")
	fmt.Println("   🔌 Access: Console connection required during boot")
	fmt.Println("   📋 Evidence: Boot sequence security validation")
	fmt.Println()

	fmt.Println("3. FTD CLI CONTEXT ANALYSIS")
	fmt.Println("   Commands:")
	fmt.Println("     connect ftd")
	fmt.Println("     system support diagnostic-cli")
	fmt.Println("   📋 Evidence: FTD security engine analysis")
	fmt.Println()

	fmt.Println("4. MULTI-CONTEXT VERIFICATION")
	fmt.Println("   Commands:")
	fmt.Println("     scope security-services")
	fmt.Println("     show application-instance")
	fmt.Println("   📋 Evidence: Security service context isolation")
	fmt.Println()

	fmt.Println("⚠️  CRITICAL REMINDERS:")
	fmt.Println("   • Plan core dump collection during maintenance windows")
	fmt.Println("   • Console access required for ROM monitor verification")
	fmt.Println("   • Both FXOS and FTD CLI access may be required")
	fmt.Println("   • Document all manual procedures in chain of custody")
	fmt.Println(strings.Repeat("=", 80) + "\n")
}
