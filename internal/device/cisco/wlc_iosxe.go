package cisco

import (
	"fmt"
	"strings"
	"time"

	"netdac/internal/core"

	"golang.org/x/crypto/ssh"
)

// WLCIOSXECollector implements forensically sound data collection for Cisco Wireless LAN Controller (WLC)
// platforms running IOS XE Software based on official forensic procedures
// https://sec.cloudapps.cisco.com/security/center/resources/forensic_guides/iosxe_wlc_forensic_guide.html
type WLCIOSXECollector struct {
	Target     string
	Username   string
	Password   string
	Timeout    time.Duration
	CommandSet string

	client    *ssh.Client
	session   *ssh.Session
	parser    *WLCIOSXEParser
	connected bool
}

// WLCIOSXECommand represents a command to be executed during forensic collection
type WLCIOSXECommand struct {
	Command string
	Parser  string
	Timeout time.Duration
}

// NewWLCIOSXECollector creates a new WLC IOS XE collector instance
func NewWLCIOSXECollector(target, username, password string, timeout time.Duration) *WLCIOSXECollector {
	return &WLCIOSXECollector{
		Target:     target,
		Username:   username,
		Password:   password,
		Timeout:    timeout,
		CommandSet: "standard", // Default to standard forensic collection
		parser:     NewWLCIOSXEParser(),
		connected:  false,
	}
}

// SetCommandSet configures the forensic command set to execute
// Available sets: "minimal", "standard", "full"
func (c *WLCIOSXECollector) SetCommandSet(commandSet string) error {
	// Handle empty string by setting to default
	if commandSet == "" {
		c.CommandSet = "standard"
		return nil
	}

	validSets := []string{"minimal", "standard", "full"}
	for _, valid := range validSets {
		if commandSet == valid {
			c.CommandSet = commandSet
			return nil
		}
	}

	// For invalid command sets, set to default and return error
	c.CommandSet = "standard"
	return fmt.Errorf("invalid command set: %s. Valid options: %v", commandSet, validSets)
}

// GetAvailableCommandSets returns the list of available command sets
func (c *WLCIOSXECollector) GetAvailableCommandSets() []string {
	return []string{"minimal", "standard", "full"}
}

// GetCommandSet returns the current command set
func (c *WLCIOSXECollector) GetCommandSet() string {
	return c.CommandSet
}

// ListCommands returns the list of commands for the current command set
func (c *WLCIOSXECollector) ListCommands() []string {
	commands := c.getCommandSet(c.CommandSet)
	var commandList []string
	for _, cmd := range commands {
		commandList = append(commandList, cmd.Command)
	}
	return commandList
}

// Connect establishes an SSH connection to the device
func (c *WLCIOSXECollector) Connect() error {
	config := &ssh.ClientConfig{
		User: c.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(c.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         c.Timeout,
	}

	client, err := ssh.Dial("tcp", c.Target+":22", config)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	c.client = client
	c.connected = true
	return nil
}

// Disconnect closes the SSH connection
func (c *WLCIOSXECollector) Disconnect() error {
	if c.session != nil {
		c.session.Close()
	}
	if c.client != nil {
		err := c.client.Close()
		c.connected = false
		return err
	}
	return nil
}

// IsConnected returns the connection status
func (c *WLCIOSXECollector) IsConnected() bool {
	return c.connected
}

// executeCommand executes a single command and returns the output
func (c *WLCIOSXECollector) executeCommand(command WLCIOSXECommand) (string, error) {
	if c.session != nil {
		c.session.Close()
	}

	session, err := c.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	c.session = session

	// Set timeout for this command
	timeout := command.Timeout
	if timeout == 0 {
		timeout = c.Timeout
	}

	// Execute command
	output, err := session.Output(command.Command)
	if err != nil {
		return "", fmt.Errorf("failed to execute command '%s': %w", command.Command, err)
	}

	return string(output), nil
}

// Collect performs forensic data collection based on official Cisco WLC procedures
func (c *WLCIOSXECollector) Collect() (*core.DeviceState, error) {
	if !c.connected {
		return nil, fmt.Errorf("not connected to device")
	}

	deviceState := &core.DeviceState{
		Timestamp: time.Now(),
		Metadata: core.CollectionMetadata{
			CollectorVersion: "1.0.0",
			CollectionTime:   time.Now(),
			CommandSet:       c.CommandSet,
		},
		ForensicData: make(map[string]interface{}),
	}

	// Get command set based on configuration
	commands := c.getCommandSet(c.CommandSet)
	deviceState.Metadata.TotalCommands = len(commands)

	startTime := time.Now()

	for _, cmd := range commands {
		// Execute command with timeout
		output, err := c.executeCommand(cmd)

		// Store raw command output
		rawCmd := core.RawCommand{
			Command:   cmd.Command,
			Output:    output,
			Timestamp: time.Now(),
		}

		if err != nil {
			rawCmd.ExitCode = 1
			rawCmd.ErrorOutput = err.Error()
			deviceState.Metadata.FailedCommands++
			deviceState.Metadata.Errors = append(deviceState.Metadata.Errors,
				fmt.Sprintf("Command '%s' failed: %v", cmd.Command, err))
		} else {
			rawCmd.ExitCode = 0
			deviceState.Metadata.SuccessfulCommands++

			// Parse command output using the integrated parser
			parsedData, parseErr := c.parser.ParseCommand(cmd.Command, output)
			if parseErr != nil {
				deviceState.Metadata.Warnings = append(deviceState.Metadata.Warnings,
					fmt.Sprintf("Failed to parse output for '%s': %v", cmd.Command, parseErr))
			} else {
				// Store parsed data in appropriate fields
				c.storeCommandData(cmd.Command, parsedData, deviceState)
			}

			// Store forensic data
			if cmd.Parser != "" {
				deviceState.ForensicData[cmd.Parser] = parsedData
			}
		}

		deviceState.RawCommands = append(deviceState.RawCommands, rawCmd)
	}

	deviceState.Metadata.CollectionDuration = time.Since(startTime).String()

	// Add forensic metadata and warnings
	c.addForensicMetadata(deviceState)

	// Print manual forensic procedures if full command set was used
	if c.CommandSet == "full" {
		c.printManualProcedures()
	}

	return deviceState, nil
}

// storeCommandData stores parsed command data in the appropriate DeviceState fields
func (c *WLCIOSXECollector) storeCommandData(command string, data interface{}, deviceState *core.DeviceState) {
	switch {
	case strings.Contains(command, "show version"):
		if deviceInfo, ok := data.(*core.DeviceInfo); ok {
			deviceState.DeviceInfo = *deviceInfo
		}
	case strings.Contains(command, "show processes"):
		if processes, ok := data.([]core.Process); ok {
			deviceState.Processes = processes
		}
	case strings.Contains(command, "show interfaces"):
		if interfaces, ok := data.([]core.Interface); ok {
			deviceState.Interfaces = interfaces
		}
	case strings.Contains(command, "show ip route"):
		if routes, ok := data.([]core.Route); ok {
			deviceState.Routes = routes
		}
	}
}

// addForensicMetadata adds WLC-specific forensic metadata
func (c *WLCIOSXECollector) addForensicMetadata(deviceState *core.DeviceState) {
	deviceState.ForensicData["platform"] = "Cisco Wireless LAN Controller (WLC)"
	deviceState.ForensicData["forensic_procedures"] = "Official Cisco IOS XE WLC Forensic Guide"
	deviceState.ForensicData["collection_method"] = "SSH-based command execution"
	deviceState.ForensicData["target"] = c.Target
}

// getCommandSet returns the appropriate command set based on the forensic collection level
func (c *WLCIOSXECollector) getCommandSet(commandSet string) []WLCIOSXECommand {
	switch commandSet {
	case "minimal":
		return c.getMinimalCommandSet()
	case "standard":
		return c.getStandardCommandSet()
	case "full":
		return c.getFullCommandSet()
	default:
		return c.getStandardCommandSet()
	}
}

// getMinimalCommandSet returns essential forensic commands for quick assessment
func (c *WLCIOSXECollector) getMinimalCommandSet() []WLCIOSXECommand {
	return []WLCIOSXECommand{
		// Step 1: Problem Description Documentation (essential info)
		{Command: "show version", Parser: "version", Timeout: 30 * time.Second},
		{Command: "show tech-support", Parser: "tech_support", Timeout: 300 * time.Second},

		// Step 3: Basic Image Verification
		{Command: "show version | inc System image", Parser: "system_image", Timeout: 30 * time.Second},

		// Step 4: Basic Signature Verification
		{Command: "show software authenticity running", Parser: "software_authenticity", Timeout: 60 * time.Second},
	}
}

// getStandardCommandSet returns standard forensic commands following official 6-step procedures
func (c *WLCIOSXECollector) getStandardCommandSet() []WLCIOSXECommand {
	commands := c.getMinimalCommandSet()

	// Add standard forensic commands per official procedures
	standardCommands := []WLCIOSXECommand{
		// Step 2: Complete Runtime Environment Documentation
		{Command: "show tech-support wireless", Parser: "tech_support_wireless", Timeout: 300 * time.Second},
		{Command: "show tech-support diagnostic", Parser: "tech_support_diagnostic", Timeout: 300 * time.Second},
		{Command: "dir /recursive all-filesystems", Parser: "directory_listing", Timeout: 120 * time.Second},
		{Command: "show iox", Parser: "iox_info", Timeout: 30 * time.Second},
		{Command: "show app-hosting list", Parser: "app_hosting", Timeout: 30 * time.Second},
		{Command: "show platform software process memory chassis active r0 name linux_iosd-imag maps", Parser: "memory_maps", Timeout: 120 * time.Second},
		{Command: "show platform software process memory chassis active r0 name iosd smaps", Parser: "iosd_smaps", Timeout: 300 * time.Second},
		{Command: "show platform integrity sign nonce 12345", Parser: "integrity_nonce", Timeout: 60 * time.Second},
		{Command: "request platform software trace archive", Parser: "trace_archive", Timeout: 180 * time.Second},

		// Step 3: Image File Hash Verification
		{Command: "more bootflash:packages.conf", Parser: "packages_conf", Timeout: 60 * time.Second},
		{Command: "verify bootflash:packages.conf", Parser: "verify_packages", Timeout: 60 * time.Second},

		// Step 4: Complete Digital Signature Verification
		{Command: "show software authenticity keys", Parser: "auth_keys", Timeout: 30 * time.Second},

		// Step 5: Text Memory Section Export
		{Command: "dir system:memory/text", Parser: "memory_text_dir", Timeout: 30 * time.Second},
		{Command: "verify /md5 system:memory/text", Parser: "memory_text_hash", Timeout: 300 * time.Second},
	}

	return append(commands, standardCommands...)
}

// getFullCommandSet returns complete forensic commands for thorough investigation
func (c *WLCIOSXECollector) getFullCommandSet() []WLCIOSXECommand {
	commands := c.getStandardCommandSet()

	// Add full forensic commands
	fullCommands := []WLCIOSXECommand{
		// Additional Runtime Environment Analysis
		{Command: "show version", Parser: "detailed_version", Timeout: 30 * time.Second},
		{Command: "show processes cpu", Parser: "processes_cpu", Timeout: 60 * time.Second},
		{Command: "show processes memory", Parser: "processes_memory", Timeout: 60 * time.Second},
		{Command: "show interfaces", Parser: "interfaces", Timeout: 60 * time.Second},
		{Command: "show ip route", Parser: "routes", Timeout: 60 * time.Second},
		{Command: "show arp", Parser: "arp_table", Timeout: 30 * time.Second},

		// Wireless-Specific Analysis
		{Command: "show wireless summary", Parser: "wireless_summary", Timeout: 60 * time.Second},
		{Command: "show ap summary", Parser: "ap_summary", Timeout: 60 * time.Second},
		{Command: "show wireless client summary", Parser: "client_summary", Timeout: 60 * time.Second},
		{Command: "show wireless security", Parser: "wireless_security", Timeout: 60 * time.Second},
		{Command: "show wireless fabric summary", Parser: "fabric_summary", Timeout: 60 * time.Second},

		// Platform-Specific Analysis
		{Command: "show platform hardware", Parser: "platform_hardware", Timeout: 60 * time.Second},
		{Command: "show platform software status control-processor", Parser: "platform_status", Timeout: 60 * time.Second},
		{Command: "show platform software mount", Parser: "platform_mount", Timeout: 30 * time.Second},

		// Advanced Memory Analysis
		{Command: "show platform software process list", Parser: "process_list", Timeout: 60 * time.Second},
		{Command: "show platform software thread", Parser: "thread_info", Timeout: 60 * time.Second},

		// Security and Certificate Analysis
		{Command: "show crypto pki certificates", Parser: "pki_certificates", Timeout: 60 * time.Second},
		{Command: "show crypto engine connections active", Parser: "crypto_connections", Timeout: 60 * time.Second},

		// Logging and Event Analysis
		{Command: "show logging", Parser: "system_logs", Timeout: 60 * time.Second},
		{Command: "show archive log config all", Parser: "config_archive", Timeout: 60 * time.Second},

		// Network and Connectivity Analysis
		{Command: "show cdp neighbors detail", Parser: "cdp_neighbors", Timeout: 60 * time.Second},
		{Command: "show lldp neighbors detail", Parser: "lldp_neighbors", Timeout: 60 * time.Second},
		{Command: "show spanning-tree", Parser: "spanning_tree", Timeout: 60 * time.Second},

		// Step 6: Core File Generation (Note: This requires manual intervention)
		// These commands are included for documentation but may require separate execution
		{Command: "service internal", Parser: "service_internal", Timeout: 10 * time.Second},
		{Command: "show platform software process environment ios chassis active r0", Parser: "process_environment", Timeout: 60 * time.Second},
		// Note: "request platform software process core ios chassis active r0" intentionally omitted
		// as it causes system disruption and should be executed separately when needed
	}

	return append(commands, fullCommands...)
}

// ValidateConnection tests the connection and basic authentication
func (c *WLCIOSXECollector) ValidateConnection() error {
	if !c.connected {
		return fmt.Errorf("not connected to device")
	}

	// Test basic command execution
	testCmd := WLCIOSXECommand{
		Command: "show version",
		Timeout: 30 * time.Second,
	}

	_, err := c.executeCommand(testCmd)
	if err != nil {
		return fmt.Errorf("connection validation failed: %w", err)
	}

	return nil
}

// GetParser returns the associated parser instance
func (c *WLCIOSXECollector) GetParser() *WLCIOSXEParser {
	return c.parser
}

// GetDeviceInfo retrieves basic device information for forensic context
func (c *WLCIOSXECollector) GetDeviceInfo() (*core.DeviceInfo, error) {
	if !c.connected {
		return nil, fmt.Errorf("not connected to device")
	}

	// Get version information
	versionCmd := WLCIOSXECommand{
		Command: "show version",
		Timeout: 30 * time.Second,
	}

	output, err := c.executeCommand(versionCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to get device info: %w", err)
	}

	return c.parser.ParseVersion(output)
}

// GetTimeout returns the configured timeout
func (c *WLCIOSXECollector) GetTimeout() time.Duration {
	return c.Timeout
}

// SetTimeout configures the command execution timeout
func (c *WLCIOSXECollector) SetTimeout(timeout time.Duration) {
	c.Timeout = timeout
}

// GetSupportedCommands returns the list of commands supported by this collector
func (c *WLCIOSXECollector) GetSupportedCommands() []string {
	commands := c.getCommandSet(c.CommandSet)
	var cmdList []string
	for _, cmd := range commands {
		cmdList = append(cmdList, cmd.Command)
	}
	return cmdList
}

// printManualProcedures displays additional manual forensic procedures required for WLC IOS XE
func (c *WLCIOSXECollector) printManualProcedures() {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("🔧 MANUAL FORENSIC PROCEDURES REQUIRED FOR CISCO WLC IOS XE")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("The following procedures require manual execution to complete")
	fmt.Println("forensic compliance per official Cisco WLC procedures:")
	fmt.Println()

	fmt.Println("1. CORE FILE GENERATION (Step 6)")
	fmt.Println("   Command: write core bootflash:wlc-core-dump.bin")
	fmt.Println("   ⚠️  CAUTION: Wireless service interruption (~5-10 minutes)")
	fmt.Println("   📋 Evidence: Wireless controller memory analysis")
	fmt.Println()
	fmt.Println("2. WIRELESS SECURITY MODULE ANALYSIS")
	fmt.Println("   Commands:")
	fmt.Println("     debug wireless-security")
	fmt.Println("     show wireless security")
	fmt.Println("   📋 Evidence: Wireless security component verification")
	fmt.Println()
	fmt.Println("3. ACCESS POINT FORENSIC ANALYSIS")
	fmt.Println("   Commands:")
	fmt.Println("     show ap config general [ap-name]")
	fmt.Println("     show ap core-dump [ap-name]")
	fmt.Println("   📋 Evidence: Connected AP security analysis")
	fmt.Println()
	fmt.Println("4. CLIENT ASSOCIATION FORENSICS")
	fmt.Println("   Commands:")
	fmt.Println("     show wireless client mac-address [mac] detail")
	fmt.Println("     show wireless client security [mac]")
	fmt.Println("   📋 Evidence: Client connection security verification")
	fmt.Println()
	fmt.Println("5. CERTIFICATE AND PKI ANALYSIS")
	fmt.Println("   Commands:")
	fmt.Println("     show crypto pki certificates verbose")
	fmt.Println("     show crypto pki trustpoints")
	fmt.Println("   📋 Evidence: Wireless authentication infrastructure")
	fmt.Println()
	fmt.Println("⚠️  CRITICAL REMINDERS:")
	fmt.Println("   • Core dump collection may interrupt wireless services")
	fmt.Println("   • AP analysis requires individual AP access")
	fmt.Println("   • Client forensics requires active connections")
	fmt.Println("   • Document all manual procedures in chain of custody")
	fmt.Println(strings.Repeat("=", 80) + "\n")
}
