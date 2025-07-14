package cisco

import (
	"fmt"
	"strings"
	"time"

	"netdac/internal/core"

	"golang.org/x/crypto/ssh"
)

// FPR4100_9300Collector implements forensically sound data collection for Cisco Firepower 4100/9300 Series appliances
// running Cisco FXOS Software based on official forensic procedures
// https://sec.cloudapps.cisco.com/security/center/resources/forensic_guides/firepower4100_9300_forensic_investigation.html
type FPR4100_9300Collector struct {
	Target     string
	Username   string
	Password   string
	Timeout    time.Duration
	CommandSet string

	client    *ssh.Client
	session   *ssh.Session
	parser    *FPR4100_9300Parser
	connected bool
}

// FPR4100_9300Command represents a command to be executed during forensic collection
type FPR4100_9300Command struct {
	Command string
	Parser  string
	Timeout time.Duration
	CLI     string // "fxos", "ftd", "expert", "adapter" - specifies CLI context
	SlotID  string // For multi-slot 9300 series (1-3)
}

// NewFPR4100_9300Collector creates a new Firepower 4100/9300 collector instance
func NewFPR4100_9300Collector(target, username, password string, timeout time.Duration) *FPR4100_9300Collector {
	return &FPR4100_9300Collector{
		Target:     target,
		Username:   username,
		Password:   password,
		Timeout:    timeout,
		CommandSet: "standard", // Default to standard forensic collection
		parser:     NewFPR4100_9300Parser(),
		connected:  false,
	}
}

// SetCommandSet configures the forensic command set to execute
// Available sets: "minimal", "standard", "full"
func (c *FPR4100_9300Collector) SetCommandSet(commandSet string) error {
	validSets := []string{"minimal", "standard", "full"}
	for _, valid := range validSets {
		if commandSet == valid {
			c.CommandSet = commandSet
			return nil
		}
	}
	return fmt.Errorf("invalid command set: %s. Valid options: %v", commandSet, validSets)
}

// GetAvailableCommandSets returns the list of available command sets
func (c *FPR4100_9300Collector) GetAvailableCommandSets() []string {
	return []string{"minimal", "standard", "full"}
}

// GetCommandSet returns the current command set
func (c *FPR4100_9300Collector) GetCommandSet() string {
	return c.CommandSet
}

// ListCommands returns the list of commands for the current command set
func (c *FPR4100_9300Collector) ListCommands() []string {
	commands := c.getCommandSet(c.CommandSet)
	var commandList []string
	for _, cmd := range commands {
		commandList = append(commandList, cmd.Command)
	}
	return commandList
}

// Connect establishes an SSH connection to the device
func (c *FPR4100_9300Collector) Connect() error {
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
func (c *FPR4100_9300Collector) Disconnect() error {
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
func (c *FPR4100_9300Collector) IsConnected() bool {
	return c.connected
}

// switchCLIContext switches between different CLI contexts
func (c *FPR4100_9300Collector) switchCLIContext(context, slotID string) error {
	if c.session != nil {
		c.session.Close()
	}

	session, err := c.client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	c.session = session

	switch context {
	case "fxos":
		// Default FXOS CLI - no context switch needed
		return nil
	case "ftd":
		// Connect to FTD module
		connectCmd := fmt.Sprintf("connect module %s console", slotID)
		_, err = session.Output(connectCmd)
		if err != nil {
			return fmt.Errorf("failed to connect to FTD module %s: %w", slotID, err)
		}
	case "expert":
		// First connect to FTD, then expert mode
		connectCmd := fmt.Sprintf("connect module %s console", slotID)
		_, err = session.Output(connectCmd)
		if err != nil {
			return fmt.Errorf("failed to connect to FTD module %s: %w", slotID, err)
		}
		// Enter expert mode
		_, err = session.Output("expert")
		if err != nil {
			return fmt.Errorf("failed to enter expert mode: %w", err)
		}
	case "adapter":
		// Connect to mezzanine adapter
		adapterCmd := fmt.Sprintf("connect adapter 1/1/%s", slotID)
		_, err = session.Output(adapterCmd)
		if err != nil {
			return fmt.Errorf("failed to connect to adapter 1/1/%s: %w", slotID, err)
		}
	case "local-mgmt":
		// Connect to local management interface
		_, err = session.Output("connect local-mgmt")
		if err != nil {
			return fmt.Errorf("failed to connect to local-mgmt: %w", err)
		}
	}

	return nil
}

// executeCommand executes a single command and returns the output
func (c *FPR4100_9300Collector) executeCommand(command FPR4100_9300Command) (string, error) {
	// Switch to appropriate CLI context
	err := c.switchCLIContext(command.CLI, command.SlotID)
	if err != nil {
		return "", fmt.Errorf("failed to switch CLI context: %w", err)
	}

	// Set timeout for this command
	timeout := command.Timeout
	if timeout == 0 {
		timeout = c.Timeout
	}

	// Execute command
	output, err := c.session.Output(command.Command)
	if err != nil {
		return "", fmt.Errorf("failed to execute command '%s': %w", command.Command, err)
	}

	return string(output), nil
}

// Collect performs forensic data collection based on official Cisco procedures
func (c *FPR4100_9300Collector) Collect() (*core.DeviceState, error) {
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

	// Detect platform type and determine appropriate slot IDs
	slotIDs, err := c.detectPlatformSlots()
	if err != nil {
		return nil, fmt.Errorf("failed to detect platform slots: %w", err)
	}

	for _, slotID := range slotIDs {
		slotForensicData := make(map[string]interface{})

		for _, cmd := range commands {
			// Set slot ID for multi-slot commands
			if cmd.CLI == "ftd" || cmd.CLI == "expert" || cmd.CLI == "adapter" {
				cmd.SlotID = slotID
			}

			// Execute command
			output, err := c.executeCommand(cmd)

			// Store raw command output
			rawCmd := core.RawCommand{
				Command:   fmt.Sprintf("%s (slot %s)", cmd.Command, slotID),
				Output:    output,
				Timestamp: time.Now(),
			}

			if err != nil {
				rawCmd.ExitCode = 1
				rawCmd.ErrorOutput = err.Error()
				deviceState.Metadata.FailedCommands++
				deviceState.Metadata.Errors = append(deviceState.Metadata.Errors,
					fmt.Sprintf("Command '%s' failed on slot %s: %v", cmd.Command, slotID, err))
			} else {
				rawCmd.ExitCode = 0
				deviceState.Metadata.SuccessfulCommands++

				// Parse command output using the integrated parser
				parsedData, parseErr := c.parser.ParseCommand(cmd.Command, output)
				if parseErr != nil {
					deviceState.Metadata.Warnings = append(deviceState.Metadata.Warnings,
						fmt.Sprintf("Failed to parse output for '%s' on slot %s: %v", cmd.Command, slotID, parseErr))
				} else {
					// Store parsed data in slot-specific forensic data
					if cmd.Parser != "" {
						slotForensicData[cmd.Parser] = parsedData
					}

					// Store parsed data in appropriate fields (for slot 1 only to avoid duplicates)
					if slotID == "1" {
						c.storeCommandData(cmd.Command, parsedData, deviceState)
					}
				}
			}

			deviceState.RawCommands = append(deviceState.RawCommands, rawCmd)
		}

		// Store slot-specific data
		deviceState.ForensicData[fmt.Sprintf("slot_%s", slotID)] = slotForensicData
	}

	deviceState.Metadata.CollectionDuration = time.Since(startTime).String()

	// Add forensic metadata
	c.addForensicMetadata(deviceState)

	return deviceState, nil
}

// storeCommandData stores parsed command data in the appropriate DeviceState fields
func (c *FPR4100_9300Collector) storeCommandData(command string, data interface{}, deviceState *core.DeviceState) {
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
	case strings.Contains(command, "show route"):
		if routes, ok := data.([]core.Route); ok {
			deviceState.Routes = routes
		}
	}
}

// addForensicMetadata adds FPR4100/9300-specific forensic metadata
func (c *FPR4100_9300Collector) addForensicMetadata(deviceState *core.DeviceState) {
	deviceState.ForensicData["platform"] = "Firepower 4100/9300 Series"
	deviceState.ForensicData["forensic_procedures"] = "Official Cisco Firepower 4100/9300 Forensic Guide"
	deviceState.ForensicData["collection_method"] = "SSH-based multi-slot command execution"
	deviceState.ForensicData["target"] = c.Target
}

// getCommandSet returns the appropriate command set based on the forensic collection level
func (c *FPR4100_9300Collector) getCommandSet(commandSet string) []FPR4100_9300Command {
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
func (c *FPR4100_9300Collector) getMinimalCommandSet() []FPR4100_9300Command {
	return []FPR4100_9300Command{
		// Step 1: Document Runtime Environment (Essential)
		{Command: "show version", Parser: "fxos_version", Timeout: 30 * time.Second, CLI: "fxos"},
		{Command: "show app-instance", Parser: "app_instances", Timeout: 30 * time.Second, CLI: "fxos"},
		{Command: "show version", Parser: "ftd_version", Timeout: 30 * time.Second, CLI: "ftd"},

		// Step 2: Basic Digital Signature Verification
		{Command: "show software authenticity running", Parser: "software_authenticity", Timeout: 60 * time.Second, CLI: "local-mgmt"},
	}
}

// getStandardCommandSet returns standard forensic commands following official procedures
func (c *FPR4100_9300Collector) getStandardCommandSet() []FPR4100_9300Command {
	commands := c.getMinimalCommandSet()

	// Add standard forensic commands
	standardCommands := []FPR4100_9300Command{
		// Step 2: Document Runtime Environment (Full)
		{Command: "show tech-support detail", Parser: "tech_support", Timeout: 300 * time.Second, CLI: "ftd"},
		{Command: "dir /recursive all-filesystems", Parser: "directory_listing", Timeout: 120 * time.Second, CLI: "ftd"},

		// Step 3: FTD System File Integrity
		{Command: "find /ngfw/var/sf/.icdb/* -name *.icdb.RELEASE.tar | xargs sha512sum", Parser: "file_hashes", Timeout: 120 * time.Second, CLI: "expert"},
		{Command: "verify_file_integ.sh -f", Parser: "file_integrity", Timeout: 180 * time.Second, CLI: "expert"},

		// Step 4: FXOS Digital Signature Verification
		{Command: "show software authenticity file", Parser: "file_authenticity", Timeout: 60 * time.Second, CLI: "local-mgmt"},
		{Command: "show software authenticity keys", Parser: "auth_keys", Timeout: 30 * time.Second, CLI: "local-mgmt"},

		// Step 5: Mezzanine Adapter Processes
		{Command: "show-systemstatus", Parser: "adapter_processes", Timeout: 60 * time.Second, CLI: "adapter"},

		// Step 6: Memory Text Segment Integrity
		{Command: "verify /sha-512 system:memory/text", Parser: "memory_hash", Timeout: 300 * time.Second, CLI: "ftd"},
	}

	return append(commands, standardCommands...)
}

// getFullCommandSet returns complete forensic commands for thorough investigation
func (c *FPR4100_9300Collector) getFullCommandSet() []FPR4100_9300Command {
	commands := c.getStandardCommandSet()

	// Add full forensic commands
	fullCommands := []FPR4100_9300Command{
		// Additional FTD Analysis
		{Command: "show processes", Parser: "processes", Timeout: 60 * time.Second, CLI: "ftd"},
		{Command: "show interface", Parser: "interfaces", Timeout: 60 * time.Second, CLI: "ftd"},
		{Command: "show route", Parser: "routes", Timeout: 60 * time.Second, CLI: "ftd"},
		{Command: "show connection", Parser: "connections", Timeout: 60 * time.Second, CLI: "ftd"},

		// Additional Expert Mode Analysis
		{Command: "cat /proc/*/smaps", Parser: "process_memory_maps", Timeout: 120 * time.Second, CLI: "expert"},
		{Command: "ps aux", Parser: "detailed_processes", Timeout: 60 * time.Second, CLI: "expert"},
		{Command: "netstat -tulpn", Parser: "network_connections", Timeout: 60 * time.Second, CLI: "expert"},
		{Command: "lsof", Parser: "open_files", Timeout: 120 * time.Second, CLI: "expert"},

		// Additional FXOS Analysis
		{Command: "show fabric-interconnect", Parser: "fabric_interconnect", Timeout: 60 * time.Second, CLI: "fxos"},
		{Command: "show chassis", Parser: "chassis_info", Timeout: 60 * time.Second, CLI: "fxos"},
		{Command: "show security-service", Parser: "security_services", Timeout: 60 * time.Second, CLI: "fxos"},

		// ROM Monitor Check (requires manual reboot - for full analysis only)
		// Note: This is typically done separately as it requires device reboot

		// Additional File System Analysis
		{Command: "ls -la /ngfw/etc/certs/", Parser: "certificates", Timeout: 30 * time.Second, CLI: "expert"},
		{Command: "ls -la /ngfw/var/log/", Parser: "log_files", Timeout: 30 * time.Second, CLI: "expert"},
		{Command: "df -h", Parser: "disk_usage", Timeout: 30 * time.Second, CLI: "expert"},
		{Command: "mount", Parser: "mounted_filesystems", Timeout: 30 * time.Second, CLI: "expert"},

		// Network Analysis
		{Command: "ip addr show", Parser: "ip_addresses", Timeout: 30 * time.Second, CLI: "expert"},
		{Command: "ip route show", Parser: "routing_table", Timeout: 30 * time.Second, CLI: "expert"},
		{Command: "arp -a", Parser: "arp_table", Timeout: 30 * time.Second, CLI: "expert"},
	}

	return append(commands, fullCommands...)
}

// ValidateConnection tests the connection and basic authentication
func (c *FPR4100_9300Collector) ValidateConnection() error {
	if !c.connected {
		return fmt.Errorf("not connected to device")
	}

	// Test basic command execution
	testCmd := FPR4100_9300Command{
		Command: "show version",
		CLI:     "fxos",
		Timeout: 30 * time.Second,
	}

	_, err := c.executeCommand(testCmd)
	if err != nil {
		return fmt.Errorf("connection validation failed: %w", err)
	}

	return nil
}

// GetParser returns the associated parser instance
func (c *FPR4100_9300Collector) GetParser() *FPR4100_9300Parser {
	return c.parser
}

// GetDeviceInfo retrieves basic device information for forensic context
func (c *FPR4100_9300Collector) GetDeviceInfo() (*core.DeviceInfo, error) {
	if !c.connected {
		return nil, fmt.Errorf("not connected to device")
	}

	// Get FXOS version information
	versionCmd := FPR4100_9300Command{
		Command: "show version",
		CLI:     "fxos",
		Timeout: 30 * time.Second,
	}

	output, err := c.executeCommand(versionCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to get device info: %w", err)
	}

	return c.parser.ParseFXOSVersion(output)
}

// GetTimeout returns the configured timeout
func (c *FPR4100_9300Collector) GetTimeout() time.Duration {
	return c.Timeout
}

// SetTimeout configures the command execution timeout
func (c *FPR4100_9300Collector) SetTimeout(timeout time.Duration) {
	c.Timeout = timeout
}

// GetSupportedCommands returns the list of commands supported by this collector
func (c *FPR4100_9300Collector) GetSupportedCommands() []string {
	commands := c.getCommandSet(c.CommandSet)
	var cmdList []string
	for _, cmd := range commands {
		cmdList = append(cmdList, cmd.Command)
	}
	return cmdList
}

// detectPlatformSlots detects whether this is a 4100 or 9300 series and returns appropriate slot IDs
func (c *FPR4100_9300Collector) detectPlatformSlots() ([]string, error) {
	// Execute 'show chassis' command to detect platform type
	chassisCmd := FPR4100_9300Command{
		Command: "show chassis",
		CLI:     "fxos",
		Timeout: 30 * time.Second,
	}

	output, err := c.executeCommand(chassisCmd)
	if err != nil {
		// Fallback: try show version if chassis command fails
		versionCmd := FPR4100_9300Command{
			Command: "show version",
			CLI:     "fxos",
			Timeout: 30 * time.Second,
		}

		versionOutput, versionErr := c.executeCommand(versionCmd)
		if versionErr != nil {
			return []string{"1"}, fmt.Errorf("failed to detect platform type: %w", err)
		}
		output = versionOutput
	}

	// Parse output to determine platform type
	platform := c.parsePlatformType(output)

	switch platform {
	case "4100":
		// FPR-4100 series has single slot
		return []string{"1"}, nil
	case "9300":
		// FPR-9300 series has up to 3 slots - detect active slots
		return c.detectActiveSlots()
	default:
		// Unknown platform - default to single slot with warning
		return []string{"1"}, fmt.Errorf("unknown platform type, defaulting to single slot")
	}
}

// parsePlatformType extracts platform type from show chassis or show version output
func (c *FPR4100_9300Collector) parsePlatformType(output string) string {
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.ToLower(strings.TrimSpace(line))

		// Look for platform indicators in the output
		if strings.Contains(line, "fpr-4") || strings.Contains(line, "firepower 41") {
			return "4100"
		}
		if strings.Contains(line, "fpr-9") || strings.Contains(line, "firepower 93") {
			return "9300"
		}
		// Additional patterns for chassis output
		if strings.Contains(line, "chassis") && strings.Contains(line, "fpr41") {
			return "4100"
		}
		if strings.Contains(line, "chassis") && strings.Contains(line, "fpr93") {
			return "9300"
		}
	}

	// Default to 4100 if cannot determine
	return "4100"
}

// detectActiveSlots detects active slots for 9300 series
func (c *FPR4100_9300Collector) detectActiveSlots() ([]string, error) {
	// Execute 'show app-instance' to see active security modules
	appCmd := FPR4100_9300Command{
		Command: "show app-instance",
		CLI:     "fxos",
		Timeout: 30 * time.Second,
	}

	output, err := c.executeCommand(appCmd)
	if err != nil {
		// Fallback to all possible slots if detection fails
		return []string{"1", "2", "3"}, nil
	}

	activeSlots := []string{}
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Look for slot indicators in app-instance output
		// Example: "ftd    1    Deployed     1/1    Ready"
		if strings.Contains(line, "ftd") || strings.Contains(line, "asa") {
			// Extract slot number from the line
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				slotInfo := fields[3] // Usually in format "1/1", "1/2", etc.
				if strings.Contains(slotInfo, "/") {
					parts := strings.Split(slotInfo, "/")
					if len(parts) >= 2 {
						slotNum := parts[1]
						// Verify it's a valid slot number
						if slotNum == "1" || slotNum == "2" || slotNum == "3" {
							// Add to active slots if not already present
							found := false
							for _, existing := range activeSlots {
								if existing == slotNum {
									found = true
									break
								}
							}
							if !found {
								activeSlots = append(activeSlots, slotNum)
							}
						}
					}
				}
			}
		}
	}

	// If no active slots detected, default to slot 1
	if len(activeSlots) == 0 {
		activeSlots = []string{"1"}
	}

	return activeSlots, nil
}

// getPlatformType returns the detected platform type (for external use)
func (c *FPR4100_9300Collector) GetPlatformType() (string, error) {
	slots, err := c.detectPlatformSlots()
	if err != nil {
		return "unknown", err
	}

	if len(slots) == 1 {
		return "FPR-4100", nil
	} else {
		return "FPR-9300", nil
	}
}
