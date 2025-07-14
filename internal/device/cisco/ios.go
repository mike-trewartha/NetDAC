package cisco

import (
	"fmt"
	"strings"
	"time"

	"netdac/internal/core"

	"golang.org/x/crypto/ssh"
)

// IOSCollector implements the DeviceCollector interface for Cisco IOS devices
type IOSCollector struct {
	Target                  string
	Username                string
	Password                string
	SSHKey                  []byte
	Timeout                 time.Duration
	CommandSet              string
	SkipHostKeyVerification bool

	client    *ssh.Client
	session   *ssh.Session
	parser    *IOSParser
	connected bool
}

// NewIOSCollector creates a new Cisco IOS collector
func NewIOSCollector(target, username, password string, timeout time.Duration) *IOSCollector {
	return &IOSCollector{
		Target:    target,
		Username:  username,
		Password:  password,
		SSHKey:    nil, // Will be set by SetSSHKey if needed
		Timeout:   timeout,
		parser:    NewIOSParser(),
		connected: false,
	}
}

// SetSSHKey sets the SSH private key bytes for authentication
func (c *IOSCollector) SetSSHKey(key []byte) {
	c.SSHKey = key
}

// SetSkipHostKeyVerification sets whether to skip SSH host key verification
func (c *IOSCollector) SetSkipHostKeyVerification(skip bool) {
	c.SkipHostKeyVerification = skip
}

// Connect establishes an SSH connection to the Cisco IOS device
func (c *IOSCollector) Connect() error {
	// Create authentication methods
	authMethods, err := core.CreateSSHAuthMethods(c.SSHKey, c.Password)
	if err != nil {
		return err
	}

	config := &ssh.ClientConfig{
		User:            c.Username,
		Auth:            authMethods,
		HostKeyCallback: core.CreateHostKeyCallback(c.SkipHostKeyVerification, c.Target),
		Timeout:         c.Timeout,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", c.Target), config)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %v", c.Target, err)
	}

	c.client = client
	c.connected = true
	return nil
}

// ValidateConnection tests if the connection is working properly
func (c *IOSCollector) ValidateConnection() error {
	if !c.connected {
		return fmt.Errorf("not connected to device")
	}

	// Test with a simple command
	output, err := c.executeCommand("show version | include uptime")
	if err != nil {
		return fmt.Errorf("connection validation failed: %v", err)
	}

	if output == "" {
		return fmt.Errorf("received empty response from device")
	}

	return nil
}

// Collect executes the collection commands and returns structured device state
func (c *IOSCollector) Collect() (*core.DeviceState, error) {
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
	commands := c.getCommandSet()
	deviceState.Metadata.TotalCommands = len(commands)

	startTime := time.Now()

	for _, cmd := range commands {
		// Execute command
		output, err := c.executeCommand(cmd.Command)

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

			// Parse command output
			err = c.parseCommandOutput(cmd, output, deviceState)
			if err != nil {
				deviceState.Metadata.Warnings = append(deviceState.Metadata.Warnings,
					fmt.Sprintf("Failed to parse output for '%s': %v", cmd.Command, err))
			}
		}

		deviceState.RawCommands = append(deviceState.RawCommands, rawCmd)
	}

	// Phase 2: Execute dynamic image verification commands (for full collection)
	if c.CommandSet == "full" {
		dynamicCommands := c.addDynamicImageVerificationCommands(deviceState, []core.Command{})

		if len(dynamicCommands) > 0 {
			fmt.Printf("Executing %d dynamic image verification commands...\n", len(dynamicCommands))

			for _, cmd := range dynamicCommands {
				// Execute dynamic command
				output, err := c.executeCommand(cmd.Command)

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
					deviceState.Metadata.Warnings = append(deviceState.Metadata.Warnings,
						fmt.Sprintf("Dynamic command '%s' failed: %v", cmd.Command, err))
				} else {
					rawCmd.ExitCode = 0
					deviceState.Metadata.SuccessfulCommands++

					// Parse dynamic command output
					err = c.parseCommandOutput(cmd, output, deviceState)
					if err != nil {
						deviceState.Metadata.Warnings = append(deviceState.Metadata.Warnings,
							fmt.Sprintf("Failed to parse output for dynamic command '%s': %v", cmd.Command, err))
					}
				}

				deviceState.RawCommands = append(deviceState.RawCommands, rawCmd)
			}

			// Update total commands count
			deviceState.Metadata.TotalCommands += len(dynamicCommands)
		}
	}

	deviceState.Metadata.CollectionDuration = time.Since(startTime).String()

	// Add forensic warnings and notices
	c.addForensicWarning(deviceState)

	// Print manual forensic procedures if full command set was used
	if c.CommandSet == "full" {
		c.printManualProcedures()
	}

	return deviceState, nil
}

// Disconnect closes the SSH connection
func (c *IOSCollector) Disconnect() error {
	if c.session != nil {
		c.session.Close()
	}
	if c.client != nil {
		c.client.Close()
	}
	c.connected = false
	return nil
}

// GetSupportedCommands returns the list of commands supported by this collector
func (c *IOSCollector) GetSupportedCommands() []string {
	commands := c.getCommandSet()
	var cmdList []string
	for _, cmd := range commands {
		cmdList = append(cmdList, cmd.Command)
	}
	return cmdList
}

// executeCommand executes a single command on the device
func (c *IOSCollector) executeCommand(command string) (string, error) {
	session, err := c.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(command)
	if err != nil {
		return string(output), fmt.Errorf("command execution failed: %v", err)
	}

	return string(output), nil
}

// getCommandSet returns the appropriate command set based on configuration
func (c *IOSCollector) getCommandSet() []core.Command {
	switch c.CommandSet {
	case "minimal":
		return c.getMinimalCommandSet()
	case "full":
		return c.getFullCommandSet()
	default: // "standard"
		return c.getStandardCommandSet()
	}
}

// getMinimalCommandSet returns a minimal set of commands for quick collection
func (c *IOSCollector) getMinimalCommandSet() []core.Command {
	return []core.Command{
		{Name: "version", Command: "show version", Parser: "version", Required: true, Description: "Device version information"},
		{Name: "interfaces", Command: "show ip interface brief", Parser: "interfaces", Required: true, Description: "Interface status"},
		{Name: "routes", Command: "show ip route", Parser: "routes", Required: false, Description: "Routing table"},
	}
}

// getStandardCommandSet returns a standard set of commands for typical collection
// Based on Cisco IOS Software Forensic Data Collection Procedures
func (c *IOSCollector) getStandardCommandSet() []core.Command {
	return []core.Command{
		// Step 2: Runtime Environment (Core Forensic Commands)
		{Name: "tech_support", Command: "show tech-support", Parser: "tech_support", Required: true, Description: "Comprehensive technical support information (CRITICAL for forensics)"},
		{Name: "dir_all_filesystems", Command: "dir /recursive all-filesystems", Parser: "dir_all", Required: true, Description: "Complete filesystem listing (CRITICAL for forensics)"},

		// Step 3: Image Verification
		{Name: "version_image", Command: "show version | inc image", Parser: "version_image", Required: true, Description: "System image file location"},
		{Name: "region", Command: "show region", Parser: "region", Required: false, Description: "Memory region information"},

		// Step 4: Digital Signature Verification (if supported)
		{Name: "software_auth_running", Command: "show software authenticity running", Parser: "software_auth", Required: false, Description: "Running image authenticity check"},
		{Name: "software_auth_keys", Command: "show software authenticity keys", Parser: "software_keys", Required: false, Description: "Public signing keys"},

		// Step 7: ROMMON Check
		{Name: "rom_monitor", Command: "show rom-monitor", Parser: "rom_monitor", Required: false, Description: "ROM Monitor firmware check"},

		// Device Information
		{Name: "version", Command: "show version", Parser: "version", Required: true, Description: "Device version information"},
		{Name: "inventory", Command: "show inventory", Parser: "inventory", Required: false, Description: "Hardware inventory"},

		// Network Information (Forensically Relevant)
		{Name: "interfaces", Command: "show ip interface brief", Parser: "interfaces", Required: true, Description: "Interface status"},
		{Name: "interface_detail", Command: "show interfaces", Parser: "interface_detail", Required: false, Description: "Detailed interface information"},
		{Name: "routes", Command: "show ip route", Parser: "routes", Required: false, Description: "Routing table"},
		{Name: "arp", Command: "show arp", Parser: "arp", Required: false, Description: "ARP table (volatile evidence)"},
		{Name: "ip_nat", Command: "show ip nat translations", Parser: "nat_translations", Required: false, Description: "NAT translations (volatile evidence)"},

		// System Information (Forensically Critical)
		{Name: "processes", Command: "show processes", Parser: "processes", Required: false, Description: "Running processes"},
		{Name: "processes_cpu", Command: "show processes cpu", Parser: "processes_cpu", Required: false, Description: "CPU usage by process"},
		{Name: "processes_memory", Command: "show processes memory", Parser: "processes_memory", Required: false, Description: "Memory usage by process"},
		{Name: "memory", Command: "show memory", Parser: "memory", Required: false, Description: "Memory usage"},

		// Security Information (Critical for Incident Response)
		{Name: "users", Command: "show users", Parser: "users", Required: false, Description: "Active user sessions"},
		{Name: "access_lists", Command: "show access-lists", Parser: "access_lists", Required: false, Description: "Access control lists with hit counts"},
		{Name: "logging", Command: "show logging", Parser: "logging", Required: false, Description: "System logs (volatile evidence)"},
		{Name: "archive", Command: "show archive", Parser: "archive", Required: false, Description: "Configuration archive history"},

		// Network Security State
		{Name: "ip_accounting", Command: "show ip accounting", Parser: "ip_accounting", Required: false, Description: "IP accounting information"},
		{Name: "tcp", Command: "show tcp brief", Parser: "tcp_brief", Required: false, Description: "TCP connections"},
		{Name: "sessions", Command: "show sessions", Parser: "sessions", Required: false, Description: "Active terminal sessions"},

		// Clock and Environment (Forensic Timestamps)
		{Name: "clock", Command: "show clock detail", Parser: "clock", Required: false, Description: "System clock and timezone"},
		{Name: "ntp", Command: "show ntp status", Parser: "ntp", Required: false, Description: "NTP synchronization status"},
		{Name: "environment", Command: "show environment", Parser: "environment", Required: false, Description: "Environmental status"},
	}
}

// getFullCommandSet returns a comprehensive set of commands for detailed collection
// Includes all forensic commands plus configuration and advanced analysis
func (c *IOSCollector) getFullCommandSet() []core.Command {
	commands := c.getStandardCommandSet()

	// Add additional commands for full forensic collection
	additionalCommands := []core.Command{
		// Step 3: Image File Verification (Full Forensic Analysis)
		// Note: Image verification commands will be dynamically generated based on show version output

		// Step 5: Text Memory Region Analysis (Advanced Forensics)
		{Name: "memory_text_verify", Command: "verify /md5 system:memory/text", Parser: "memory_verify", Required: false, Description: "Text memory region MD5 verification"},

		// Configuration Analysis (Critical for Forensics)
		{Name: "config", Command: "show running-config", Parser: "config", Required: false, Description: "Running configuration"},
		{Name: "startup_config", Command: "show startup-config", Parser: "startup_config", Required: false, Description: "Startup configuration"},
		{Name: "config_diff", Command: "show archive config differences", Parser: "config_diff", Required: false, Description: "Configuration differences"},

		// Advanced Network State
		{Name: "vlan", Command: "show vlan brief", Parser: "vlan", Required: false, Description: "VLAN information"},
		{Name: "spanning_tree", Command: "show spanning-tree", Parser: "spanning_tree", Required: false, Description: "Spanning tree information"},
		{Name: "cdp_neighbors", Command: "show cdp neighbors detail", Parser: "cdp_neighbors", Required: false, Description: "CDP neighbor information"},
		{Name: "lldp_neighbors", Command: "show lldp neighbors detail", Parser: "lldp_neighbors", Required: false, Description: "LLDP neighbor information"},

		// Advanced Security Analysis
		{Name: "crypto_pki", Command: "show crypto pki certificates", Parser: "crypto_pki", Required: false, Description: "PKI certificates"},
		{Name: "crypto_sessions", Command: "show crypto session", Parser: "crypto_sessions", Required: false, Description: "Crypto sessions"},
		{Name: "aaa_servers", Command: "show aaa servers", Parser: "aaa_servers", Required: false, Description: "AAA server status"},
		{Name: "login_failures", Command: "show login failures", Parser: "login_failures", Required: false, Description: "Login failure attempts"},

		// Advanced System Analysis
		{Name: "file_systems", Command: "show file systems", Parser: "file_systems", Required: false, Description: "Available file systems"},
		{Name: "flash_info", Command: "show flash: all", Parser: "flash_info", Required: false, Description: "Flash memory details"},
		{Name: "bootvar", Command: "show bootvar", Parser: "bootvar", Required: false, Description: "Boot variables"},
		{Name: "reload_reason", Command: "show reload", Parser: "reload_reason", Required: false, Description: "Last reload reason"},

		// Performance and Resource Monitoring
		{Name: "cpu_history", Command: "show processes cpu history", Parser: "cpu_history", Required: false, Description: "CPU usage history"},
		{Name: "memory_summary", Command: "show memory summary", Parser: "memory_summary", Required: false, Description: "Memory summary"},
		{Name: "buffers", Command: "show buffers", Parser: "buffers", Required: false, Description: "Buffer pool statistics"},

		// Network Traffic Analysis
		{Name: "ip_traffic", Command: "show ip traffic", Parser: "ip_traffic", Required: false, Description: "IP traffic statistics"},
		{Name: "interface_counters", Command: "show interfaces counters", Parser: "interface_counters", Required: false, Description: "Interface counters"},

		// Diagnostic Information
		{Name: "diagnostics", Command: "show diagnostic result", Parser: "diagnostics", Required: false, Description: "Diagnostic test results"},
		{Name: "controllers", Command: "show controllers", Parser: "controllers", Required: false, Description: "Hardware controller information"},

		// NOTE: Core dump and memory extraction commands are intentionally excluded
		// as they require special configuration and can be CPU intensive
		// These should be performed manually following Cisco procedures if needed:
		// - write core (Step 6)
		// - copy system:memory/text (Step 5)
	}

	return append(commands, additionalCommands...)
}

// parseCommandOutput parses command output using the appropriate parser
func (c *IOSCollector) parseCommandOutput(cmd core.Command, output string, deviceState *core.DeviceState) error {
	parser := NewIOSParser()

	switch cmd.Parser {
	case "version":
		return parser.ParseVersion(output, deviceState)
	case "interfaces":
		return parser.ParseInterfaces(output, deviceState)
	case "routes":
		return parser.ParseRoutes(output, deviceState)
	case "processes":
		return parser.ParseProcesses(output, deviceState)
	case "users":
		return parser.ParseUsers(output, deviceState)
	case "access_lists":
		return parser.ParseAccessLists(output, deviceState)
	case "tech_support":
		return parser.ParseTechSupport(output, deviceState)
	case "directory_listing":
		return parser.ParseDirectoryListing(output, deviceState)
	case "image_info":
		return parser.ParseVersionImage(output, deviceState)
	case "memory_region":
		return parser.ParseMemoryRegion(output, deviceState)
	case "image_verification":
		return parser.ParseImageVerification(output, deviceState)
	case "software_authenticity":
		return parser.ParseSoftwareAuthenticity(output, deviceState)
	case "signing_keys":
		return parser.ParseSoftwareKeys(output, deviceState)
	case "rom_monitor":
		return parser.ParseROMMonitor(output, deviceState)
	case "logging":
		return parser.ParseLogging(output, deviceState)
	case "arp_table":
		return parser.ParseArpTable(output, deviceState)
	case "nat_translations":
		return parser.ParseNatTranslations(output, deviceState)
	case "tcp_connections":
		return parser.ParseTcpConnections(output, deviceState)
	case "clock_info":
		return parser.ParseClock(output, deviceState)
	default:
		// For unknown parsers, store as raw output in forensic data
		if deviceState.ForensicData == nil {
			deviceState.ForensicData = make(map[string]interface{})
		}
		deviceState.ForensicData[cmd.Name+"_raw"] = output
	}

	return nil
}

// addDynamicImageVerificationCommands adds image verification commands based on detected images
func (c *IOSCollector) addDynamicImageVerificationCommands(deviceState *core.DeviceState, commands []core.Command) []core.Command {
	// Extract image paths from device state (from "show version" output)
	var imageFiles []string

	// Look for image information in forensic data
	if deviceState.ForensicData != nil {
		if versionData, exists := deviceState.ForensicData["version"]; exists {
			if versionMap, ok := versionData.(map[string]interface{}); ok {
				// Check for system image path
				if systemImage, exists := versionMap["system_image"]; exists {
					if imagePath, ok := systemImage.(string); ok && imagePath != "" {
						imageFiles = append(imageFiles, imagePath)
					}
				}
				// Check for boot image path
				if bootImage, exists := versionMap["boot_image"]; exists {
					if imagePath, ok := bootImage.(string); ok && imagePath != "" {
						imageFiles = append(imageFiles, imagePath)
					}
				}
			}
		}

		// Also check raw version output for image paths
		if versionRaw, exists := deviceState.ForensicData["version_raw"]; exists {
			if rawOutput, ok := versionRaw.(string); ok {
				// Parse common image path patterns from show version output
				lines := strings.Split(rawOutput, "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					// Look for common image path patterns
					if strings.Contains(line, "image file is") {
						// Example: "System image file is flash:c2900-universalk9-mz.SPA.157-3.M5.bin"
						parts := strings.Split(line, "\"")
						if len(parts) >= 2 {
							imagePath := strings.Trim(parts[1], "\"")
							if imagePath != "" {
								imageFiles = append(imageFiles, imagePath)
							}
						}
					} else if strings.Contains(line, "boot image") || strings.Contains(line, "system image") {
						// Extract image paths from various version output formats
						words := strings.Fields(line)
						for _, word := range words {
							if strings.Contains(word, "flash:") || strings.Contains(word, "bootflash:") ||
								strings.Contains(word, "disk0:") || strings.Contains(word, "disk1:") {
								imageFiles = append(imageFiles, word)
							}
						}
					}
				}
			}
		}
	}

	// Remove duplicates
	imageFiles = removeDuplicateStrings(imageFiles)

	// Generate verification commands for each detected image
	var dynamicCommands []core.Command

	for i, imagePath := range imageFiles {
		// Clean up the image path (remove quotes, etc.)
		cleanPath := strings.Trim(imagePath, "\"")

		// Generate unique command names
		imageBaseName := getImageBaseName(cleanPath)

		// Add MD5 verification command
		dynamicCommands = append(dynamicCommands, core.Command{
			Name:        fmt.Sprintf("verify_image_%d_%s", i+1, imageBaseName),
			Command:     fmt.Sprintf("verify /md5 %s", cleanPath),
			Parser:      "verify_image",
			Required:    false,
			Description: fmt.Sprintf("MD5 verification of image: %s", cleanPath),
		})

		// Add software authenticity verification command (if supported)
		dynamicCommands = append(dynamicCommands, core.Command{
			Name:        fmt.Sprintf("software_auth_%d_%s", i+1, imageBaseName),
			Command:     fmt.Sprintf("show software authenticity file %s", cleanPath),
			Parser:      "software_auth_file",
			Required:    false,
			Description: fmt.Sprintf("Software authenticity check for: %s", cleanPath),
		})

		// Add file size verification
		dynamicCommands = append(dynamicCommands, core.Command{
			Name:        fmt.Sprintf("image_size_%d_%s", i+1, imageBaseName),
			Command:     fmt.Sprintf("dir %s", cleanPath),
			Parser:      "file_info",
			Required:    false,
			Description: fmt.Sprintf("File size and attributes for: %s", cleanPath),
		})
	}

	return append(commands, dynamicCommands...)
}

// removeDuplicateStrings removes duplicate strings from a slice
func removeDuplicateStrings(slice []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, item := range slice {
		if !seen[item] && item != "" {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}

// getImageBaseName extracts a clean base name from an image path for command naming
func getImageBaseName(imagePath string) string {
	// Extract filename from path
	parts := strings.Split(imagePath, "/")
	filename := parts[len(parts)-1]

	// Remove file extension and special characters for clean command naming
	baseName := strings.Split(filename, ".")[0]
	baseName = strings.ReplaceAll(baseName, "-", "_")
	baseName = strings.ReplaceAll(baseName, ":", "_")

	// Limit length to avoid overly long command names
	if len(baseName) > 20 {
		baseName = baseName[:20]
	}

	return baseName
}

// addForensicWarning adds important forensic warnings to metadata
func (c *IOSCollector) addForensicWarning(deviceState *core.DeviceState) {
	forensicWarnings := []string{
		"FORENSIC NOTICE: Device should be isolated from network during examination",
		"FORENSIC NOTICE: Do not reboot device - volatile evidence will be lost",
		"FORENSIC NOTICE: Consider manual core dump collection if advanced analysis needed",
		"FORENSIC NOTICE: Image verification and authenticity checks should be performed",
		"FORENSIC NOTICE: This collection follows Cisco IOS Forensic Data Collection Procedures",
	}

	deviceState.Metadata.Warnings = append(deviceState.Metadata.Warnings, forensicWarnings...)
}

// printManualProcedures displays additional manual forensic procedures required for IOS/IOS XE
func (c *IOSCollector) printManualProcedures() {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("🔧 MANUAL FORENSIC PROCEDURES REQUIRED FOR CISCO IOS/IOS XE")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("The following procedures require manual execution to complete")
	fmt.Println("forensic compliance per official Cisco IOS procedures:")
	fmt.Println()

	fmt.Println("1. CORE DUMP GENERATION (Step 6)")
	fmt.Println("   Command: write core")
	fmt.Println("   ⚠️  CAUTION: Device reload required (~5-10 minutes downtime)")
	fmt.Println("   📋 Evidence: Complete memory image for forensic analysis")
	fmt.Println()
	fmt.Println("2. ROM MONITOR ANALYSIS (Step 7)")
	fmt.Println("   Access: Console cable required during boot sequence")
	fmt.Println("   Commands: Break sequence (Ctrl+Break), rommon 1> set, rommon 2> boot")
	fmt.Println("   🔌 Access: Console cable required")
	fmt.Println("   📋 Evidence: Boot loader integrity verification")
	fmt.Println()
	fmt.Println("3. MEMORY TEXT SEGMENT EXPORT")
	fmt.Println("   Command: copy system:memory/text tftp://server/memory-dump.bin")
	fmt.Println("   📋 Evidence: Memory regions for integrity analysis")
	fmt.Println()
	fmt.Println("4. IMAGE HASH VERIFICATION")
	fmt.Println("   Commands:")
	fmt.Println("     verify /md5 flash:/*.bin")
	fmt.Println("     show software authenticity file [image-name]")
	fmt.Println("   📋 Evidence: System image integrity verification")
	fmt.Println()
	fmt.Println("⚠️  CRITICAL REMINDERS:")
	fmt.Println("   • Plan core dump collection during maintenance windows")
	fmt.Println("   • Console access required for ROM monitor analysis")
	fmt.Println("   • Verify device isolation before advanced procedures")
	fmt.Println("   • Document all manual procedures in chain of custody")
	fmt.Println(strings.Repeat("=", 80) + "\n")
}
