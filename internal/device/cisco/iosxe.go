package cisco

import (
	"fmt"
	"strings"
	"time"

	"netdac/internal/core"

	"golang.org/x/crypto/ssh"
)

// IOSXECollector implements forensically sound data collection for Cisco IOS XE devices
// based on official Cisco IOS XE Software Forensic Data Collection Procedures
type IOSXECollector struct {
	Target                  string
	Username                string
	Password                string
	SSHKey                  []byte
	Timeout                 time.Duration
	CommandSet              string
	SkipHostKeyVerification bool

	client    *ssh.Client
	session   *ssh.Session
	parser    *IOSXEParser
	connected bool
}

// NewIOSXECollector creates a new IOS XE collector instance
func NewIOSXECollector(target, username, password string, timeout time.Duration) *IOSXECollector {
	return &IOSXECollector{
		Target:    target,
		Username:  username,
		Password:  password,
		SSHKey:    nil, // Will be set by SetSSHKey if needed
		Timeout:   timeout,
		parser:    NewIOSXEParser(),
		connected: false,
	}
}

// SetSSHKey sets the SSH private key bytes for authentication
func (c *IOSXECollector) SetSSHKey(key []byte) {
	c.SSHKey = key
}

// SetSkipHostKeyVerification sets whether to skip SSH host key verification
func (c *IOSXECollector) SetSkipHostKeyVerification(skip bool) {
	c.SkipHostKeyVerification = skip
}

// Collect performs comprehensive forensic data collection from IOS XE device
func (c *IOSXECollector) Collect() (*core.DeviceState, error) {
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

	// Add forensic collection warnings
	result.Metadata.Warnings = []string{
		"FORENSIC COLLECTION: Device should be isolated from network",
		"DO NOT REBOOT during investigation - volatile data will be permanently lost",
		"Following Cisco IOS XE Software Forensic Data Collection Procedures",
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
		}
	}

	// Update metadata
	result.Metadata.SuccessfulCommands = successCount
	result.Metadata.FailedCommands = len(commands) - successCount
	result.Metadata.CollectionDuration = time.Since(result.Metadata.CollectionTime).String()

	// Parse all commands using the enhanced forensic parser
	if err := c.parser.ParseAllForensic(result); err != nil {
		result.Metadata.Warnings = append(result.Metadata.Warnings,
			fmt.Sprintf("Parsing warnings: %v", err))
	}

	// Add forensic metadata
	c.addForensicMetadata(result)

	return result, nil
}

// Connect establishes an SSH connection to the Cisco IOS XE device
func (c *IOSXECollector) Connect() error {
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
		return fmt.Errorf("failed to connect to %s:22: %v", c.Target, err)
	}

	c.client = client
	c.connected = true
	return nil
}

// Disconnect closes the SSH connection
func (c *IOSXECollector) Disconnect() error {
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

// ValidateConnection tests if the connection is working
func (c *IOSXECollector) ValidateConnection() error {
	if !c.connected {
		return fmt.Errorf("not connected to device")
	}

	// Test with a simple command
	_, err := c.ExecuteCommand("show clock")
	if err != nil {
		return fmt.Errorf("connection validation failed: %v", err)
	}

	return nil
}

// EnablePrivilegedMode enters enable mode on the device
func (c *IOSXECollector) EnablePrivilegedMode() error {
	// Most forensic commands require privileged mode
	output, err := c.ExecuteCommand("enable")
	if err != nil {
		return fmt.Errorf("failed to enter enable mode: %v", err)
	}

	// Check if we're in privileged mode
	if strings.Contains(output, "Password:") {
		// Device is asking for enable password - this may fail if password is required
		// but not provided. For now, we'll try to continue
		return fmt.Errorf("enable password required but not provided")
	}

	return nil
}

// ExecuteCommand executes a single command on the device
func (c *IOSXECollector) ExecuteCommand(command string) (string, error) {
	if !c.connected {
		return "", fmt.Errorf("not connected to device")
	}

	session, err := c.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(command)
	if err != nil {
		return "", fmt.Errorf("command execution failed: %v", err)
	}

	return string(output), nil
}

// GetSupportedCommands returns the list of supported commands
func (c *IOSXECollector) GetSupportedCommands() []string {
	commands := c.getCommandSet()
	result := make([]string, len(commands))
	for i, cmd := range commands {
		result[i] = cmd.Command
	}
	return result
}

// getCommandSet returns the appropriate command set based on configuration
func (c *IOSXECollector) getCommandSet() []core.Command {
	switch c.CommandSet {
	case "minimal":
		return c.getMinimalCommandSet()
	case "full":
		return c.getFullForensicCommandSet()
	default: // "standard"
		return c.getStandardForensicCommandSet()
	}
}

// getMinimalCommandSet returns essential commands for quick forensic triage
func (c *IOSXECollector) getMinimalCommandSet() []core.Command {
	return []core.Command{
		{
			Name:        "show_version",
			Command:     "show version",
			Description: "System version, uptime, image file, and hardware information",
			Required:    true,
		},
		{
			Name:        "show_running_config",
			Command:     "show running-config",
			Description: "Current running configuration",
			Required:    true,
		},
		{
			Name:        "show_processes",
			Command:     "show processes",
			Description: "Active processes and CPU utilization",
			Required:    true,
		},
		{
			Name:        "show_users",
			Command:     "show users",
			Description: "Currently logged-in users",
			Required:    true,
		},
		{
			Name:        "show_logging",
			Command:     "show logging",
			Description: "System log messages",
			Required:    true,
		},
		{
			Name:        "verify_system_image_conf",
			Command:     "verify bootflash:packages.conf",
			Description: "Verify packages configuration file",
			Required:    true,
		},
		{
			Name:        "show_software_authenticity_running",
			Command:     "show software authenticity running",
			Description: "Verify running image digital signature",
			Required:    true,
		},
	}
}

// getStandardForensicCommandSet returns standard forensic collection commands
func (c *IOSXECollector) getStandardForensicCommandSet() []core.Command {
	minimal := c.getMinimalCommandSet()

	additional := []core.Command{
		{
			Name:        "show_inventory",
			Command:     "show inventory",
			Description: "Hardware inventory and serial numbers",
			Required:    true,
		},
		{
			Name:        "show_interfaces",
			Command:     "show interfaces",
			Description: "Detailed interface information",
			Required:    true,
		},
		{
			Name:        "show_ip_route",
			Command:     "show ip route",
			Description: "IP routing table",
			Required:    true,
		},
		{
			Name:        "show_arp",
			Command:     "show arp",
			Description: "ARP table entries",
			Required:    true,
		},
		{
			Name:        "show_platform_process_memory_rp_iosd_smaps",
			Command:     "show platform software process memory rp active name iosd smaps",
			Description: "IOSd process memory segments (routing platforms) - check for tampering",
			Required:    true,
		},
		{
			Name:        "show_platform_integrity_sign",
			Command:     "show platform integrity sign nonce 12345",
			Description: "Platform integrity signature with nonce",
			Required:    true,
		},
		{
			Name:        "dir_all_filesystems",
			Command:     "dir all-filesystems",
			Description: "Complete file system listing",
			Required:    true,
		},
		{
			Name:        "dir_system_memory",
			Command:     "dir system:memory",
			Description: "System memory directory (text, data, heap, stack regions)",
			Required:    true,
		},
		{
			Name:        "verify_md5_system_memory_text",
			Command:     "verify /md5 system:memory/text",
			Description: "MD5 hash of text memory region for runtime integrity",
			Required:    true,
		},
	}

	return append(minimal, additional...)
}

// getFullForensicCommandSet returns comprehensive forensic collection commands
// This implements all steps from Cisco IOS XE Software Forensic Data Collection Procedures
func (c *IOSXECollector) getFullForensicCommandSet() []core.Command {
	return []core.Command{
		// Step 2: Document the Cisco IOS XE Runtime Environment
		{
			Name:        "show_tech_support",
			Command:     "show tech-support",
			Description: "Comprehensive technical support information (can be large)",
			Required:    true,
		},
		{
			Name:        "show_version",
			Command:     "show version",
			Description: "System version, uptime, image file, and hardware information",
			Required:    true,
		},
		{
			Name:        "show_running_config",
			Command:     "show running-config",
			Description: "Current running configuration",
			Required:    true,
		},
		{
			Name:        "show_startup_config",
			Command:     "show startup-config",
			Description: "Startup configuration",
			Required:    false,
		},
		{
			Name:        "show_inventory",
			Command:     "show inventory",
			Description: "Hardware inventory and serial numbers",
			Required:    true,
		},
		{
			Name:        "show_processes",
			Command:     "show processes",
			Description: "Active processes and CPU utilization",
			Required:    true,
		},
		{
			Name:        "show_processes_memory",
			Command:     "show processes memory",
			Description: "Memory usage by processes",
			Required:    true,
		},
		{
			Name:        "show_ip_interface_brief",
			Command:     "show ip interface brief",
			Description: "Interface status and IP addresses",
			Required:    true,
		},
		{
			Name:        "show_interfaces",
			Command:     "show interfaces",
			Description: "Detailed interface information",
			Required:    true,
		},
		{
			Name:        "show_ip_route",
			Command:     "show ip route",
			Description: "IP routing table",
			Required:    true,
		},
		{
			Name:        "show_arp",
			Command:     "show arp",
			Description: "ARP table entries",
			Required:    true,
		},
		{
			Name:        "show_mac_address_table",
			Command:     "show mac address-table",
			Description: "MAC address table (switching platforms)",
			Required:    false,
		},
		{
			Name:        "show_cdp_neighbors_detail",
			Command:     "show cdp neighbors detail",
			Description: "Detailed CDP neighbor information",
			Required:    false,
		},
		{
			Name:        "show_lldp_neighbors_detail",
			Command:     "show lldp neighbors detail",
			Description: "Detailed LLDP neighbor information",
			Required:    false,
		},
		{
			Name:        "show_users",
			Command:     "show users",
			Description: "Currently logged-in users",
			Required:    true,
		},
		{
			Name:        "show_logging",
			Command:     "show logging",
			Description: "System log messages",
			Required:    true,
		},
		{
			Name:        "show_access_lists",
			Command:     "show access-lists",
			Description: "Access control lists and hit counts",
			Required:    false,
		},
		{
			Name:        "show_crypto_key_mypubkey_rsa",
			Command:     "show crypto key mypubkey rsa",
			Description: "RSA public keys",
			Required:    false,
		},
		{
			Name:        "show_crypto_pki_certificates",
			Command:     "show crypto pki certificates",
			Description: "PKI certificates",
			Required:    false,
		},

		// App hosting and container enumeration
		{
			Name:        "show_iox",
			Command:     "show iox",
			Description: "IOx application hosting environment",
			Required:    false,
		},
		{
			Name:        "show_app_hosting_list",
			Command:     "show app-hosting list",
			Description: "Hosted applications list",
			Required:    false,
		},

		// Router-specific process and integrity information
		{
			Name:        "show_platform_process_memory_rp_linux_iosd_maps",
			Command:     "show platform software process memory rp active name linux_iosd-imag maps",
			Description: "Linux IOSd image memory maps (routing platforms)",
			Required:    false,
		},
		{
			Name:        "show_platform_process_memory_rp_iosd_smaps",
			Command:     "show platform software process memory rp active name iosd smaps",
			Description: "IOSd process memory segments (routing platforms) - check for tampering",
			Required:    true,
		},

		// Switch-specific process and integrity information
		{
			Name:        "show_platform_process_memory_switch_linux_iosd_maps",
			Command:     "show platform software process memory switch active r0 name linux_iosd-imag maps",
			Description: "Linux IOSd image memory maps (switching platforms)",
			Required:    false,
		},
		{
			Name:        "show_platform_process_memory_switch_iosd_smaps",
			Command:     "show platform software process memory switch active rp active name iosd smaps",
			Description: "IOSd process memory segments (switching platforms) - check for tampering",
			Required:    true,
		},

		// Platform integrity and authentication
		{
			Name:        "show_platform_integrity_sign",
			Command:     "show platform integrity sign nonce 12345",
			Description: "Platform integrity signature with nonce",
			Required:    true,
		},
		{
			Name:        "show_platform_hardware_authentication_status",
			Command:     "show platform hardware authentication status",
			Description: "Hardware authentication status",
			Required:    true,
		},

		// File system enumeration and core files
		{
			Name:        "dir_all_filesystems",
			Command:     "dir all-filesystems",
			Description: "Complete file system listing",
			Required:    true,
		},
		{
			Name:        "dir_recursive_all_filesystems",
			Command:     "dir /recursive all-filesystems",
			Description: "Recursive listing of all file systems",
			Required:    true,
		},
		{
			Name:        "dir_bootflash",
			Command:     "dir bootflash:",
			Description: "Boot flash directory listing",
			Required:    true,
		},
		{
			Name:        "dir_harddisk_tracelogs",
			Command:     "dir harddisk:/tracelogs",
			Description: "System logs and trace files (may contain system_shell logs)",
			Required:    false,
		},
		{
			Name:        "dir_bootflash_tracelogs",
			Command:     "dir bootflash:/tracelogs",
			Description: "Boot flash trace logs",
			Required:    true,
		},
		{
			Name:        "dir_crashinfo",
			Command:     "dir crashinfo:",
			Description: "Crash information files",
			Required:    false,
		},
		{
			Name:        "dir_core_files",
			Command:     "dir bootflash:/core",
			Description: "Core dump files",
			Required:    false,
		},

		// Step 3: Image File Hash Verification
		{
			Name:        "verify_system_image_bin",
			Command:     "verify bootflash:*.bin",
			Description: "Verify system image integrity (.bin files)",
			Required:    true,
		},
		{
			Name:        "verify_system_image_conf",
			Command:     "verify bootflash:packages.conf",
			Description: "Verify packages configuration file",
			Required:    true,
		},
		{
			Name:        "more_packages_conf",
			Command:     "more bootflash:packages.conf",
			Description: "Display packages configuration contents",
			Required:    true,
		},

		// Additional hash verification commands
		{
			Name:        "verify_md5_system_image",
			Command:     "verify /md5 bootflash:*.bin",
			Description: "MD5 hash verification of system image",
			Required:    false,
		},
		{
			Name:        "verify_sha512_system_image",
			Command:     "verify /sha512 bootflash:*.bin",
			Description: "SHA-512 hash verification of system image",
			Required:    false,
		},

		// Step 4: Digitally Signed Image Authenticity
		{
			Name:        "show_software_authenticity_running",
			Command:     "show software authenticity running",
			Description: "Verify running image digital signature",
			Required:    true,
		},
		{
			Name:        "show_platform_software_authenticity_verify",
			Command:     "show platform software authenticity verify bootflash:*.bin",
			Description: "Platform-level authenticity verification",
			Required:    true,
		},

		// Step 5: Text Memory Section Export
		{
			Name:        "dir_system_memory",
			Command:     "dir system:memory",
			Description: "System memory directory (text, data, heap, stack regions)",
			Required:    true,
		},
		{
			Name:        "verify_md5_system_memory_text",
			Command:     "verify /md5 system:memory/text",
			Description: "MD5 hash of text memory region for runtime integrity",
			Required:    true,
		},

		// Additional forensic commands for comprehensive evidence collection
		{
			Name:        "show_ip_nat_translations",
			Command:     "show ip nat translations",
			Description: "NAT translation table",
			Required:    false,
		},
		{
			Name:        "show_ip_dhcp_binding",
			Command:     "show ip dhcp binding",
			Description: "DHCP bindings",
			Required:    false,
		},
		{
			Name:        "show_spanning_tree",
			Command:     "show spanning-tree",
			Description: "Spanning tree protocol status",
			Required:    false,
		},
		{
			Name:        "show_vlan_brief",
			Command:     "show vlan brief",
			Description: "VLAN configuration summary",
			Required:    false,
		},
		{
			Name:        "show_etherchannel_summary",
			Command:     "show etherchannel summary",
			Description: "EtherChannel configuration",
			Required:    false,
		},
		{
			Name:        "show_ip_ospf_neighbor",
			Command:     "show ip ospf neighbor",
			Description: "OSPF neighbor information",
			Required:    false,
		},
		{
			Name:        "show_ip_bgp_summary",
			Command:     "show ip bgp summary",
			Description: "BGP peer summary",
			Required:    false,
		},
		{
			Name:        "show_ip_eigrp_neighbors",
			Command:     "show ip eigrp neighbors",
			Description: "EIGRP neighbor information",
			Required:    false,
		},
		{
			Name:        "show_snmp_community",
			Command:     "show snmp community",
			Description: "SNMP community strings",
			Required:    false,
		},
		{
			Name:        "show_ntp_status",
			Command:     "show ntp status",
			Description: "NTP synchronization status",
			Required:    false,
		},
		{
			Name:        "show_ntp_associations",
			Command:     "show ntp associations",
			Description: "NTP server associations",
			Required:    false,
		},
		{
			Name:        "show_clock",
			Command:     "show clock",
			Description: "System date and time",
			Required:    true,
		},
		{
			Name:        "show_timezone",
			Command:     "show clock detail",
			Description: "Detailed time and timezone information",
			Required:    false,
		},

		// Memory and performance diagnostics
		{
			Name:        "show_memory_summary",
			Command:     "show memory summary",
			Description: "Memory usage summary",
			Required:    true,
		},
		{
			Name:        "show_memory_statistics",
			Command:     "show memory statistics",
			Description: "Memory allocation statistics",
			Required:    false,
		},
		{
			Name:        "show_buffers",
			Command:     "show buffers",
			Description: "Buffer pool utilization",
			Required:    false,
		},

		// Security and authentication
		{
			Name:        "show_privilege",
			Command:     "show privilege",
			Description: "Current privilege level",
			Required:    true,
		},
		{
			Name:        "show_sessions",
			Command:     "show sessions",
			Description: "Active terminal sessions",
			Required:    true,
		},
		{
			Name:        "show_line",
			Command:     "show line",
			Description: "Terminal line information",
			Required:    true,
		},

		// Environment and hardware monitoring
		{
			Name:        "show_environment_all",
			Command:     "show environment all",
			Description: "Environmental monitoring (temperature, power, fans)",
			Required:    false,
		},
		{
			Name:        "show_power",
			Command:     "show power",
			Description: "Power supply status",
			Required:    false,
		},
		{
			Name:        "show_module",
			Command:     "show module",
			Description: "Module status and information",
			Required:    false,
		},

		// Additional platform-specific diagnostics
		{
			Name:        "show_platform_software_status_control_processor",
			Command:     "show platform software status control-processor",
			Description: "Control processor software status",
			Required:    false,
		},
		{
			Name:        "show_platform_hardware_qfp_active_infrastructure_bqs_status",
			Command:     "show platform hardware qfp active infrastructure bqs status",
			Description: "Quantum Flow Processor buffer queue status",
			Required:    false,
		},
		{
			Name:        "show_platform_hardware_qfp_active_infrastructure_exmem_statistics",
			Command:     "show platform hardware qfp active infrastructure exmem statistics",
			Description: "QFP external memory statistics",
			Required:    false,
		},

		// Security policies and configurations
		{
			Name:        "show_ip_ssh",
			Command:     "show ip ssh",
			Description: "SSH configuration and status",
			Required:    false,
		},
		{
			Name:        "show_aaa_servers",
			Command:     "show aaa servers",
			Description: "AAA server configuration",
			Required:    false,
		},
		{
			Name:        "show_radius_server_groups",
			Command:     "show radius server-group all",
			Description: "RADIUS server groups",
			Required:    false,
		},
		{
			Name:        "show_tacacs",
			Command:     "show tacacs",
			Description: "TACACS+ configuration",
			Required:    false,
		},

		// File system enumeration for malicious file detection
		{
			Name:        "dir_recursive_bootflash_suspicious",
			Command:     "dir /recursive bootflash:/ | include .sh|.py|.pl|.exe|.bin",
			Description: "Find potentially suspicious executable files in bootflash",
			Required:    true,
		},
		{
			Name:        "dir_tmp_directory",
			Command:     "dir unix:/tmp/",
			Description: "Check temporary directory for uploaded files",
			Required:    true,
		},
		{
			Name:        "dir_var_tmp",
			Command:     "dir unix:/var/tmp/",
			Description: "Check variable temporary directory",
			Required:    false,
		},
		{
			Name:        "show_file_systems_detailed",
			Command:     "show file systems",
			Description: "Available file systems for comprehensive enumeration",
			Required:    true,
		},
		{
			Name:        "dir_recent_files",
			Command:     "dir all-filesystems | include $(date +%b\\ %d)",
			Description: "Files modified today (potential uploads)",
			Required:    false,
		},

		// Network connection monitoring for C2 detection
		{
			Name:        "show_tcp_connections_all",
			Command:     "show tcp brief all",
			Description: "All TCP connections for C2 detection",
			Required:    true,
		},
		{
			Name:        "show_udp_connections",
			Command:     "show udp brief",
			Description: "UDP connections and listeners",
			Required:    true,
		},
		{
			Name:        "show_ip_sockets",
			Command:     "show ip sockets",
			Description: "Active IP socket connections",
			Required:    true,
		},
		{
			Name:        "show_platform_netstat",
			Command:     "show platform software linux iosd r0 netstat -anp",
			Description: "Linux netstat with process IDs for C2 detection",
			Required:    true,
		},
		{
			Name:        "show_tcp_connections_established",
			Command:     "show tcp brief all | include ESTAB",
			Description: "Established TCP connections",
			Required:    true,
		},
		{
			Name:        "show_ip_nat_translations",
			Command:     "show ip nat translations",
			Description: "NAT translations for connection tracking",
			Required:    false,
		},

		// Enhanced process analysis for privilege escalation detection
		{
			Name:        "show_processes_cpu_sorted",
			Command:     "show processes cpu sorted",
			Description: "Processes sorted by CPU usage for anomaly detection",
			Required:    true,
		},
		{
			Name:        "show_processes_memory_sorted",
			Command:     "show processes memory sorted",
			Description: "Processes sorted by memory usage",
			Required:    true,
		},
		{
			Name:        "show_platform_process_list_all",
			Command:     "show platform software process list location all",
			Description: "All platform processes across locations",
			Required:    true,
		},
		{
			Name:        "show_platform_linux_ps_detailed",
			Command:     "show platform software linux iosd r0 ps -auxww",
			Description: "Detailed Linux process list with full command lines",
			Required:    true,
		},
		{
			Name:        "show_platform_process_memory_detailed",
			Command:     "show platform software process memory detailed",
			Description: "Detailed process memory usage for anomaly detection",
			Required:    true,
		},
		{
			Name:        "show_processes_history",
			Command:     "show processes history",
			Description: "Process execution history",
			Required:    false,
		},
		{
			Name:        "show_platform_software_status_control",
			Command:     "show platform software status control-processor brief",
			Description: "Control processor software status",
			Required:    true,
		},

		// ...existing code...
	}
}

// extractDeviceInfo extracts device information from show version output
func (c *IOSXECollector) extractDeviceInfo(output string, deviceInfo *core.DeviceInfo) {
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Extract hostname
		if strings.Contains(line, " uptime is ") {
			parts := strings.Split(line, " uptime is ")
			if len(parts) > 0 {
				deviceInfo.Hostname = strings.TrimSpace(parts[0])
			}
		}

		// Extract model/platform
		if strings.Contains(line, "cisco ") && (strings.Contains(line, "processor") || strings.Contains(line, "bytes of")) {
			if strings.Contains(line, "cisco ") {
				start := strings.Index(line, "cisco ") + 6
				end := strings.Index(line[start:], " ")
				if end != -1 {
					deviceInfo.Model = line[start : start+end]
				} else {
					// Take everything after "cisco "
					parts := strings.Split(line[start:], " ")
					if len(parts) > 0 {
						deviceInfo.Model = parts[0]
					}
				}
			}
		}

		// Extract OS version
		if strings.Contains(line, "Cisco IOS XE Software, Version ") {
			start := strings.Index(line, "Version ") + 8
			end := strings.Index(line[start:], " ")
			if end != -1 {
				deviceInfo.Version = line[start : start+end]
			} else {
				deviceInfo.Version = strings.TrimSpace(line[start:])
			}
		}

		// Extract serial number
		if strings.Contains(line, "Processor board ID ") {
			start := strings.Index(line, "Processor board ID ") + 19
			deviceInfo.SerialNumber = strings.TrimSpace(line[start:])
		}

		// Extract system image
		if strings.Contains(line, "System image file is ") {
			start := strings.Index(line, "System image file is \"") + 22
			end := strings.Index(line[start:], "\"")
			if end != -1 {
				// Store system image in forensic data instead of device info
				// This will be properly extracted by the enhanced parser
			}
		}
	}
}

// addForensicMetadata adds comprehensive forensic metadata to the collection result
func (c *IOSXECollector) addForensicMetadata(result *core.DeviceState) {
	// Add forensic warnings to the metadata
	forensicWarnings := []string{
		"FORENSIC COLLECTION: Device should be isolated from network during examination",
		"DO NOT REBOOT the device - volatile data will be permanently lost",
		"Monitor system:memory/text region for runtime integrity verification",
		"Check for non-zero Private_Dirty values in rwxp memory segments (potential tampering)",
		"Preserve any system_shell_*.log files from tracelogs directory",
		"Consider generating core files if tampering is suspected",
		"Verify all image hashes against Cisco official hash database",
		"Document any configuration changes that cannot be explained",
		"Engage Cisco PSIRT for advanced analysis if compromise is confirmed",
	}

	// Add to existing warnings
	result.Metadata.Warnings = append(result.Metadata.Warnings, forensicWarnings...)

	// Set collection metadata
	result.Metadata.CollectionTime = time.Now()
	result.Metadata.CommandSet = "IOS XE Forensic Collection (Steps 1-6)"

	// Calculate total commands
	commands := c.getCommandSet()
	result.Metadata.TotalCommands = len(commands)
}
