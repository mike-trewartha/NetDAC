package core

import "time"

// DeviceCollector defines the interface that all vendor-specific collectors must implement
type DeviceCollector interface {
	// Connect establishes a connection to the network device
	Connect() error

	// Collect executes the collection commands and returns structured device state
	Collect() (*DeviceState, error)

	// Disconnect closes the connection to the device
	Disconnect() error

	// GetSupportedCommands returns the list of commands supported by this collector
	GetSupportedCommands() []string

	// ValidateConnection tests if the connection is working properly
	ValidateConnection() error
}

// CommandParser defines the interface for parsing vendor-specific command output
type CommandParser interface {
	// ParseCommand parses the output of a specific command into structured data
	ParseCommand(command string, output string) (interface{}, error)

	// GetCommandType returns the type of data this command produces
	GetCommandType(command string) string

	// SupportedCommands returns the list of commands this parser can handle
	SupportedCommands() []string
}

// DeviceState represents the complete collected state information from a network device
type DeviceState struct {
	DeviceInfo   DeviceInfo             `json:"device_info" yaml:"device_info"`
	Timestamp    time.Time              `json:"timestamp" yaml:"timestamp"`
	Connections  []Connection           `json:"connections,omitempty" yaml:"connections,omitempty"`
	Routes       []Route                `json:"routes,omitempty" yaml:"routes,omitempty"`
	Processes    []Process              `json:"processes,omitempty" yaml:"processes,omitempty"`
	Interfaces   []Interface            `json:"interfaces,omitempty" yaml:"interfaces,omitempty"`
	Sessions     []Session              `json:"sessions,omitempty" yaml:"sessions,omitempty"`
	SystemInfo   SystemInfo             `json:"system_info" yaml:"system_info"`
	Security     SecurityInfo           `json:"security,omitempty" yaml:"security,omitempty"`
	RawCommands  []RawCommand           `json:"raw_commands,omitempty" yaml:"raw_commands,omitempty"`
	Metadata     CollectionMetadata     `json:"metadata" yaml:"metadata"`
	ForensicData map[string]interface{} `json:"forensic_data,omitempty" yaml:"forensic_data,omitempty"`
}

// DeviceInfo contains basic device identification and hardware information
type DeviceInfo struct {
	Hostname     string `json:"hostname" yaml:"hostname"`
	IPAddress    string `json:"ip_address" yaml:"ip_address"`
	Vendor       string `json:"vendor" yaml:"vendor"`
	Model        string `json:"model,omitempty" yaml:"model,omitempty"`
	Version      string `json:"version,omitempty" yaml:"version,omitempty"`
	SerialNumber string `json:"serial_number,omitempty" yaml:"serial_number,omitempty"`
	Uptime       string `json:"uptime,omitempty" yaml:"uptime,omitempty"`
	LastReboot   string `json:"last_reboot,omitempty" yaml:"last_reboot,omitempty"`
	Location     string `json:"location,omitempty" yaml:"location,omitempty"`
	Contact      string `json:"contact,omitempty" yaml:"contact,omitempty"`
}

// Connection represents an active network connection
type Connection struct {
	Protocol        string `json:"protocol" yaml:"protocol"`
	LocalAddress    string `json:"local_address" yaml:"local_address"`
	LocalPort       string `json:"local_port" yaml:"local_port"`
	RemoteAddress   string `json:"remote_address" yaml:"remote_address"`
	RemotePort      string `json:"remote_port" yaml:"remote_port"`
	State           string `json:"state" yaml:"state"`
	PID             string `json:"pid,omitempty" yaml:"pid,omitempty"`
	Process         string `json:"process,omitempty" yaml:"process,omitempty"`
	EstablishedTime string `json:"established_time,omitempty" yaml:"established_time,omitempty"`
}

// Route represents a routing table entry
type Route struct {
	Destination   string `json:"destination" yaml:"destination"`
	Gateway       string `json:"gateway" yaml:"gateway"`
	Interface     string `json:"interface" yaml:"interface"`
	Metric        string `json:"metric,omitempty" yaml:"metric,omitempty"`
	Protocol      string `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	AdminDistance string `json:"admin_distance,omitempty" yaml:"admin_distance,omitempty"`
	Age           string `json:"age,omitempty" yaml:"age,omitempty"`
	NextHop       string `json:"next_hop,omitempty" yaml:"next_hop,omitempty"`
}

// Process represents a running process
type Process struct {
	PID         string `json:"pid" yaml:"pid"`
	Name        string `json:"name" yaml:"name"`
	CPU         string `json:"cpu,omitempty" yaml:"cpu,omitempty"`
	Memory      string `json:"memory,omitempty" yaml:"memory,omitempty"`
	Runtime     string `json:"runtime,omitempty" yaml:"runtime,omitempty"`
	State       string `json:"state,omitempty" yaml:"state,omitempty"`
	Priority    string `json:"priority,omitempty" yaml:"priority,omitempty"`
	ParentPID   string `json:"parent_pid,omitempty" yaml:"parent_pid,omitempty"`
	CommandLine string `json:"command_line,omitempty" yaml:"command_line,omitempty"`
}

// Interface represents a network interface
type Interface struct {
	Name        string `json:"name" yaml:"name"`
	Status      string `json:"status" yaml:"status"`
	AdminStatus string `json:"admin_status,omitempty" yaml:"admin_status,omitempty"`
	IPAddress   string `json:"ip_address,omitempty" yaml:"ip_address,omitempty"`
	SubnetMask  string `json:"subnet_mask,omitempty" yaml:"subnet_mask,omitempty"`
	MACAddress  string `json:"mac_address,omitempty" yaml:"mac_address,omitempty"`
	MTU         string `json:"mtu,omitempty" yaml:"mtu,omitempty"`
	Speed       string `json:"speed,omitempty" yaml:"speed,omitempty"`
	Duplex      string `json:"duplex,omitempty" yaml:"duplex,omitempty"`
	RxBytes     string `json:"rx_bytes,omitempty" yaml:"rx_bytes,omitempty"`
	TxBytes     string `json:"tx_bytes,omitempty" yaml:"tx_bytes,omitempty"`
	RxPackets   string `json:"rx_packets,omitempty" yaml:"rx_packets,omitempty"`
	TxPackets   string `json:"tx_packets,omitempty" yaml:"tx_packets,omitempty"`
	RxErrors    string `json:"rx_errors,omitempty" yaml:"rx_errors,omitempty"`
	TxErrors    string `json:"tx_errors,omitempty" yaml:"tx_errors,omitempty"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	VLAN        string `json:"vlan,omitempty" yaml:"vlan,omitempty"`
}

// Session represents an active user session
type Session struct {
	User      string `json:"user" yaml:"user"`
	Line      string `json:"line" yaml:"line"`
	Location  string `json:"location,omitempty" yaml:"location,omitempty"`
	IdleTime  string `json:"idle_time,omitempty" yaml:"idle_time,omitempty"`
	LoginTime string `json:"login_time,omitempty" yaml:"login_time,omitempty"`
	Protocol  string `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	Privilege string `json:"privilege,omitempty" yaml:"privilege,omitempty"`
	SourceIP  string `json:"source_ip,omitempty" yaml:"source_ip,omitempty"`
}

// SystemInfo contains system-level performance and resource information
type SystemInfo struct {
	CPUUsage         string            `json:"cpu_usage,omitempty" yaml:"cpu_usage,omitempty"`
	MemoryUsage      string            `json:"memory_usage,omitempty" yaml:"memory_usage,omitempty"`
	MemoryTotal      string            `json:"memory_total,omitempty" yaml:"memory_total,omitempty"`
	MemoryFree       string            `json:"memory_free,omitempty" yaml:"memory_free,omitempty"`
	DiskUsage        string            `json:"disk_usage,omitempty" yaml:"disk_usage,omitempty"`
	LoadAverage      string            `json:"load_average,omitempty" yaml:"load_average,omitempty"`
	Temperature      string            `json:"temperature,omitempty" yaml:"temperature,omitempty"`
	PowerStatus      string            `json:"power_status,omitempty" yaml:"power_status,omitempty"`
	FanStatus        string            `json:"fan_status,omitempty" yaml:"fan_status,omitempty"`
	EnvironmentStats []EnvironmentStat `json:"environment_stats,omitempty" yaml:"environment_stats,omitempty"`
}

// EnvironmentStat represents environmental monitoring data
type EnvironmentStat struct {
	Component string `json:"component" yaml:"component"`
	Status    string `json:"status" yaml:"status"`
	Value     string `json:"value,omitempty" yaml:"value,omitempty"`
	Threshold string `json:"threshold,omitempty" yaml:"threshold,omitempty"`
	Unit      string `json:"unit,omitempty" yaml:"unit,omitempty"`
}

// SecurityInfo contains security-related information
type SecurityInfo struct {
	AccessLists   []AccessList   `json:"access_lists,omitempty" yaml:"access_lists,omitempty"`
	FirewallRules []FirewallRule `json:"firewall_rules,omitempty" yaml:"firewall_rules,omitempty"`
	NATRules      []NATRule      `json:"nat_rules,omitempty" yaml:"nat_rules,omitempty"`
	VPNSessions   []VPNSession   `json:"vpn_sessions,omitempty" yaml:"vpn_sessions,omitempty"`
	AuthSessions  []AuthSession  `json:"auth_sessions,omitempty" yaml:"auth_sessions,omitempty"`
	Logs          []LogEntry     `json:"logs,omitempty" yaml:"logs,omitempty"`
}

// AccessList represents an access control list entry
type AccessList struct {
	Name      string    `json:"name" yaml:"name"`
	Type      string    `json:"type" yaml:"type"`
	Direction string    `json:"direction,omitempty" yaml:"direction,omitempty"`
	Interface string    `json:"interface,omitempty" yaml:"interface,omitempty"`
	Rules     []ACLRule `json:"rules,omitempty" yaml:"rules,omitempty"`
}

// ACLRule represents an individual access control rule
type ACLRule struct {
	Sequence    string `json:"sequence,omitempty" yaml:"sequence,omitempty"`
	Action      string `json:"action" yaml:"action"`
	Protocol    string `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	Source      string `json:"source,omitempty" yaml:"source,omitempty"`
	Destination string `json:"destination,omitempty" yaml:"destination,omitempty"`
	Port        string `json:"port,omitempty" yaml:"port,omitempty"`
	HitCount    string `json:"hit_count,omitempty" yaml:"hit_count,omitempty"`
	LastHit     string `json:"last_hit,omitempty" yaml:"last_hit,omitempty"`
}

// FirewallRule represents a firewall rule
type FirewallRule struct {
	ID          string `json:"id,omitempty" yaml:"id,omitempty"`
	Name        string `json:"name,omitempty" yaml:"name,omitempty"`
	Action      string `json:"action" yaml:"action"`
	Source      string `json:"source,omitempty" yaml:"source,omitempty"`
	Destination string `json:"destination,omitempty" yaml:"destination,omitempty"`
	Service     string `json:"service,omitempty" yaml:"service,omitempty"`
	Interface   string `json:"interface,omitempty" yaml:"interface,omitempty"`
	HitCount    string `json:"hit_count,omitempty" yaml:"hit_count,omitempty"`
	Enabled     bool   `json:"enabled" yaml:"enabled"`
}

// NATRule represents a Network Address Translation rule
type NATRule struct {
	ID               string `json:"id,omitempty" yaml:"id,omitempty"`
	Type             string `json:"type" yaml:"type"`
	OriginalSource   string `json:"original_source,omitempty" yaml:"original_source,omitempty"`
	TranslatedSource string `json:"translated_source,omitempty" yaml:"translated_source,omitempty"`
	OriginalDest     string `json:"original_destination,omitempty" yaml:"original_destination,omitempty"`
	TranslatedDest   string `json:"translated_destination,omitempty" yaml:"translated_destination,omitempty"`
	Interface        string `json:"interface,omitempty" yaml:"interface,omitempty"`
	HitCount         string `json:"hit_count,omitempty" yaml:"hit_count,omitempty"`
}

// VPNSession represents an active VPN session
type VPNSession struct {
	SessionID  string `json:"session_id" yaml:"session_id"`
	User       string `json:"user,omitempty" yaml:"user,omitempty"`
	ClientIP   string `json:"client_ip,omitempty" yaml:"client_ip,omitempty"`
	AssignedIP string `json:"assigned_ip,omitempty" yaml:"assigned_ip,omitempty"`
	Tunnel     string `json:"tunnel,omitempty" yaml:"tunnel,omitempty"`
	Protocol   string `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	Encryption string `json:"encryption,omitempty" yaml:"encryption,omitempty"`
	Duration   string `json:"duration,omitempty" yaml:"duration,omitempty"`
	BytesRx    string `json:"bytes_rx,omitempty" yaml:"bytes_rx,omitempty"`
	BytesTx    string `json:"bytes_tx,omitempty" yaml:"bytes_tx,omitempty"`
}

// AuthSession represents an authentication session
type AuthSession struct {
	User      string `json:"user" yaml:"user"`
	Source    string `json:"source,omitempty" yaml:"source,omitempty"`
	Method    string `json:"method,omitempty" yaml:"method,omitempty"`
	Status    string `json:"status" yaml:"status"`
	StartTime string `json:"start_time,omitempty" yaml:"start_time,omitempty"`
	Duration  string `json:"duration,omitempty" yaml:"duration,omitempty"`
	Privilege string `json:"privilege,omitempty" yaml:"privilege,omitempty"`
}

// RawCommand stores the raw command output for forensic purposes
type RawCommand struct {
	Command     string    `json:"command" yaml:"command"`
	Output      string    `json:"output" yaml:"output"`
	Timestamp   time.Time `json:"timestamp" yaml:"timestamp"`
	ExitCode    int       `json:"exit_code" yaml:"exit_code"`
	Duration    string    `json:"duration,omitempty" yaml:"duration,omitempty"`
	ErrorOutput string    `json:"error_output,omitempty" yaml:"error_output,omitempty"`
}

// CollectionMetadata contains metadata about the collection process
type CollectionMetadata struct {
	CollectorVersion   string    `json:"collector_version" yaml:"collector_version"`
	CollectionTime     time.Time `json:"collection_time" yaml:"collection_time"`
	CommandSet         string    `json:"command_set" yaml:"command_set"`
	TotalCommands      int       `json:"total_commands" yaml:"total_commands"`
	SuccessfulCommands int       `json:"successful_commands" yaml:"successful_commands"`
	FailedCommands     int       `json:"failed_commands" yaml:"failed_commands"`
	CollectionDuration string    `json:"collection_duration" yaml:"collection_duration"`
	Errors             []string  `json:"errors,omitempty" yaml:"errors,omitempty"`
	Warnings           []string  `json:"warnings,omitempty" yaml:"warnings,omitempty"`
}

// CommandSet defines a set of commands to execute for data collection
type CommandSet struct {
	Name        string    `json:"name" yaml:"name"`
	Description string    `json:"description" yaml:"description"`
	Commands    []Command `json:"commands" yaml:"commands"`
}

// Command represents a single command to execute
type Command struct {
	Name        string `json:"name" yaml:"name"`
	Command     string `json:"command" yaml:"command"`
	Parser      string `json:"parser,omitempty" yaml:"parser,omitempty"`
	Timeout     int    `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	Required    bool   `json:"required" yaml:"required"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// Forensic-specific data structures for advanced analysis
// These structures support Cisco forensic guidelines compliance

// TechSupportInfo represents parsed tech-support information
type TechSupportInfo struct {
	Sections    map[string]string `json:"sections" yaml:"sections"`
	CollectedAt time.Time         `json:"collected_at" yaml:"collected_at"`
	TotalLines  int               `json:"total_lines" yaml:"total_lines"`
	SizeBytes   int               `json:"size_bytes" yaml:"size_bytes"`
}

// DirectoryEntry represents a file or directory listing entry
type DirectoryEntry struct {
	Filesystem   string `json:"filesystem" yaml:"filesystem"`
	Name         string `json:"name" yaml:"name"`
	Size         int64  `json:"size" yaml:"size"`
	Permissions  string `json:"permissions,omitempty" yaml:"permissions,omitempty"`
	ModifiedTime string `json:"modified_time,omitempty" yaml:"modified_time,omitempty"`
}

// ImageInfo represents system image information for verification
type ImageInfo struct {
	SystemImage     string    `json:"system_image,omitempty" yaml:"system_image,omitempty"`
	ROMImage        string    `json:"rom_image,omitempty" yaml:"rom_image,omitempty"`
	BootVariable    string    `json:"boot_variable,omitempty" yaml:"boot_variable,omitempty"`
	CompilationInfo string    `json:"compilation_info,omitempty" yaml:"compilation_info,omitempty"`
	DetectedAt      time.Time `json:"detected_at" yaml:"detected_at"`
}

// MemoryRegion represents memory regions for tampering analysis
type MemoryRegion struct {
	Name       string `json:"name" yaml:"name"`
	Manager    string `json:"manager" yaml:"manager"`
	BaseAddr   string `json:"base_addr" yaml:"base_addr"`
	EndAddr    string `json:"end_addr" yaml:"end_addr"`
	Size       string `json:"size" yaml:"size"`
	Class      string `json:"class" yaml:"class"`
	Attributes string `json:"attributes,omitempty" yaml:"attributes,omitempty"`
}

// ImageVerification represents file verification results for tampering detection
type ImageVerification struct {
	CheckedAt         time.Time                   `json:"checked_at" yaml:"checked_at"`
	Files             map[string]FileVerification `json:"files" yaml:"files"`
	TamperingDetected bool                        `json:"tampering_detected" yaml:"tampering_detected"`
}

// FileVerification represents individual file verification results
type FileVerification struct {
	Filename          string `json:"filename" yaml:"filename"`
	EmbeddedSHA1      string `json:"embedded_sha1,omitempty" yaml:"embedded_sha1,omitempty"`
	ComputedSHA1      string `json:"computed_sha1,omitempty" yaml:"computed_sha1,omitempty"`
	EmbeddedSHA2      string `json:"embedded_sha2,omitempty" yaml:"embedded_sha2,omitempty"`
	ComputedSHA2      string `json:"computed_sha2,omitempty" yaml:"computed_sha2,omitempty"`
	Verified          bool   `json:"verified" yaml:"verified"`
	TamperingDetected bool   `json:"tampering_detected" yaml:"tampering_detected"`
	SignatureVerified bool   `json:"signature_verified" yaml:"signature_verified"`
}

// SoftwareAuthenticity represents digital signature verification
type SoftwareAuthenticity struct {
	CheckedAt   time.Time                    `json:"checked_at" yaml:"checked_at"`
	Sections    map[string]map[string]string `json:"sections" yaml:"sections"`
	CiscoSigned bool                         `json:"cisco_signed" yaml:"cisco_signed"`
}

// SigningKey represents cryptographic signing key information
type SigningKey struct {
	Type    string `json:"type" yaml:"type"`
	Name    string `json:"name" yaml:"name"`
	Version string `json:"version,omitempty" yaml:"version,omitempty"`
	Storage string `json:"storage,omitempty" yaml:"storage,omitempty"`
}

// ROMMonitorInfo represents ROM monitor information
type ROMMonitorInfo struct {
	Version   string            `json:"version,omitempty" yaml:"version,omitempty"`
	Variables map[string]string `json:"variables" yaml:"variables"`
	ParsedAt  time.Time         `json:"parsed_at" yaml:"parsed_at"`
}

// LogEntry represents a system log entry for forensic analysis (updated for IOS XR)
type LogEntry struct {
	Timestamp time.Time `json:"timestamp" yaml:"timestamp"`
	Facility  string    `json:"facility,omitempty" yaml:"facility,omitempty"`
	Severity  string    `json:"severity,omitempty" yaml:"severity,omitempty"`
	Mnemonic  string    `json:"mnemonic,omitempty" yaml:"mnemonic,omitempty"`
	Message   string    `json:"message" yaml:"message"`
	Category  string    `json:"category,omitempty" yaml:"category,omitempty"` // SECURITY, SYSTEM, INTEGRITY
	RawLine   string    `json:"raw_line,omitempty" yaml:"raw_line,omitempty"`
}

// ClockInfo represents system clock and timezone information
type ClockInfo struct {
	CurrentTime string    `json:"current_time,omitempty" yaml:"current_time,omitempty"`
	TimeSource  string    `json:"time_source,omitempty" yaml:"time_source,omitempty"`
	ParsedAt    time.Time `json:"parsed_at" yaml:"parsed_at"`
}

// IOS XR-specific forensic data structures
// Based on Cisco IOS XR Software Forensic Data Collection Procedures

// NetIOClientsData represents NetIO client information for IOS XR forensic analysis
type NetIOClientsData struct {
	Clients       []NetIOClient `json:"clients" yaml:"clients"`
	ForensicNotes []string      `json:"forensic_notes,omitempty" yaml:"forensic_notes,omitempty"`
	ParsedAt      time.Time     `json:"parsed_at" yaml:"parsed_at"`
}

// NetIOClient represents a single NetIO client (critical for IOS XR forensics)
type NetIOClient struct {
	ClientID     string `json:"client_id" yaml:"client_id"`
	DropTotal    string `json:"drop_total,omitempty" yaml:"drop_total,omitempty"`
	DropTotalRx  string `json:"drop_total_rx,omitempty" yaml:"drop_total_rx,omitempty"`
	CurrentQueue string `json:"current_queue,omitempty" yaml:"current_queue,omitempty"`
	MaxQueue     string `json:"max_queue,omitempty" yaml:"max_queue,omitempty"`
}

// PacketMemoryClientsData represents packet memory client information for IOS XR
type PacketMemoryClientsData struct {
	Clients       []PacketMemoryClient `json:"clients" yaml:"clients"`
	ForensicNotes []string             `json:"forensic_notes,omitempty" yaml:"forensic_notes,omitempty"`
	ParsedAt      time.Time            `json:"parsed_at" yaml:"parsed_at"`
}

// PacketMemoryClient represents a process with packet memory access (high forensic priority)
type PacketMemoryClient struct {
	JobID   int    `json:"job_id" yaml:"job_id"`
	Coid    int    `json:"coid" yaml:"coid"`
	Options string `json:"options" yaml:"options"`
	Process string `json:"process" yaml:"process"`
}

// PlatformIntegrityData represents IOS XR platform integrity information
type PlatformIntegrityData struct {
	SecureBootStatus string    `json:"secure_boot_status" yaml:"secure_boot_status"`
	IntegrityChecks  []string  `json:"integrity_checks" yaml:"integrity_checks"`
	ForensicNotes    []string  `json:"forensic_notes,omitempty" yaml:"forensic_notes,omitempty"`
	ParsedAt         time.Time `json:"parsed_at" yaml:"parsed_at"`
}

// InstallInfo represents active software installation information for IOS XR
type InstallInfo struct {
	Version        string    `json:"version" yaml:"version"`
	ActivePackages []string  `json:"active_packages" yaml:"active_packages"`
	ParsedAt       time.Time `json:"parsed_at" yaml:"parsed_at"`
}

// SystemLogData represents system log analysis for IOS XR forensics
type SystemLogData struct {
	LogEntries    []LogEntry `json:"log_entries" yaml:"log_entries"`
	ForensicNotes []string   `json:"forensic_notes,omitempty" yaml:"forensic_notes,omitempty"`
	ParsedAt      time.Time  `json:"parsed_at" yaml:"parsed_at"`
}

// DirectoryListing represents file system analysis for IOS XR forensics
type DirectoryListing struct {
	Files         []FileInfo `json:"files" yaml:"files"`
	ForensicNotes []string   `json:"forensic_notes,omitempty" yaml:"forensic_notes,omitempty"`
	ParsedAt      time.Time  `json:"parsed_at" yaml:"parsed_at"`
}

// FileInfo represents file information for forensic analysis
type FileInfo struct {
	Name         string    `json:"name" yaml:"name"`
	Size         string    `json:"size" yaml:"size"`
	Permissions  string    `json:"permissions" yaml:"permissions"`
	ModifiedTime time.Time `json:"modified_time" yaml:"modified_time"`
	Owner        string    `json:"owner,omitempty" yaml:"owner,omitempty"`
	Group        string    `json:"group,omitempty" yaml:"group,omitempty"`
}

// TechSupportData represents parsed tech-support output for forensic analysis
type TechSupportData struct {
	GeneratedAt   time.Time `json:"generated_at" yaml:"generated_at"`
	Size          int       `json:"size" yaml:"size"`
	CommandCount  int       `json:"command_count" yaml:"command_count"`
	ErrorCount    int       `json:"error_count,omitempty" yaml:"error_count,omitempty"`
	ForensicNotes []string  `json:"forensic_notes,omitempty" yaml:"forensic_notes,omitempty"`
	ParsedAt      time.Time `json:"parsed_at" yaml:"parsed_at"`
}

// NX-OS Specific Forensic Data Structures
// Based on Cisco NX-OS Software Forensic Data Collection Procedures

// NXOSSocketData represents NX-OS socket connection information for forensic analysis
type NXOSSocketData struct {
	TCPConnections []Connection `json:"tcp_connections" yaml:"tcp_connections"`
	UDPConnections []Connection `json:"udp_connections" yaml:"udp_connections"`
	RawSockets     []Connection `json:"raw_sockets,omitempty" yaml:"raw_sockets,omitempty"`
	ForensicNotes  []string     `json:"forensic_notes,omitempty" yaml:"forensic_notes,omitempty"`
	ParsedAt       time.Time    `json:"parsed_at" yaml:"parsed_at"`
}

// SoftwareAuthenticityData represents NX-OS software authenticity verification
type SoftwareAuthenticityData struct {
	ImageType          string            `json:"image_type" yaml:"image_type"`
	SignerInfo         map[string]string `json:"signer_info" yaml:"signer_info"`
	CertificateSerial  string            `json:"certificate_serial" yaml:"certificate_serial"`
	HashAlgorithm      string            `json:"hash_algorithm" yaml:"hash_algorithm"`
	SignatureAlgorithm string            `json:"signature_algorithm" yaml:"signature_algorithm"`
	KeyVersion         string            `json:"key_version" yaml:"key_version"`
	VerifierInfo       map[string]string `json:"verifier_info,omitempty" yaml:"verifier_info,omitempty"`
	ForensicNotes      []string          `json:"forensic_notes,omitempty" yaml:"forensic_notes,omitempty"`
	ParsedAt           time.Time         `json:"parsed_at" yaml:"parsed_at"`
}

// AuthenticityKeysData represents NX-OS public key information
type AuthenticityKeysData struct {
	PublicKeys    []PublicKeyInfo `json:"public_keys" yaml:"public_keys"`
	ForensicNotes []string        `json:"forensic_notes,omitempty" yaml:"forensic_notes,omitempty"`
	ParsedAt      time.Time       `json:"parsed_at" yaml:"parsed_at"`
}

// PublicKeyInfo represents a single public key for verification
type PublicKeyInfo struct {
	KeyType     string `json:"key_type" yaml:"key_type"`
	Algorithm   string `json:"algorithm" yaml:"algorithm"`
	Modulus     string `json:"modulus" yaml:"modulus"`
	Exponent    string `json:"exponent" yaml:"exponent"`
	KeyVersion  string `json:"key_version" yaml:"key_version"`
	ProductName string `json:"product_name" yaml:"product_name"`
	Storage     string `json:"storage,omitempty" yaml:"storage,omitempty"`
}

// BootInfo represents NX-OS boot configuration information
type BootInfo struct {
	SystemVariable    string    `json:"system_variable" yaml:"system_variable"`
	KickstartVariable string    `json:"kickstart_variable,omitempty" yaml:"kickstart_variable,omitempty"`
	POAPStatus        string    `json:"poap_status" yaml:"poap_status"`
	BootVariables     []string  `json:"boot_variables,omitempty" yaml:"boot_variables,omitempty"`
	ParsedAt          time.Time `json:"parsed_at" yaml:"parsed_at"`
}

// VDCData represents Virtual Device Context information for NX-OS
type VDCData struct {
	VDCs          []VDCInfo `json:"vdcs" yaml:"vdcs"`
	ForensicNotes []string  `json:"forensic_notes,omitempty" yaml:"forensic_notes,omitempty"`
	ParsedAt      time.Time `json:"parsed_at" yaml:"parsed_at"`
}

// VDCInfo represents a single Virtual Device Context
type VDCInfo struct {
	ID    string `json:"id" yaml:"id"`
	Name  string `json:"name" yaml:"name"`
	State string `json:"state" yaml:"state"`
	Owner string `json:"owner" yaml:"owner"`
	Type  string `json:"type,omitempty" yaml:"type,omitempty"`
	MAC   string `json:"mac,omitempty" yaml:"mac,omitempty"`
}

// VirtualServiceData represents virtual service information (guestshell, etc.)
type VirtualServiceData struct {
	Services      []VirtualService `json:"services" yaml:"services"`
	ForensicNotes []string         `json:"forensic_notes,omitempty" yaml:"forensic_notes,omitempty"`
	ParsedAt      time.Time        `json:"parsed_at" yaml:"parsed_at"`
}

// VirtualService represents a single virtual service
type VirtualService struct {
	Name    string `json:"name" yaml:"name"`
	Status  string `json:"status" yaml:"status"`
	Package string `json:"package" yaml:"package"`
	Version string `json:"version,omitempty" yaml:"version,omitempty"`
}

// GuestShellData represents guest shell configuration and forensic information
type GuestShellData struct {
	State         string            `json:"state" yaml:"state"`
	Version       string            `json:"version" yaml:"version"`
	Resources     map[string]string `json:"resources" yaml:"resources"`
	Devices       []string          `json:"devices,omitempty" yaml:"devices,omitempty"`
	ForensicNotes []string          `json:"forensic_notes,omitempty" yaml:"forensic_notes,omitempty"`
	ParsedAt      time.Time         `json:"parsed_at" yaml:"parsed_at"`
}

// CoreFileData represents core file information for forensic analysis
type CoreFileData struct {
	CoreFiles     []CoreFile `json:"core_files" yaml:"core_files"`
	ForensicNotes []string   `json:"forensic_notes,omitempty" yaml:"forensic_notes,omitempty"`
	ParsedAt      time.Time  `json:"parsed_at" yaml:"parsed_at"`
}

// CoreFile represents a single core file
type CoreFile struct {
	Name      string    `json:"name" yaml:"name"`
	Size      string    `json:"size" yaml:"size"`
	Date      string    `json:"date" yaml:"date"`
	Process   string    `json:"process" yaml:"process"`
	Path      string    `json:"path,omitempty" yaml:"path,omitempty"`
	Hash      string    `json:"hash,omitempty" yaml:"hash,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty" yaml:"created_at,omitempty"`
}

// FeatureData represents NX-OS feature configuration
type FeatureData struct {
	Features      []Feature `json:"features" yaml:"features"`
	ForensicNotes []string  `json:"forensic_notes,omitempty" yaml:"forensic_notes,omitempty"`
	ParsedAt      time.Time `json:"parsed_at" yaml:"parsed_at"`
}

// Feature represents a single NX-OS feature
type Feature struct {
	Name        string `json:"name" yaml:"name"`
	Status      string `json:"status" yaml:"status"`
	Instance    string `json:"instance,omitempty" yaml:"instance,omitempty"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// Module represents NX-OS module information
type Module struct {
	Slot     string `json:"slot" yaml:"slot"`
	Type     string `json:"type" yaml:"type"`
	Model    string `json:"model" yaml:"model"`
	Status   string `json:"status" yaml:"status"`
	Serial   string `json:"serial,omitempty" yaml:"serial,omitempty"`
	Hardware string `json:"hardware,omitempty" yaml:"hardware,omitempty"`
	Software string `json:"software,omitempty" yaml:"software,omitempty"`
}

// VPCData represents Virtual Port Channel information
type VPCData struct {
	DomainID      string            `json:"domain_id" yaml:"domain_id"`
	PeerStatus    string            `json:"peer_status" yaml:"peer_status"`
	PeerAddress   string            `json:"peer_address,omitempty" yaml:"peer_address,omitempty"`
	Role          string            `json:"role,omitempty" yaml:"role,omitempty"`
	SystemMAC     string            `json:"system_mac,omitempty" yaml:"system_mac,omitempty"`
	PeerMAC       string            `json:"peer_mac,omitempty" yaml:"peer_mac,omitempty"`
	Configuration map[string]string `json:"configuration,omitempty" yaml:"configuration,omitempty"`
	ForensicNotes []string          `json:"forensic_notes,omitempty" yaml:"forensic_notes,omitempty"`
	ParsedAt      time.Time         `json:"parsed_at" yaml:"parsed_at"`
}

// SystemInternalData represents NX-OS system internal information
type SystemInternalData struct {
	ProcessInfo   map[string]interface{} `json:"process_info" yaml:"process_info"`
	KernelInfo    map[string]interface{} `json:"kernel_info,omitempty" yaml:"kernel_info,omitempty"`
	MemoryInfo    map[string]interface{} `json:"memory_info,omitempty" yaml:"memory_info,omitempty"`
	ForensicNotes []string               `json:"forensic_notes,omitempty" yaml:"forensic_notes,omitempty"`
	ParsedAt      time.Time              `json:"parsed_at" yaml:"parsed_at"`
}

// FTD (Firepower Threat Defense) Specific Forensic Data Structures
// Based on Cisco FTD Software Forensic Data Collection Procedures
// https://sec.cloudapps.cisco.com/security/center/resources/forensic_guides/ftd_forensic_investigation.html

// FTDDigitalSignatureData represents FTD digital signature verification results
type FTDDigitalSignatureData struct {
	RunningImageAuth    *SoftwareAuthenticityData            `json:"running_image_auth,omitempty" yaml:"running_image_auth,omitempty"`
	FileAuthentications map[string]*SoftwareAuthenticityData `json:"file_authentications,omitempty" yaml:"file_authentications,omitempty"`
	PublicKeys          *AuthenticityKeysData                `json:"public_keys,omitempty" yaml:"public_keys,omitempty"`
	TamperingDetected   bool                                 `json:"tampering_detected" yaml:"tampering_detected"`
	ForensicNotes       []string                             `json:"forensic_notes,omitempty" yaml:"forensic_notes,omitempty"`
	ParsedAt            time.Time                            `json:"parsed_at" yaml:"parsed_at"`
}

// FTDImageVerificationData represents comprehensive FTD image verification results
type FTDImageVerificationData struct {
	SystemImages      map[string]*FTDImageInfo  `json:"system_images" yaml:"system_images"`
	HashVerifications map[string]*FTDHashResult `json:"hash_verifications" yaml:"hash_verifications"`
	MemoryTextHash    *FTDHashResult            `json:"memory_text_hash,omitempty" yaml:"memory_text_hash,omitempty"`
	TamperingDetected bool                      `json:"tampering_detected" yaml:"tampering_detected"`
	ForensicNotes     []string                  `json:"forensic_notes,omitempty" yaml:"forensic_notes,omitempty"`
	VerifiedAt        time.Time                 `json:"verified_at" yaml:"verified_at"`
}

// FTDImageInfo represents detailed FTD system image information
type FTDImageInfo struct {
	Filename      string                    `json:"filename" yaml:"filename"`
	Location      string                    `json:"location" yaml:"location"`
	Size          string                    `json:"size,omitempty" yaml:"size,omitempty"`
	HashMD5       string                    `json:"hash_md5,omitempty" yaml:"hash_md5,omitempty"`
	HashSHA512    string                    `json:"hash_sha512,omitempty" yaml:"hash_sha512,omitempty"`
	Verification  *FileVerification         `json:"verification,omitempty" yaml:"verification,omitempty"`
	Authenticity  *SoftwareAuthenticityData `json:"authenticity,omitempty" yaml:"authenticity,omitempty"`
	ForensicNotes []string                  `json:"forensic_notes,omitempty" yaml:"forensic_notes,omitempty"`
	VerifiedAt    time.Time                 `json:"verified_at" yaml:"verified_at"`
}

// FTDHashResult represents hash verification results
type FTDHashResult struct {
	Filename   string    `json:"filename" yaml:"filename"`
	Algorithm  string    `json:"algorithm" yaml:"algorithm"`
	Hash       string    `json:"hash" yaml:"hash"`
	Expected   string    `json:"expected,omitempty" yaml:"expected,omitempty"`
	Verified   bool      `json:"verified" yaml:"verified"`
	Mismatch   bool      `json:"mismatch" yaml:"mismatch"`
	ComputedAt time.Time `json:"computed_at" yaml:"computed_at"`
}

// FTDMemoryAnalysisData represents FTD memory segment analysis
type FTDMemoryAnalysisData struct {
	TextSegmentHash   *FTDHashResult `json:"text_segment_hash,omitempty" yaml:"text_segment_hash,omitempty"`
	TextSegmentDump   *FTDMemoryDump `json:"text_segment_dump,omitempty" yaml:"text_segment_dump,omitempty"`
	TamperingDetected bool           `json:"tampering_detected" yaml:"tampering_detected"`
	ForensicNotes     []string       `json:"forensic_notes,omitempty" yaml:"forensic_notes,omitempty"`
	AnalyzedAt        time.Time      `json:"analyzed_at" yaml:"analyzed_at"`
}

// FTDMemoryDump represents a memory dump file
type FTDMemoryDump struct {
	Filename      string    `json:"filename" yaml:"filename"`
	Size          int64     `json:"size" yaml:"size"`
	Hash          string    `json:"hash,omitempty" yaml:"hash,omitempty"`
	HashAlgorithm string    `json:"hash_algorithm,omitempty" yaml:"hash_algorithm,omitempty"`
	DumpedAt      time.Time `json:"dumped_at" yaml:"dumped_at"`
	Location      string    `json:"location,omitempty" yaml:"location,omitempty"`
}

// FTDCrashInfoData represents FTD crashinfo and core dump information
type FTDCrashInfoData struct {
	CrashInfoFiles []FTDCrashFile `json:"crashinfo_files" yaml:"crashinfo_files"`
	CoreFiles      []FTDCoreFile  `json:"core_files,omitempty" yaml:"core_files,omitempty"`
	ForensicNotes  []string       `json:"forensic_notes,omitempty" yaml:"forensic_notes,omitempty"`
	CollectedAt    time.Time      `json:"collected_at" yaml:"collected_at"`
}

// FTDCrashFile represents a crashinfo file
type FTDCrashFile struct {
	Filename    string    `json:"filename" yaml:"filename"`
	Size        int64     `json:"size" yaml:"size"`
	CreatedAt   time.Time `json:"created_at" yaml:"created_at"`
	Hash        string    `json:"hash,omitempty" yaml:"hash,omitempty"`
	Location    string    `json:"location" yaml:"location"`
	ThreadInfo  string    `json:"thread_info,omitempty" yaml:"thread_info,omitempty"`
	CrashReason string    `json:"crash_reason,omitempty" yaml:"crash_reason,omitempty"`
}

// FTDCoreFile represents a core dump file
type FTDCoreFile struct {
	Filename   string    `json:"filename" yaml:"filename"`
	Size       int64     `json:"size" yaml:"size"`
	Process    string    `json:"process" yaml:"process"`
	CreatedAt  time.Time `json:"created_at" yaml:"created_at"`
	Hash       string    `json:"hash,omitempty" yaml:"hash,omitempty"`
	Location   string    `json:"location" yaml:"location"`
	SourcePath string    `json:"source_path,omitempty" yaml:"source_path,omitempty"`
}

// FTDROMMonitorData represents FTD ROM monitor forensic information
type FTDROMMonitorData struct {
	Variables     map[string]string `json:"variables" yaml:"variables"`
	BootSequence  []string          `json:"boot_sequence,omitempty" yaml:"boot_sequence,omitempty"`
	Tampered      bool              `json:"tampered" yaml:"tampered"`
	ForensicNotes []string          `json:"forensic_notes,omitempty" yaml:"forensic_notes,omitempty"`
	CollectedAt   time.Time         `json:"collected_at" yaml:"collected_at"`
}

// FTDConnectionData represents FTD connection analysis for forensic investigation
type FTDConnectionData struct {
	ActiveConnections []FTDConnection `json:"active_connections" yaml:"active_connections"`
	NATTranslations   []FTDNATEntry   `json:"nat_translations,omitempty" yaml:"nat_translations,omitempty"`
	SuspiciousTraffic []FTDConnection `json:"suspicious_traffic,omitempty" yaml:"suspicious_traffic,omitempty"`
	ForensicNotes     []string        `json:"forensic_notes,omitempty" yaml:"forensic_notes,omitempty"`
	AnalyzedAt        time.Time       `json:"analyzed_at" yaml:"analyzed_at"`
}

// FTDConnection represents an FTD connection with forensic context
type FTDConnection struct {
	Protocol        string   `json:"protocol" yaml:"protocol"`
	SourceInterface string   `json:"source_interface,omitempty" yaml:"source_interface,omitempty"`
	SourceAddress   string   `json:"source_address" yaml:"source_address"`
	SourcePort      string   `json:"source_port" yaml:"source_port"`
	DestInterface   string   `json:"dest_interface,omitempty" yaml:"dest_interface,omitempty"`
	DestAddress     string   `json:"dest_address" yaml:"dest_address"`
	DestPort        string   `json:"dest_port" yaml:"dest_port"`
	State           string   `json:"state,omitempty" yaml:"state,omitempty"`
	IdleTime        string   `json:"idle_time,omitempty" yaml:"idle_time,omitempty"`
	ByteCount       string   `json:"byte_count,omitempty" yaml:"byte_count,omitempty"`
	ConnectionFlags []string `json:"connection_flags,omitempty" yaml:"connection_flags,omitempty"`
	Suspicious      bool     `json:"suspicious" yaml:"suspicious"`
	SuspicionReason string   `json:"suspicion_reason,omitempty" yaml:"suspicion_reason,omitempty"`
}

// FTDNATEntry represents an FTD NAT translation entry
type FTDNATEntry struct {
	Direction    string `json:"direction" yaml:"direction"`
	OriginalAddr string `json:"original_addr" yaml:"original_addr"`
	OriginalPort string `json:"original_port,omitempty" yaml:"original_port,omitempty"`
	MappedAddr   string `json:"mapped_addr" yaml:"mapped_addr"`
	MappedPort   string `json:"mapped_port,omitempty" yaml:"mapped_port,omitempty"`
	Protocol     string `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	Flags        string `json:"flags,omitempty" yaml:"flags,omitempty"`
	IdleTime     string `json:"idle_time,omitempty" yaml:"idle_time,omitempty"`
}

// FTDThreatAnalysisData represents FTD threat detection analysis
type FTDThreatAnalysisData struct {
	ThreatDetectionStatus string              `json:"threat_detection_status" yaml:"threat_detection_status"`
	ActiveThreats         []FTDThreatEvent    `json:"active_threats,omitempty" yaml:"active_threats,omitempty"`
	SecurityEvents        []FTDSecurityEvent  `json:"security_events,omitempty" yaml:"security_events,omitempty"`
	IntrusionEvents       []FTDIntrusionEvent `json:"intrusion_events,omitempty" yaml:"intrusion_events,omitempty"`
	MalwareEvents         []FTDMalwareEvent   `json:"malware_events,omitempty" yaml:"malware_events,omitempty"`
	ForensicNotes         []string            `json:"forensic_notes,omitempty" yaml:"forensic_notes,omitempty"`
	AnalyzedAt            time.Time           `json:"analyzed_at" yaml:"analyzed_at"`
}

// FTDThreatEvent represents a detected threat event
type FTDThreatEvent struct {
	EventID     string    `json:"event_id" yaml:"event_id"`
	ThreatType  string    `json:"threat_type" yaml:"threat_type"`
	Severity    string    `json:"severity" yaml:"severity"`
	SourceIP    string    `json:"source_ip,omitempty" yaml:"source_ip,omitempty"`
	DestIP      string    `json:"dest_ip,omitempty" yaml:"dest_ip,omitempty"`
	Description string    `json:"description,omitempty" yaml:"description,omitempty"`
	Action      string    `json:"action,omitempty" yaml:"action,omitempty"`
	Timestamp   time.Time `json:"timestamp" yaml:"timestamp"`
	Interface   string    `json:"interface,omitempty" yaml:"interface,omitempty"`
}

// FTDSecurityEvent represents a security-related event
type FTDSecurityEvent struct {
	EventType string    `json:"event_type" yaml:"event_type"`
	Message   string    `json:"message" yaml:"message"`
	SourceIP  string    `json:"source_ip,omitempty" yaml:"source_ip,omitempty"`
	User      string    `json:"user,omitempty" yaml:"user,omitempty"`
	Action    string    `json:"action,omitempty" yaml:"action,omitempty"`
	Timestamp time.Time `json:"timestamp" yaml:"timestamp"`
	Critical  bool      `json:"critical" yaml:"critical"`
}

// FTDIntrusionEvent represents an intrusion detection event
type FTDIntrusionEvent struct {
	RuleID     string    `json:"rule_id" yaml:"rule_id"`
	Signature  string    `json:"signature" yaml:"signature"`
	Priority   string    `json:"priority" yaml:"priority"`
	SourceIP   string    `json:"source_ip" yaml:"source_ip"`
	SourcePort string    `json:"source_port,omitempty" yaml:"source_port,omitempty"`
	DestIP     string    `json:"dest_ip" yaml:"dest_ip"`
	DestPort   string    `json:"dest_port,omitempty" yaml:"dest_port,omitempty"`
	Protocol   string    `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	Action     string    `json:"action" yaml:"action"`
	Timestamp  time.Time `json:"timestamp" yaml:"timestamp"`
	Blocked    bool      `json:"blocked" yaml:"blocked"`
}

// FTDMalwareEvent represents a malware detection event
type FTDMalwareEvent struct {
	Filename    string    `json:"filename" yaml:"filename"`
	FileHash    string    `json:"file_hash,omitempty" yaml:"file_hash,omitempty"`
	MalwareType string    `json:"malware_type" yaml:"malware_type"`
	ThreatName  string    `json:"threat_name" yaml:"threat_name"`
	SourceIP    string    `json:"source_ip,omitempty" yaml:"source_ip,omitempty"`
	DestIP      string    `json:"dest_ip,omitempty" yaml:"dest_ip,omitempty"`
	Action      string    `json:"action" yaml:"action"`
	Disposition string    `json:"disposition" yaml:"disposition"`
	Timestamp   time.Time `json:"timestamp" yaml:"timestamp"`
	Quarantined bool      `json:"quarantined" yaml:"quarantined"`
}

// FTDVPNAnalysisData represents FTD VPN session analysis
type FTDVPNAnalysisData struct {
	ActiveSessions     []FTDVPNSession `json:"active_sessions" yaml:"active_sessions"`
	SuspiciousSessions []FTDVPNSession `json:"suspicious_sessions,omitempty" yaml:"suspicious_sessions,omitempty"`
	ForensicNotes      []string        `json:"forensic_notes,omitempty" yaml:"forensic_notes,omitempty"`
	AnalyzedAt         time.Time       `json:"analyzed_at" yaml:"analyzed_at"`
}

// FTDVPNSession represents an FTD VPN session with forensic details
type FTDVPNSession struct {
	SessionID        string    `json:"session_id" yaml:"session_id"`
	User             string    `json:"user,omitempty" yaml:"user,omitempty"`
	GroupPolicy      string    `json:"group_policy,omitempty" yaml:"group_policy,omitempty"`
	ClientIP         string    `json:"client_ip" yaml:"client_ip"`
	AssignedIP       string    `json:"assigned_ip,omitempty" yaml:"assigned_ip,omitempty"`
	TunnelType       string    `json:"tunnel_type,omitempty" yaml:"tunnel_type,omitempty"`
	Encryption       string    `json:"encryption,omitempty" yaml:"encryption,omitempty"`
	LoginTime        time.Time `json:"login_time" yaml:"login_time"`
	Duration         string    `json:"duration,omitempty" yaml:"duration,omitempty"`
	BytesTransmitted string    `json:"bytes_transmitted,omitempty" yaml:"bytes_transmitted,omitempty"`
	BytesReceived    string    `json:"bytes_received,omitempty" yaml:"bytes_received,omitempty"`
	Suspicious       bool      `json:"suspicious" yaml:"suspicious"`
	SuspicionReason  string    `json:"suspicion_reason,omitempty" yaml:"suspicion_reason,omitempty"`
}

// FTDFailoverData represents FTD failover status and configuration
type FTDFailoverData struct {
	Status         string            `json:"status" yaml:"status"`
	Role           string            `json:"role,omitempty" yaml:"role,omitempty"`
	PeerStatus     string            `json:"peer_status,omitempty" yaml:"peer_status,omitempty"`
	PeerAddress    string            `json:"peer_address,omitempty" yaml:"peer_address,omitempty"`
	Configuration  map[string]string `json:"configuration,omitempty" yaml:"configuration,omitempty"`
	LastFailover   time.Time         `json:"last_failover,omitempty" yaml:"last_failover,omitempty"`
	FailoverReason string            `json:"failover_reason,omitempty" yaml:"failover_reason,omitempty"`
	ForensicNotes  []string          `json:"forensic_notes,omitempty" yaml:"forensic_notes,omitempty"`
	AnalyzedAt     time.Time         `json:"analyzed_at" yaml:"analyzed_at"`
}

// Legacy types used by older parsers - these should be migrated to newer structures
// ARPEntry represents ARP table entries (legacy - use Connection instead for new implementations)
type ARPEntry struct {
	IPAddress  string `json:"ip_address" yaml:"ip_address"`
	MACAddress string `json:"mac_address" yaml:"mac_address"`
	Interface  string `json:"interface,omitempty" yaml:"interface,omitempty"`
	Type       string `json:"type,omitempty" yaml:"type,omitempty"`
	Age        string `json:"age,omitempty" yaml:"age,omitempty"`
}

// NATEntry represents NAT translation entries (legacy - use Connection instead for new implementations)
type NATEntry struct {
	Protocol      string `json:"protocol" yaml:"protocol"`
	InsideLocal   string `json:"inside_local" yaml:"inside_local"`
	InsideGlobal  string `json:"inside_global" yaml:"inside_global"`
	OutsideLocal  string `json:"outside_local" yaml:"outside_local"`
	OutsideGlobal string `json:"outside_global" yaml:"outside_global"`
}

// TCPConnection represents TCP connection entries (legacy - use Connection instead for new implementations)
type TCPConnection struct {
	LocalAddress  string `json:"local_address" yaml:"local_address"`
	LocalPort     string `json:"local_port" yaml:"local_port"`
	RemoteAddress string `json:"remote_address" yaml:"remote_address"`
	RemotePort    string `json:"remote_port" yaml:"remote_port"`
	State         string `json:"state" yaml:"state"`
	Process       string `json:"process,omitempty" yaml:"process,omitempty"`
}
