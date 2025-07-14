package cisco

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"netdac/internal/core"
)

// NXOSParser handles parsing of NX-OS command outputs for forensic analysis
// Implements specialized parsing for Cisco NX-OS Software Forensic Data Collection Procedures
type NXOSParser struct {
	patterns map[string]*regexp.Regexp
}

// NewNXOSParser creates a new NX-OS parser instance
func NewNXOSParser() *NXOSParser {
	return &NXOSParser{
		patterns: map[string]*regexp.Regexp{
			"hostname":        regexp.MustCompile(`(\w+)#\s*$`),
			"version":         regexp.MustCompile(`NXOS:\s+version\s+(\S+)`),
			"model":           regexp.MustCompile(`cisco\s+(Nexus\s+\d+|N\d+K)`),
			"serial":          regexp.MustCompile(`Processor Board ID\s+(\w+)`),
			"uptime":          regexp.MustCompile(`(\w+) uptime is (.+)`),
			"device_name":     regexp.MustCompile(`Device name:\s+(\S+)`),
			"system_image":    regexp.MustCompile(`system image file is:\s+(\S+)`),
			"kickstart_image": regexp.MustCompile(`kickstart image file is:\s+(\S+)`),
			"tcp_conn":        regexp.MustCompile(`tcp\s+(\S+)\s+\d+\s+(\S+)\((\d+)\)\s*(\S+)\((\d+)\)`),
			"udp_conn":        regexp.MustCompile(`udp\s+(\S+)\s+\d+\s+(\S+)\((\d+)\)`),
			"interface":       regexp.MustCompile(`^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)`),
			"process":         regexp.MustCompile(`(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(.+)`),
			"route":           regexp.MustCompile(`(\S+)\s+(\S+)\s+(\S+)`),
			"vdc":             regexp.MustCompile(`(\d+)\s+(\S+)\s+(\S+)\s+(\S+)`),
			"feature":         regexp.MustCompile(`(\S+)\s+\d+\s+(enabled|disabled)`),
			"module":          regexp.MustCompile(`(\d+)\s+(\S+)\s+(\S+)\s+(\S+)`),
			"core_file":       regexp.MustCompile(`(\S+)\s+(\d+)\s+(\S+)\s+(\S+)`),
		},
	}
}

// ParseCommand parses a command output based on the command type
func (p *NXOSParser) ParseCommand(command string, output string) (interface{}, error) {
	switch {
	case strings.Contains(command, "show version"):
		return p.ParseVersion(output)
	case strings.Contains(command, "show tech-support"):
		return p.ParseTechSupport(output)
	case strings.Contains(command, "show processes"):
		return p.ParseProcesses(output)
	case strings.Contains(command, "show sockets connection"):
		return p.ParseSocketConnections(output)
	case strings.Contains(command, "show interfaces"):
		return p.ParseInterfaces(output)
	case strings.Contains(command, "show software authenticity running"):
		return p.ParseSoftwareAuthenticity(output)
	case strings.Contains(command, "show software authenticity keys"):
		return p.ParseAuthenticityKeys(output)
	case strings.Contains(command, "show boot"):
		return p.ParseBootInfo(output)
	case strings.Contains(command, "show vdc"):
		return p.ParseVDC(output)
	case strings.Contains(command, "show virtual-service list"):
		return p.ParseVirtualServices(output)
	case strings.Contains(command, "show guestshell detail"):
		return p.ParseGuestShell(output)
	case strings.Contains(command, "show cores"):
		return p.ParseCoreFiles(output)
	case strings.Contains(command, "show feature"):
		return p.ParseFeatures(output)
	case strings.Contains(command, "show module"):
		return p.ParseModules(output)
	case strings.Contains(command, "show vpc"):
		return p.ParseVPC(output)
	case strings.Contains(command, "show logging"):
		return p.ParseSystemLogs(output)
	case strings.Contains(command, "show users"):
		return p.ParseSessions(output)
	case strings.Contains(command, "show ip route"):
		return p.ParseRoutes(output)
	case strings.Contains(command, "show install"):
		return p.ParseInstallInfo(output)
	case strings.Contains(command, "dir"):
		return p.ParseDirectoryListing(output)
	case strings.Contains(command, "show system internal"):
		return p.ParseSystemInternal(output)
	default:
		// Return raw output for unparsed commands
		return map[string]interface{}{
			"raw_output": output,
			"command":    command,
		}, nil
	}
}

// ParseVersion extracts device information from show version output
func (p *NXOSParser) ParseVersion(output string) (*core.DeviceInfo, error) {
	info := &core.DeviceInfo{
		Vendor: "cisco",
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Extract hostname from prompt or device name
		if match := p.patterns["hostname"].FindStringSubmatch(line); match != nil {
			info.Hostname = match[1]
		}
		if match := p.patterns["device_name"].FindStringSubmatch(line); match != nil {
			info.Hostname = match[1]
		}

		// Extract NX-OS version
		if match := p.patterns["version"].FindStringSubmatch(line); match != nil {
			info.Version = match[1]
		}

		// Extract model (Nexus series)
		if match := p.patterns["model"].FindStringSubmatch(line); match != nil {
			info.Model = strings.TrimSpace(match[1])
		}

		// Extract serial number
		if match := p.patterns["serial"].FindStringSubmatch(line); match != nil {
			info.SerialNumber = match[1]
		}

		// Extract uptime
		if match := p.patterns["uptime"].FindStringSubmatch(line); match != nil {
			info.Uptime = match[2]
		}
	}

	return info, nil
}

// ParseTechSupport analyzes tech-support output for forensic evidence
func (p *NXOSParser) ParseTechSupport(output string) (*core.TechSupportData, error) {
	data := &core.TechSupportData{
		GeneratedAt:   time.Now(),
		Size:          len(output),
		CommandCount:  strings.Count(output, "show "),
		ForensicNotes: []string{},
		ParsedAt:      time.Now(),
	}

	// Check for suspicious patterns in tech-support
	suspiciousPatterns := []string{
		"core dump",
		"segmentation fault",
		"memory corruption",
		"unexpected reboot",
		"authentication failure",
		"privilege escalation",
		"container escape",
		"docker manipulation",
		"guestshell abuse",
		"vdc violation",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(strings.ToLower(output), pattern) {
			data.ForensicNotes = append(data.ForensicNotes,
				fmt.Sprintf("SUSPICIOUS: Found pattern '%s' in tech-support", pattern))
		}
	}

	// Extract critical information
	if strings.Contains(output, "crash") {
		data.ForensicNotes = append(data.ForensicNotes, "ALERT: Crash information detected")
	}

	if strings.Contains(output, "error") {
		data.ErrorCount = strings.Count(strings.ToLower(output), "error")
	}

	// Check for VDC-related issues
	if strings.Contains(output, "vdc") && strings.Contains(strings.ToLower(output), "error") {
		data.ForensicNotes = append(data.ForensicNotes, "WARNING: VDC-related errors detected")
	}

	return data, nil
}

// ParseProcesses extracts process information for forensic analysis
func (p *NXOSParser) ParseProcesses(output string) ([]core.Process, error) {
	var processes []core.Process
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if match := p.patterns["process"].FindStringSubmatch(line); match != nil {
			processes = append(processes, core.Process{
				PID:         match[1],
				Name:        strings.TrimSpace(match[5]),
				CommandLine: strings.TrimSpace(match[5]),
				State:       match[3],
			})
		}
	}

	return processes, nil
}

// ParseSocketConnections extracts NX-OS socket connection information
func (p *NXOSParser) ParseSocketConnections(output string) (*core.NXOSSocketData, error) {
	data := &core.NXOSSocketData{
		TCPConnections: []core.Connection{},
		UDPConnections: []core.Connection{},
		ForensicNotes:  []string{},
		ParsedAt:       time.Now(),
	}

	lines := strings.Split(output, "\n")
	currentProtocol := ""

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Detect protocol sections
		if strings.Contains(line, "netstack tcp sockets") {
			currentProtocol = "tcp"
			continue
		}
		if strings.Contains(line, "netstack udp sockets") {
			currentProtocol = "udp"
			continue
		}
		if strings.Contains(line, "netstack raw sockets") {
			currentProtocol = "raw"
			continue
		}

		// Parse TCP connections
		if currentProtocol == "tcp" {
			if match := p.patterns["tcp_conn"].FindStringSubmatch(line); match != nil {
				conn := core.Connection{
					Protocol:      "TCP",
					State:         match[1],
					LocalAddress:  match[2],
					LocalPort:     match[3],
					RemoteAddress: match[4],
					RemotePort:    match[5],
				}
				data.TCPConnections = append(data.TCPConnections, conn)

				// Check for suspicious connections
				if conn.State == "ESTABLISHED" && (conn.RemotePort == "22" || conn.RemotePort == "23") {
					data.ForensicNotes = append(data.ForensicNotes,
						fmt.Sprintf("FORENSIC: Active remote connection to %s:%s", conn.RemoteAddress, conn.RemotePort))
				}
			}
		}

		// Parse UDP connections
		if currentProtocol == "udp" {
			if match := p.patterns["udp_conn"].FindStringSubmatch(line); match != nil {
				conn := core.Connection{
					Protocol:     "UDP",
					LocalAddress: match[2],
					LocalPort:    match[3],
					State:        "LISTEN",
				}
				data.UDPConnections = append(data.UDPConnections, conn)
			}
		}
	}

	return data, nil
}

// ParseInterfaces extracts interface information
func (p *NXOSParser) ParseInterfaces(output string) ([]core.Interface, error) {
	var interfaces []core.Interface
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if match := p.patterns["interface"].FindStringSubmatch(line); match != nil {
			interfaces = append(interfaces, core.Interface{
				Name:        match[1],
				Status:      match[2],
				AdminStatus: match[3],
				Description: match[4],
			})
		}
	}

	return interfaces, nil
}

// ParseSoftwareAuthenticity analyzes software authenticity verification
func (p *NXOSParser) ParseSoftwareAuthenticity(output string) (*core.SoftwareAuthenticityData, error) {
	data := &core.SoftwareAuthenticityData{
		ImageType:          "Unknown",
		SignerInfo:         map[string]string{},
		CertificateSerial:  "",
		HashAlgorithm:      "",
		SignatureAlgorithm: "",
		KeyVersion:         "",
		ForensicNotes:      []string{},
		ParsedAt:           time.Now(),
	}

	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.Contains(line, "Image type") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				data.ImageType = strings.TrimSpace(parts[1])
			}
		}

		if strings.Contains(line, "Common Name") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				data.SignerInfo["CommonName"] = strings.TrimSpace(parts[1])
			}
		}

		if strings.Contains(line, "Organization") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				data.SignerInfo["Organization"] = strings.TrimSpace(parts[1])
			}
		}

		if strings.Contains(line, "Certificate Serial Number") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				data.CertificateSerial = strings.TrimSpace(parts[1])
			}
		}

		if strings.Contains(line, "Hash Algorithm") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				data.HashAlgorithm = strings.TrimSpace(parts[1])
			}
		}

		if strings.Contains(line, "Signature Algorithm") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				data.SignatureAlgorithm = strings.TrimSpace(parts[1])
			}
		}

		if strings.Contains(line, "Key Version") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				data.KeyVersion = strings.TrimSpace(parts[1])
			}
		}
	}

	// Add forensic notes based on findings
	if data.ImageType != "Release" {
		data.ForensicNotes = append(data.ForensicNotes,
			fmt.Sprintf("WARNING: Non-release image type detected: %s", data.ImageType))
	}

	if data.SignerInfo["CommonName"] != "CiscoSystems" {
		data.ForensicNotes = append(data.ForensicNotes, "ALERT: Unexpected signer detected")
	}

	return data, nil
}

// ParseAuthenticityKeys extracts public key information
func (p *NXOSParser) ParseAuthenticityKeys(output string) (*core.AuthenticityKeysData, error) {
	data := &core.AuthenticityKeysData{
		PublicKeys:    []core.PublicKeyInfo{},
		ForensicNotes: []string{},
		ParsedAt:      time.Now(),
	}

	lines := strings.Split(output, "\n")
	var currentKey *core.PublicKeyInfo
	var inKeyBlock bool
	var keyName string

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Start of a new key entry
		if strings.Contains(line, "Public Key") && strings.Contains(line, ":") {
			// Save previous key if exists
			if currentKey != nil {
				data.PublicKeys = append(data.PublicKeys, *currentKey)
			}

			// Start new key
			currentKey = &core.PublicKeyInfo{
				KeyType:     "",
				Algorithm:   "",
				Modulus:     "",
				Exponent:    "",
				KeyVersion:  "",
				ProductName: "",
				Storage:     "",
			}

			// Extract key name from line like "Public Key cisco-ta:"
			parts := strings.Split(line, ":")
			if len(parts) >= 1 {
				keyName = strings.TrimSpace(strings.Replace(parts[0], "Public Key", "", 1))
				currentKey.ProductName = keyName // Use ProductName to store key name
			}
			inKeyBlock = true
			continue
		}

		// Parse key properties within a key block
		if inKeyBlock && currentKey != nil {
			// Algorithm information
			if strings.Contains(line, "Algorithm") {
				parts := strings.Split(line, ":")
				if len(parts) == 2 {
					currentKey.Algorithm = strings.TrimSpace(parts[1])
				}
			}

			// Key type (RSA, DSA, etc.)
			if strings.Contains(line, "Key Type") || strings.Contains(line, "Type") {
				parts := strings.Split(line, ":")
				if len(parts) == 2 {
					currentKey.KeyType = strings.TrimSpace(parts[1])
				}
			}

			// Modulus
			if strings.Contains(line, "Modulus") {
				parts := strings.Split(line, ":")
				if len(parts) == 2 {
					currentKey.Modulus = strings.TrimSpace(parts[1])
				}
			}

			// Public Exponent
			if strings.Contains(line, "Exponent") {
				parts := strings.Split(line, ":")
				if len(parts) == 2 {
					currentKey.Exponent = strings.TrimSpace(parts[1])
				}
			}

			// Key version
			if strings.Contains(line, "Key Version") || strings.Contains(line, "Version") {
				parts := strings.Split(line, ":")
				if len(parts) == 2 {
					currentKey.KeyVersion = strings.TrimSpace(parts[1])
				}
			}

			// Storage location
			if strings.Contains(line, "Storage") || strings.Contains(line, "Location") {
				parts := strings.Split(line, ":")
				if len(parts) == 2 {
					currentKey.Storage = strings.TrimSpace(parts[1])
				}
			}

			// End of key block detection
			if line == "" || strings.HasPrefix(line, "---") || strings.HasPrefix(line, "=") {
				inKeyBlock = false
			}
		}
	}

	// Add the last key if exists
	if currentKey != nil {
		data.PublicKeys = append(data.PublicKeys, *currentKey)
	}

	// Add forensic analysis
	for _, key := range data.PublicKeys {
		// Check for Cisco-specific keys
		if strings.Contains(strings.ToLower(key.ProductName), "cisco") {
			data.ForensicNotes = append(data.ForensicNotes,
				fmt.Sprintf("FORENSIC: Cisco signing key detected: %s", key.ProductName))
		} else if key.ProductName != "" {
			data.ForensicNotes = append(data.ForensicNotes,
				fmt.Sprintf("WARNING: Non-Cisco signing key detected: %s", key.ProductName))
		}

		// Check key algorithm strength
		if key.Algorithm != "" {
			if strings.Contains(strings.ToLower(key.Algorithm), "rsa") {
				data.ForensicNotes = append(data.ForensicNotes,
					fmt.Sprintf("FORENSIC: RSA key detected for %s: %s", key.ProductName, key.Algorithm))
			}
		}

		// Check key type
		if key.KeyType != "" {
			data.ForensicNotes = append(data.ForensicNotes,
				fmt.Sprintf("FORENSIC: Key type %s detected for %s", key.KeyType, key.ProductName))
		}

		// Check key version
		if key.KeyVersion != "" {
			data.ForensicNotes = append(data.ForensicNotes,
				fmt.Sprintf("FORENSIC: Key version %s for %s", key.KeyVersion, key.ProductName))
		}

		// Check storage location
		if key.Storage != "" {
			data.ForensicNotes = append(data.ForensicNotes,
				fmt.Sprintf("FORENSIC: Key stored in %s for %s", key.Storage, key.ProductName))
		}

		// Check modulus for key strength indication
		if key.Modulus != "" {
			modulusLen := len(strings.ReplaceAll(key.Modulus, " ", ""))
			if modulusLen > 0 {
				data.ForensicNotes = append(data.ForensicNotes,
					fmt.Sprintf("FORENSIC: Key modulus length %d chars for %s", modulusLen, key.ProductName))
			}
		}
	}

	if len(data.PublicKeys) == 0 {
		data.ForensicNotes = append(data.ForensicNotes, "WARNING: No public keys found - this may indicate authenticity verification issues")
	} else {
		data.ForensicNotes = append(data.ForensicNotes,
			fmt.Sprintf("FORENSIC: %d public key(s) extracted for verification", len(data.PublicKeys)))
	}

	return data, nil
}

// ParseBootInfo extracts boot image information
func (p *NXOSParser) ParseBootInfo(output string) (*core.BootInfo, error) {
	info := &core.BootInfo{
		SystemVariable:    "",
		KickstartVariable: "",
		POAPStatus:        "",
		ParsedAt:          time.Now(),
	}

	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.Contains(line, "NXOS variable") || strings.Contains(line, "system variable") {
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				info.SystemVariable = strings.TrimSpace(parts[1])
			}
		}

		if strings.Contains(line, "kickstart variable") {
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				info.KickstartVariable = strings.TrimSpace(parts[1])
			}
		}

		if strings.Contains(line, "Boot POAP") {
			if strings.Contains(line, "Disabled") {
				info.POAPStatus = "Disabled"
			} else if strings.Contains(line, "Enabled") {
				info.POAPStatus = "Enabled"
			}
		}
	}

	return info, nil
}

// ParseVDC extracts Virtual Device Context information
func (p *NXOSParser) ParseVDC(output string) (*core.VDCData, error) {
	data := &core.VDCData{
		VDCs:          []core.VDCInfo{},
		ForensicNotes: []string{},
		ParsedAt:      time.Now(),
	}

	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if match := p.patterns["vdc"].FindStringSubmatch(line); match != nil {
			vdc := core.VDCInfo{
				ID:    match[1],
				Name:  match[2],
				State: match[3],
				Owner: match[4],
			}
			data.VDCs = append(data.VDCs, vdc)

			// Add forensic notes for multiple VDCs
			if vdc.ID != "1" {
				data.ForensicNotes = append(data.ForensicNotes,
					fmt.Sprintf("FORENSIC: Additional VDC detected - ID:%s Name:%s", vdc.ID, vdc.Name))
			}
		}
	}

	return data, nil
}

// ParseVirtualServices extracts virtual service information
func (p *NXOSParser) ParseVirtualServices(output string) (*core.VirtualServiceData, error) {
	data := &core.VirtualServiceData{
		Services:      []core.VirtualService{},
		ForensicNotes: []string{},
		ParsedAt:      time.Now(),
	}

	// Simple parsing for virtual services
	if strings.Contains(output, "guestshell") {
		service := core.VirtualService{
			Name:    "guestshell",
			Status:  "Activated",
			Package: "guestshell.ova",
		}
		data.Services = append(data.Services, service)
		data.ForensicNotes = append(data.ForensicNotes, "FORENSIC: Guest shell service detected - requires examination")
	}

	return data, nil
}

// ParseGuestShell extracts guest shell detail information
func (p *NXOSParser) ParseGuestShell(output string) (*core.GuestShellData, error) {
	data := &core.GuestShellData{
		State:         "Unknown",
		Version:       "",
		Resources:     map[string]string{},
		ForensicNotes: []string{},
		ParsedAt:      time.Now(),
	}

	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.Contains(line, "State") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				data.State = strings.TrimSpace(parts[1])
			}
		}

		if strings.Contains(line, "Installed version") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				data.Version = strings.TrimSpace(parts[1])
			}
		}

		if strings.Contains(line, "Disk") || strings.Contains(line, "Memory") || strings.Contains(line, "CPU") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				data.Resources[key] = value
			}
		}
	}

	if data.State == "Activated" {
		data.ForensicNotes = append(data.ForensicNotes, "FORENSIC: Guest shell is active - examine for unauthorized modifications")
	}

	return data, nil
}

// ParseCoreFiles extracts core file information
func (p *NXOSParser) ParseCoreFiles(output string) (*core.CoreFileData, error) {
	data := &core.CoreFileData{
		CoreFiles:     []core.CoreFile{},
		ForensicNotes: []string{},
		ParsedAt:      time.Now(),
	}

	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if match := p.patterns["core_file"].FindStringSubmatch(line); match != nil {
			coreFile := core.CoreFile{
				Name:    match[1],
				Size:    match[2],
				Date:    match[3],
				Process: match[4],
			}
			data.CoreFiles = append(data.CoreFiles, coreFile)
			data.ForensicNotes = append(data.ForensicNotes,
				fmt.Sprintf("FORENSIC: Core file detected - %s from process %s", coreFile.Name, coreFile.Process))
		}
	}

	return data, nil
}

// ParseFeatures extracts enabled features information
func (p *NXOSParser) ParseFeatures(output string) (*core.FeatureData, error) {
	data := &core.FeatureData{
		Features:      []core.Feature{},
		ForensicNotes: []string{},
		ParsedAt:      time.Now(),
	}

	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if match := p.patterns["feature"].FindStringSubmatch(line); match != nil {
			feature := core.Feature{
				Name:   match[1],
				Status: match[2],
			}
			data.Features = append(data.Features, feature)

			// Check for security-relevant features
			securityFeatures := []string{"bash-shell", "scp-server", "sftp-server", "telnet", "ssh"}
			for _, secFeature := range securityFeatures {
				if strings.Contains(feature.Name, secFeature) && feature.Status == "enabled" {
					data.ForensicNotes = append(data.ForensicNotes,
						fmt.Sprintf("FORENSIC: Security-relevant feature enabled: %s", feature.Name))
				}
			}
		}
	}

	return data, nil
}

// ParseModules extracts module information
func (p *NXOSParser) ParseModules(output string) ([]core.Module, error) {
	var modules []core.Module
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if match := p.patterns["module"].FindStringSubmatch(line); match != nil {
			modules = append(modules, core.Module{
				Slot:   match[1],
				Type:   match[2],
				Model:  match[3],
				Status: match[4],
			})
		}
	}

	return modules, nil
}

// ParseVPC extracts VPC information
func (p *NXOSParser) ParseVPC(output string) (*core.VPCData, error) {
	data := &core.VPCData{
		DomainID:      "",
		PeerStatus:    "",
		ForensicNotes: []string{},
		ParsedAt:      time.Now(),
	}

	// Simple VPC parsing - would be enhanced for full implementation
	if strings.Contains(output, "vPC domain id") {
		data.ForensicNotes = append(data.ForensicNotes, "FORENSIC: VPC configuration detected - examine peer relationships")
	}

	return data, nil
}

// ParseSystemLogs extracts system log information for forensic analysis
func (p *NXOSParser) ParseSystemLogs(output string) (*core.SystemLogData, error) {
	data := &core.SystemLogData{
		LogEntries:    []core.LogEntry{},
		ForensicNotes: []string{},
		ParsedAt:      time.Now(),
	}

	lines := strings.Split(output, "\n")

	// Forensic patterns to look for in logs
	forensicPatterns := map[string]string{
		"authentication failure": "SECURITY",
		"privilege escalation":   "SECURITY",
		"core dump":              "SYSTEM",
		"segmentation fault":     "SYSTEM",
		"memory corruption":      "SYSTEM",
		"unexpected reboot":      "SYSTEM",
		"vdc violation":          "VDC",
		"container escape":       "CONTAINER",
		"guestshell":             "GUESTSHELL",
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}

		// Create log entry
		entry := core.LogEntry{
			Message:   line,
			Timestamp: time.Now(), // In real implementation, parse actual timestamp
		}

		// Check for forensic patterns
		for pattern, category := range forensicPatterns {
			if strings.Contains(strings.ToLower(line), pattern) {
				entry.Category = category
				data.ForensicNotes = append(data.ForensicNotes,
					fmt.Sprintf("FORENSIC ALERT [%s]: %s", category, pattern))
			}
		}

		data.LogEntries = append(data.LogEntries, entry)
	}

	return data, nil
}

// ParseSessions extracts user session information
func (p *NXOSParser) ParseSessions(output string) ([]core.Session, error) {
	var sessions []core.Session
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.Contains(line, "console") || strings.Contains(line, "pts") || strings.Contains(line, "vty") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				session := core.Session{
					User:      fields[0],
					Line:      fields[1],
					LoginTime: time.Now().Format("2006-01-02 15:04:05"),
					Location:  "local",
				}

				if len(fields) >= 4 {
					session.Location = fields[3]
				}

				sessions = append(sessions, session)
			}
		}
	}

	return sessions, nil
}

// ParseRoutes extracts routing table information
func (p *NXOSParser) ParseRoutes(output string) ([]core.Route, error) {
	var routes []core.Route
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if match := p.patterns["route"].FindStringSubmatch(line); match != nil {
			routes = append(routes, core.Route{
				Destination: match[1],
				NextHop:     match[2],
				Interface:   match[3],
				Protocol:    "unknown", // Would need better parsing
			})
		}
	}

	return routes, nil
}

// ParseInstallInfo extracts active software installation information
func (p *NXOSParser) ParseInstallInfo(output string) (*core.InstallInfo, error) {
	info := &core.InstallInfo{
		ActivePackages: []string{},
		Version:        "Unknown",
		ParsedAt:       time.Now(),
	}

	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.Contains(line, "Active Packages") {
			continue
		}

		if strings.Contains(line, ".rpm") || strings.Contains(line, "nxos") {
			info.ActivePackages = append(info.ActivePackages, line)
		}

		if strings.Contains(line, "Version") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				info.Version = fields[len(fields)-1]
			}
		}
	}

	return info, nil
}

// ParseDirectoryListing analyzes directory listings for forensic evidence
func (p *NXOSParser) ParseDirectoryListing(output string) (*core.DirectoryListing, error) {
	listing := &core.DirectoryListing{
		Files:         []core.FileInfo{},
		ForensicNotes: []string{},
		ParsedAt:      time.Now(),
	}

	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "Directory of") {
			continue
		}

		// Simple parsing - in real implementation would be more sophisticated
		fields := strings.Fields(line)
		if len(fields) >= 5 {
			file := core.FileInfo{
				Name:         fields[len(fields)-1],
				Size:         fields[len(fields)-3],
				Permissions:  fields[0],
				ModifiedTime: time.Now(), // Would parse actual timestamp
			}

			listing.Files = append(listing.Files, file)

			// Check for suspicious files
			suspiciousExtensions := []string{".sh", ".bin", ".exe", ".py", ".pl", ".container"}
			for _, ext := range suspiciousExtensions {
				if strings.HasSuffix(strings.ToLower(file.Name), ext) {
					listing.ForensicNotes = append(listing.ForensicNotes,
						fmt.Sprintf("FORENSIC: Suspicious file found: %s", file.Name))
				}
			}
		}
	}

	return listing, nil
}

// ParseSystemInternal analyzes system internal command outputs
func (p *NXOSParser) ParseSystemInternal(output string) (*core.SystemInternalData, error) {
	data := &core.SystemInternalData{
		ProcessInfo:   map[string]interface{}{},
		ForensicNotes: []string{},
		ParsedAt:      time.Now(),
	}

	// Basic parsing of system internal information
	data.ForensicNotes = append(data.ForensicNotes, "FORENSIC: System internal information collected - requires detailed analysis")

	// Store raw output for detailed analysis
	data.ProcessInfo["raw_output"] = output

	return data, nil
}

// GetCommandType returns the type of data a command produces
func (p *NXOSParser) GetCommandType(command string) string {
	switch {
	case strings.Contains(command, "show version"):
		return "version_info"
	case strings.Contains(command, "show tech-support"):
		return "tech_support"
	case strings.Contains(command, "show processes"):
		return "processes"
	case strings.Contains(command, "show sockets connection"):
		return "socket_connections"
	case strings.Contains(command, "show software authenticity"):
		return "software_authenticity"
	case strings.Contains(command, "show vdc"):
		return "vdc_info"
	case strings.Contains(command, "show virtual-service"):
		return "virtual_services"
	case strings.Contains(command, "show guestshell"):
		return "guestshell"
	default:
		return "generic"
	}
}

// SupportedCommands returns the list of commands this parser can handle
func (p *NXOSParser) SupportedCommands() []string {
	return []string{
		"show version",
		"show tech-support details",
		"show processes",
		"show sockets connection",
		"show interfaces",
		"show software authenticity running",
		"show software authenticity keys",
		"show boot",
		"show vdc",
		"show virtual-service list",
		"show guestshell detail",
		"show cores",
		"show feature",
		"show module",
		"show vpc",
		"show logging",
		"show users",
		"show ip route",
		"show install active",
		"dir",
		"show system internal",
	}
}
