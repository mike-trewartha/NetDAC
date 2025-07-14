package cisco

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"netdac/internal/core"
)

// IOSParser implements command parsing for Cisco IOS devices
type IOSParser struct {
	utils *core.ParserUtils
}

// NewIOSParser creates a new IOS parser
func NewIOSParser() *IOSParser {
	return &IOSParser{
		utils: core.NewParserUtils(),
	}
}

// ParseVersion parses the output of "show version" command
func (p *IOSParser) ParseVersion(output string, deviceState *core.DeviceState) error {
	lines := p.utils.ExtractLines(output)

	deviceInfo := &deviceState.DeviceInfo
	deviceInfo.Vendor = "cisco"

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Extract hostname
		if strings.Contains(line, "uptime is") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				deviceInfo.Hostname = parts[0]
			}
		}

		// Extract version information
		if strings.Contains(line, "Cisco IOS Software") || strings.Contains(line, "Version") {
			if strings.Contains(line, "Version") {
				versionParts := strings.Split(line, "Version")
				if len(versionParts) > 1 {
					version := strings.TrimSpace(versionParts[1])
					// Extract just the version number
					versionFields := strings.Fields(version)
					if len(versionFields) > 0 {
						deviceInfo.Version = strings.TrimSuffix(versionFields[0], ",")
					}
				}
			}
		}

		// Extract model information
		if strings.Contains(line, "cisco") && (strings.Contains(line, "processor") || strings.Contains(line, "bytes")) {
			parts := strings.Fields(line)
			for i, part := range parts {
				if strings.ToLower(part) == "cisco" && i+1 < len(parts) {
					deviceInfo.Model = parts[i+1]
					break
				}
			}
		}

		// Extract serial number
		if strings.Contains(line, "Processor board ID") {
			parts := strings.Split(line, "Processor board ID")
			if len(parts) > 1 {
				deviceInfo.SerialNumber = strings.TrimSpace(parts[1])
			}
		}

		// Extract uptime
		if strings.Contains(line, "uptime is") {
			uptimeParts := strings.Split(line, "uptime is")
			if len(uptimeParts) > 1 {
				deviceInfo.Uptime = strings.TrimSpace(uptimeParts[1])
			}
		}
	}

	return nil
}

// ParseInterfaces parses the output of "show ip interface brief" command
func (p *IOSParser) ParseInterfaces(output string, deviceState *core.DeviceState) error {
	lines := p.utils.ExtractLines(output)

	var interfaces []core.Interface
	headerFound := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip until we find the header
		if !headerFound {
			if strings.Contains(line, "Interface") && strings.Contains(line, "Status") {
				headerFound = true
			}
			continue
		}

		// Skip separator lines
		if strings.Contains(line, "---") || line == "" {
			continue
		}

		// Parse interface line
		fields := strings.Fields(line)
		if len(fields) >= 6 {
			iface := core.Interface{
				Name:        fields[0],
				IPAddress:   fields[1],
				Status:      fields[4] + "/" + fields[5], // Protocol/Status
				AdminStatus: fields[4],
			}

			// Handle cases where IP is "unassigned"
			if strings.ToLower(iface.IPAddress) == "unassigned" {
				iface.IPAddress = ""
			}

			interfaces = append(interfaces, iface)
		}
	}

	deviceState.Interfaces = interfaces
	return nil
}

// ParseRoutes parses the output of "show ip route" command
func (p *IOSParser) ParseRoutes(output string, deviceState *core.DeviceState) error {
	lines := p.utils.ExtractLines(output)

	var routes []core.Route

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip header lines and empty lines
		if strings.HasPrefix(line, "Codes:") ||
			strings.HasPrefix(line, "Gateway") ||
			strings.Contains(line, "last resort") ||
			line == "" {
			continue
		}

		// Parse route entries
		if strings.Contains(line, "/") { // Likely a route with subnet mask
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				route := core.Route{}

				// Extract destination (first field that contains '/')
				for _, field := range fields {
					if strings.Contains(field, "/") {
						route.Destination = field
						break
					}
				}

				// Extract protocol (first character or word)
				if len(fields) > 0 {
					protocolCode := fields[0]
					route.Protocol = p.mapProtocolCode(protocolCode)
				}

				// Extract gateway/next hop
				if strings.Contains(line, "via") {
					viaParts := strings.Split(line, "via")
					if len(viaParts) > 1 {
						gatewayInfo := strings.TrimSpace(viaParts[1])
						gatewayFields := strings.Fields(gatewayInfo)
						if len(gatewayFields) > 0 {
							route.Gateway = gatewayFields[0]
						}
					}
				}

				// Extract interface
				for _, field := range fields {
					if strings.Contains(strings.ToLower(field), "ethernet") ||
						strings.Contains(strings.ToLower(field), "serial") ||
						strings.Contains(strings.ToLower(field), "tunnel") ||
						strings.Contains(strings.ToLower(field), "loopback") {
						route.Interface = field
						break
					}
				}

				if route.Destination != "" {
					routes = append(routes, route)
				}
			}
		}
	}

	deviceState.Routes = routes
	return nil
}

// ParseProcesses parses the output of "show processes" command
func (p *IOSParser) ParseProcesses(output string, deviceState *core.DeviceState) error {
	lines := p.utils.ExtractLines(output)

	var processes []core.Process
	headerFound := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip until we find the header
		if !headerFound {
			if strings.Contains(line, "PID") && strings.Contains(line, "Runtime") {
				headerFound = true
			}
			continue
		}

		// Parse process entries
		fields := strings.Fields(line)
		if len(fields) >= 8 {
			process := core.Process{
				PID:     fields[0],
				Runtime: fields[1],
				CPU:     fields[4],
				Name:    strings.Join(fields[7:], " "), // Process name may contain spaces
			}

			processes = append(processes, process)
		}
	}

	deviceState.Processes = processes
	return nil
}

// ParseUsers parses the output of "show users" command
func (p *IOSParser) ParseUsers(output string, deviceState *core.DeviceState) error {
	lines := p.utils.ExtractLines(output)

	var sessions []core.Session

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip header lines
		if strings.Contains(line, "Line") && strings.Contains(line, "User") {
			continue
		}

		// Parse user sessions
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			session := core.Session{
				Line: fields[0],
				User: fields[1],
			}

			// Extract location/host if available
			if len(fields) > 3 {
				session.Location = strings.Join(fields[3:], " ")
			}

			// Extract idle time if available
			if len(fields) > 2 {
				session.IdleTime = fields[2]
			}

			sessions = append(sessions, session)
		}
	}

	deviceState.Sessions = sessions
	return nil
}

// ParseAccessLists parses the output of "show access-lists" command
func (p *IOSParser) ParseAccessLists(output string, deviceState *core.DeviceState) error {
	lines := p.utils.ExtractLines(output)

	var accessLists []core.AccessList
	var currentACL *core.AccessList

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Detect start of new access list
		if strings.Contains(line, "access list") ||
			(strings.Contains(line, "Standard") && strings.Contains(line, "access list")) ||
			(strings.Contains(line, "Extended") && strings.Contains(line, "access list")) {

			// Save previous ACL if exists
			if currentACL != nil {
				accessLists = append(accessLists, *currentACL)
			}

			// Start new ACL
			currentACL = &core.AccessList{
				Rules: []core.ACLRule{},
			}

			// Extract ACL name and type
			fields := strings.Fields(line)
			for i, field := range fields {
				if strings.ToLower(field) == "list" && i+1 < len(fields) {
					currentACL.Name = fields[i+1]
					break
				}
			}

			if strings.Contains(strings.ToLower(line), "standard") {
				currentACL.Type = "standard"
			} else if strings.Contains(strings.ToLower(line), "extended") {
				currentACL.Type = "extended"
			}

			continue
		}

		// Parse ACL rules
		if currentACL != nil && (strings.Contains(line, "permit") || strings.Contains(line, "deny")) {
			rule := core.ACLRule{}

			// Extract action
			if strings.Contains(line, "permit") {
				rule.Action = "permit"
			} else if strings.Contains(line, "deny") {
				rule.Action = "deny"
			}

			// Extract sequence number if present
			fields := strings.Fields(line)
			if len(fields) > 0 && p.isNumeric(fields[0]) {
				rule.Sequence = fields[0]
				fields = fields[1:] // Remove sequence from further processing
			}

			// Parse detailed ACL rule components
			rule = p.parseACLRuleDetails(rule, fields)

			currentACL.Rules = append(currentACL.Rules, rule)
		}
	}

	// Add the last ACL
	if currentACL != nil {
		accessLists = append(accessLists, *currentACL)
	}

	if deviceState.Security.AccessLists == nil {
		deviceState.Security = core.SecurityInfo{}
	}
	deviceState.Security.AccessLists = accessLists

	return nil
}

// ParseTechSupport extracts key sections from show tech-support output
func (p *IOSParser) ParseTechSupport(output string, deviceState *core.DeviceState) error {
	lines := p.utils.ExtractLines(output)

	techSupport := core.TechSupportInfo{
		Sections:    make(map[string]string),
		CollectedAt: time.Now(),
		TotalLines:  len(lines),
		SizeBytes:   len(output),
	}

	var currentSection string
	var sectionLines []string

	for _, line := range lines {
		// Detect section headers (lines starting with "show ")
		if strings.HasPrefix(line, "show ") {
			// Save previous section
			if currentSection != "" && len(sectionLines) > 0 {
				techSupport.Sections[currentSection] = strings.Join(sectionLines, "\n")
			}

			// Start new section
			currentSection = strings.TrimSpace(line)
			sectionLines = []string{}
		} else {
			// Add line to current section
			if currentSection != "" {
				sectionLines = append(sectionLines, line)
			}
		}
	}

	// Save final section
	if currentSection != "" && len(sectionLines) > 0 {
		techSupport.Sections[currentSection] = strings.Join(sectionLines, "\n")
	}

	// Add to device state
	if deviceState.ForensicData == nil {
		deviceState.ForensicData = make(map[string]interface{})
	}
	deviceState.ForensicData["tech_support"] = techSupport

	return nil
}

// ParseDirectoryListing parses dir /recursive all-filesystems output
func (p *IOSParser) ParseDirectoryListing(output string, deviceState *core.DeviceState) error {
	lines := p.utils.ExtractLines(output)

	var directories []core.DirectoryEntry
	var currentFilesystem string

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Detect filesystem headers
		if strings.Contains(line, "Directory of ") {
			parts := strings.Split(line, "Directory of ")
			if len(parts) > 1 {
				currentFilesystem = strings.TrimSpace(parts[1])
			}
			continue
		}

		// Skip header lines and empty lines
		if strings.Contains(line, "bytes total") ||
			strings.Contains(line, "bytes free") ||
			strings.Contains(line, "---") ||
			line == "" {
			continue
		}

		// Parse file/directory entries
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			entry := core.DirectoryEntry{
				Filesystem: currentFilesystem,
				Name:       fields[len(fields)-1], // Last field is usually the name
			}

			// Extract permissions (first field)
			if len(fields) > 0 {
				entry.Permissions = fields[0]
			}

			// Extract size (look for numeric field)
			for _, field := range fields {
				if size, err := strconv.ParseInt(field, 10, 64); err == nil {
					entry.Size = size
					break
				}
			}

			// Extract date/time (look for date patterns)
			for i, field := range fields {
				if strings.Contains(field, ":") ||
					(len(field) >= 8 && strings.Contains(field, "-")) {
					if i+1 < len(fields) {
						entry.ModifiedTime = field + " " + fields[i+1]
					} else {
						entry.ModifiedTime = field
					}
					break
				}
			}

			directories = append(directories, entry)
		}
	}

	// Add to device state
	if deviceState.ForensicData == nil {
		deviceState.ForensicData = make(map[string]interface{})
	}
	deviceState.ForensicData["directory_listing"] = directories

	return nil
}

// ParseVersionImage extracts system image file paths and version info
func (p *IOSParser) ParseVersionImage(output string, deviceState *core.DeviceState) error {
	lines := p.utils.ExtractLines(output)

	imageInfo := core.ImageInfo{
		DetectedAt: time.Now(),
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Extract system image path
		if strings.Contains(line, "System image file is") {
			parts := strings.Split(line, "System image file is")
			if len(parts) > 1 {
				imagePath := strings.Trim(strings.TrimSpace(parts[1]), "\"")
				imageInfo.SystemImage = imagePath
			}
		}

		// Extract ROM image
		if strings.Contains(line, "ROM image file is") {
			parts := strings.Split(line, "ROM image file is")
			if len(parts) > 1 {
				imagePath := strings.Trim(strings.TrimSpace(parts[1]), "\"")
				imageInfo.ROMImage = imagePath
			}
		}

		// Extract boot variable
		if strings.Contains(line, "BOOT variable =") {
			parts := strings.Split(line, "BOOT variable =")
			if len(parts) > 1 {
				imageInfo.BootVariable = strings.TrimSpace(parts[1])
			}
		}

		// Extract compilation info
		if strings.Contains(line, "Compiled") {
			imageInfo.CompilationInfo = line
		}
	}

	// Add to device state
	if deviceState.ForensicData == nil {
		deviceState.ForensicData = make(map[string]interface{})
	}
	deviceState.ForensicData["image_info"] = imageInfo

	return nil
}

// ParseMemoryRegion parses show region output for memory analysis
func (p *IOSParser) ParseMemoryRegion(output string, deviceState *core.DeviceState) error {
	lines := p.utils.ExtractLines(output)

	var memoryRegions []core.MemoryRegion

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip header lines
		if strings.Contains(line, "Region") && strings.Contains(line, "Manager") {
			continue
		}

		// Parse memory region entries
		fields := strings.Fields(line)
		if len(fields) >= 6 {
			region := core.MemoryRegion{
				Name:     fields[0],
				Manager:  fields[1],
				BaseAddr: fields[2],
				EndAddr:  fields[3],
				Size:     fields[4],
				Class:    fields[5],
			}

			// Parse additional attributes if present
			if len(fields) > 6 {
				region.Attributes = strings.Join(fields[6:], " ")
			}

			memoryRegions = append(memoryRegions, region)
		}
	}

	// Add to device state
	if deviceState.ForensicData == nil {
		deviceState.ForensicData = make(map[string]interface{})
	}
	deviceState.ForensicData["memory_regions"] = memoryRegions

	return nil
}

// ParseImageVerification parses verify command output for tampering detection
func (p *IOSParser) ParseImageVerification(output string, deviceState *core.DeviceState) error {
	lines := p.utils.ExtractLines(output)

	verification := core.ImageVerification{
		CheckedAt: time.Now(),
		Files:     make(map[string]core.FileVerification),
	}

	var currentFile string

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Extract file being verified
		if strings.Contains(line, "Verifying file integrity of") {
			parts := strings.Split(line, "Verifying file integrity of")
			if len(parts) > 1 {
				currentFile = strings.TrimSpace(parts[1])
				verification.Files[currentFile] = core.FileVerification{
					Filename: currentFile,
				}
			}
		}

		// Extract hash information
		if currentFile != "" {
			fileVer := verification.Files[currentFile]

			if strings.Contains(line, "Embedded Hash") && strings.Contains(line, "SHA1") {
				parts := strings.Split(line, "SHA1:")
				if len(parts) > 1 {
					fileVer.EmbeddedSHA1 = strings.TrimSpace(parts[1])
				}
			}

			if strings.Contains(line, "Computed Hash") && strings.Contains(line, "SHA1") {
				parts := strings.Split(line, "SHA1:")
				if len(parts) > 1 {
					fileVer.ComputedSHA1 = strings.TrimSpace(parts[1])
				}
			}

			if strings.Contains(line, "verification successful") {
				fileVer.Verified = true
			}

			if strings.Contains(line, "verification failed") {
				fileVer.Verified = false
				fileVer.TamperingDetected = true
			}

			verification.Files[currentFile] = fileVer
		}
	}

	// Analyze for tampering
	verification.TamperingDetected = false
	for _, fileVer := range verification.Files {
		if fileVer.TamperingDetected ||
			(fileVer.EmbeddedSHA1 != "" && fileVer.ComputedSHA1 != "" &&
				fileVer.EmbeddedSHA1 != fileVer.ComputedSHA1) {
			verification.TamperingDetected = true
			break
		}
	}

	// Add to device state
	if deviceState.ForensicData == nil {
		deviceState.ForensicData = make(map[string]interface{})
	}
	deviceState.ForensicData["image_verification"] = verification

	return nil
}

// ParseSoftwareAuthenticity parses show software authenticity output
func (p *IOSParser) ParseSoftwareAuthenticity(output string, deviceState *core.DeviceState) error {
	lines := p.utils.ExtractLines(output)

	authenticity := core.SoftwareAuthenticity{
		CheckedAt: time.Now(),
		Sections:  make(map[string]map[string]string),
	}

	var currentSection string
	var currentMap map[string]string

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Detect section headers
		if strings.Contains(line, "SYSTEM IMAGE") {
			currentSection = "system_image"
			currentMap = make(map[string]string)
			authenticity.Sections[currentSection] = currentMap
		} else if strings.Contains(line, "Microloader") {
			currentSection = "microloader"
			currentMap = make(map[string]string)
			authenticity.Sections[currentSection] = currentMap
		}

		// Parse key-value pairs
		if currentMap != nil && strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				currentMap[key] = value
			}
		}
	}

	// Check for Cisco authenticity
	if systemImg, exists := authenticity.Sections["system_image"]; exists {
		if orgName, exists := systemImg["Organization Name"]; exists {
			authenticity.CiscoSigned = (orgName == "CiscoSystems")
		}
	}

	// Add to device state
	if deviceState.ForensicData == nil {
		deviceState.ForensicData = make(map[string]interface{})
	}
	deviceState.ForensicData["software_authenticity"] = authenticity

	return nil
}

// ParseSoftwareKeys parses signing key information
func (p *IOSParser) ParseSoftwareKeys(output string, deviceState *core.DeviceState) error {
	lines := p.utils.ExtractLines(output)

	var keys []core.SigningKey
	var currentKey *core.SigningKey

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Detect new key entry
		if strings.Contains(line, "Key type:") {
			if currentKey != nil {
				keys = append(keys, *currentKey)
			}
			currentKey = &core.SigningKey{}
			parts := strings.Split(line, "Key type:")
			if len(parts) > 1 {
				currentKey.Type = strings.TrimSpace(parts[1])
			}
		}

		// Parse key attributes
		if currentKey != nil {
			if strings.Contains(line, "Key name:") {
				parts := strings.Split(line, "Key name:")
				if len(parts) > 1 {
					currentKey.Name = strings.TrimSpace(parts[1])
				}
			}

			if strings.Contains(line, "Key version:") {
				parts := strings.Split(line, "Key version:")
				if len(parts) > 1 {
					currentKey.Version = strings.TrimSpace(parts[1])
				}
			}

			if strings.Contains(line, "Storage:") {
				parts := strings.Split(line, "Storage:")
				if len(parts) > 1 {
					currentKey.Storage = strings.TrimSpace(parts[1])
				}
			}
		}
	}

	// Add final key
	if currentKey != nil {
		keys = append(keys, *currentKey)
	}

	// Add to device state
	if deviceState.ForensicData == nil {
		deviceState.ForensicData = make(map[string]interface{})
	}
	deviceState.ForensicData["signing_keys"] = keys

	return nil
}

// ParseROMMonitor parses show rom-monitor output
func (p *IOSParser) ParseROMMonitor(output string, deviceState *core.DeviceState) error {
	lines := p.utils.ExtractLines(output)

	romMon := core.ROMMonitorInfo{
		Variables: make(map[string]string),
		ParsedAt:  time.Now(),
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Parse ROM monitor variables
		if strings.Contains(line, "=") && !strings.HasPrefix(line, "#") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				romMon.Variables[key] = value
			}
		}

		// Extract version information
		if strings.Contains(line, "ROM:") {
			romMon.Version = strings.TrimSpace(strings.TrimPrefix(line, "ROM:"))
		}
	}

	// Add to device state
	if deviceState.ForensicData == nil {
		deviceState.ForensicData = make(map[string]interface{})
	}
	deviceState.ForensicData["rom_monitor"] = romMon

	return nil
}

// ParseLogging parses system logs for forensic analysis
func (p *IOSParser) ParseLogging(output string, deviceState *core.DeviceState) error {
	lines := p.utils.ExtractLines(output)

	var logEntries []core.LogEntry

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}

		// Parse log entries (basic format: timestamp: %FACILITY-SEVERITY-MNEMONIC: message)
		entry := core.LogEntry{
			RawLine: line,
		}

		// Extract timestamp (look for patterns like *Mar 1 00:00:00.000:)
		if strings.Contains(line, ":") {
			timestampPattern := `^\*?(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{3})?)`
			if matched := regexp.MustCompile(timestampPattern).FindStringSubmatch(line); len(matched) > 1 {
				// Try to parse the timestamp, if it fails use current time
				if parsedTime, err := time.Parse("Jan 2 15:04:05", matched[1]); err == nil {
					entry.Timestamp = parsedTime
				} else {
					entry.Timestamp = time.Now()
				}
				line = strings.TrimSpace(line[len(matched[0]):])
			}
		}

		// Extract facility-severity-mnemonic pattern
		facilityPattern := `%([A-Z_]+)-(\d+)-([A-Z_]+):`
		if matched := regexp.MustCompile(facilityPattern).FindStringSubmatch(line); len(matched) > 3 {
			entry.Facility = matched[1]
			entry.Severity = matched[2]
			entry.Mnemonic = matched[3]

			// Extract message (everything after the pattern)
			msgStart := strings.Index(line, matched[0]) + len(matched[0])
			if msgStart < len(line) {
				entry.Message = strings.TrimSpace(line[msgStart:])
			}
		} else {
			// If no pattern match, treat entire line as message
			entry.Message = line
		}

		logEntries = append(logEntries, entry)
	}

	// Add to device state
	if deviceState.Security.Logs == nil {
		deviceState.Security.Logs = logEntries
	} else {
		deviceState.Security.Logs = append(deviceState.Security.Logs, logEntries...)
	}

	return nil
}

// ParseArpTable parses ARP table for network forensics
func (p *IOSParser) ParseArpTable(output string, deviceState *core.DeviceState) error {
	lines := p.utils.ExtractLines(output)

	var arpEntries []core.ARPEntry
	headerFound := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip until header is found
		if !headerFound {
			if strings.Contains(line, "Address") && strings.Contains(line, "Hardware") {
				headerFound = true
			}
			continue
		}

		// Skip separator lines
		if strings.Contains(line, "---") || line == "" {
			continue
		}

		// Parse ARP entries
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			entry := core.ARPEntry{
				IPAddress:  fields[1],
				MACAddress: fields[3],
				Interface:  fields[len(fields)-1], // Last field is usually interface
			}

			// Extract age if present
			if len(fields) >= 2 {
				entry.Age = fields[0]
			}

			// Extract type if present
			if len(fields) >= 4 {
				entry.Type = fields[2]
			}

			arpEntries = append(arpEntries, entry)
		}
	}

	// Add to device state
	if deviceState.ForensicData == nil {
		deviceState.ForensicData = make(map[string]interface{})
	}
	deviceState.ForensicData["arp_table"] = arpEntries

	return nil
}

// ParseNatTranslations parses NAT translation table
func (p *IOSParser) ParseNatTranslations(output string, deviceState *core.DeviceState) error {
	lines := p.utils.ExtractLines(output)

	var natEntries []core.NATEntry

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip header and empty lines
		if strings.Contains(line, "Inside") && strings.Contains(line, "Outside") {
			continue
		}

		if line == "" {
			continue
		}

		// Parse NAT entries
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			entry := core.NATEntry{
				InsideLocal:   fields[0],
				InsideGlobal:  fields[1],
				OutsideLocal:  fields[2],
				OutsideGlobal: fields[3],
			}

			natEntries = append(natEntries, entry)
		}
	}

	// Add to device state
	if deviceState.ForensicData == nil {
		deviceState.ForensicData = make(map[string]interface{})
	}
	deviceState.ForensicData["nat_translations"] = natEntries

	return nil
}

// ParseTcpConnections parses TCP connection state
func (p *IOSParser) ParseTcpConnections(output string, deviceState *core.DeviceState) error {
	lines := p.utils.ExtractLines(output)

	var tcpConnections []core.TCPConnection

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" || strings.Contains(line, "TCB") {
			continue
		}

		// Parse TCP connection entries
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			conn := core.TCPConnection{
				LocalAddress:  fields[0],
				RemoteAddress: fields[1],
				State:         fields[2],
			}

			tcpConnections = append(tcpConnections, conn)
		}
	}

	// Add to device state
	if deviceState.ForensicData == nil {
		deviceState.ForensicData = make(map[string]interface{})
	}
	deviceState.ForensicData["tcp_connections"] = tcpConnections

	return nil
}

// ParseClock parses clock and timezone information
func (p *IOSParser) ParseClock(output string, deviceState *core.DeviceState) error {
	lines := p.utils.ExtractLines(output)

	clockInfo := core.ClockInfo{
		ParsedAt: time.Now(),
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Extract current time
		if strings.Contains(line, ":") && (strings.Contains(line, "UTC") ||
			strings.Contains(line, "EST") || strings.Contains(line, "PST") ||
			len(strings.Fields(line)) >= 3) {
			clockInfo.CurrentTime = line
		}

		// Extract timezone
		if strings.Contains(line, "Time source") {
			parts := strings.Split(line, "Time source")
			if len(parts) > 1 {
				clockInfo.TimeSource = strings.TrimSpace(parts[1])
			}
		}
	}

	// Add to device state
	if deviceState.ForensicData == nil {
		deviceState.ForensicData = make(map[string]interface{})
	}
	deviceState.ForensicData["clock_info"] = clockInfo

	return nil
}

// parseACLRuleDetails parses detailed components of an ACL rule
func (p *IOSParser) parseACLRuleDetails(rule core.ACLRule, fields []string) core.ACLRule {
	if len(fields) < 2 {
		return rule // Not enough fields for detailed parsing
	}

	// Find action (permit/deny) and remove it from fields
	actionIndex := -1
	for i, field := range fields {
		if field == "permit" || field == "deny" {
			rule.Action = field
			actionIndex = i
			break
		}
	}

	if actionIndex >= 0 && actionIndex < len(fields)-1 {
		// Remove action from fields for further processing
		remainingFields := append(fields[:actionIndex], fields[actionIndex+1:]...)

		// Parse protocol (should be first after action)
		if len(remainingFields) > 0 {
			protocol := remainingFields[0]
			if protocol != "any" {
				rule.Protocol = protocol
			}
			remainingFields = remainingFields[1:]
		}

		// Parse source and destination
		// Format is typically: protocol source [source-wildcard] destination [destination-wildcard] [port]
		if len(remainingFields) >= 2 {
			// Parse source
			source := remainingFields[0]
			if source == "any" {
				rule.Source = "any"
				remainingFields = remainingFields[1:]
			} else if p.isIPAddress(source) {
				rule.Source = source
				remainingFields = remainingFields[1:]
				// Check if next field is a wildcard mask
				if len(remainingFields) > 0 && p.isIPAddress(remainingFields[0]) {
					rule.Source += "/" + remainingFields[0]
					remainingFields = remainingFields[1:]
				}
			} else {
				rule.Source = source
				remainingFields = remainingFields[1:]
			}

			// Parse destination
			if len(remainingFields) > 0 {
				dest := remainingFields[0]
				if dest == "any" {
					rule.Destination = "any"
					remainingFields = remainingFields[1:]
				} else if p.isIPAddress(dest) {
					rule.Destination = dest
					remainingFields = remainingFields[1:]
					// Check if next field is a wildcard mask
					if len(remainingFields) > 0 && p.isIPAddress(remainingFields[0]) {
						rule.Destination += "/" + remainingFields[0]
						remainingFields = remainingFields[1:]
					}
				} else {
					rule.Destination = dest
					remainingFields = remainingFields[1:]
				}
			}

			// Parse port information
			if len(remainingFields) > 0 {
				for i, field := range remainingFields {
					if field == "eq" || field == "gt" || field == "lt" || field == "neq" || field == "range" {
						if i+1 < len(remainingFields) {
							if field == "range" && i+2 < len(remainingFields) {
								rule.Port = field + " " + remainingFields[i+1] + " " + remainingFields[i+2]
							} else {
								rule.Port = field + " " + remainingFields[i+1]
							}
						}
						break
					}
				}
			}
		}
	}

	return rule
}

// isIPAddress checks if a string looks like an IP address
func (p *IOSParser) isIPAddress(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 3 {
			return false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// isNumeric checks if a string represents a numeric value
func (p *IOSParser) isNumeric(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// mapProtocolCode maps protocol codes to protocol names
func (p *IOSParser) mapProtocolCode(code string) string {
	protocolMap := map[string]string{
		"C":  "connected",
		"S":  "static",
		"R":  "rip",
		"M":  "mobile",
		"B":  "bgp",
		"D":  "eigrp",
		"EX": "eigrp-external",
		"O":  "ospf",
		"IA": "ospf-inter-area",
		"N1": "ospf-nssa-external-type-1",
		"N2": "ospf-nssa-external-type-2",
		"E1": "ospf-external-type-1",
		"E2": "ospf-external-type-2",
		"i":  "isis",
		"su": "isis-summary",
		"L1": "isis-level-1",
		"L2": "isis-level-2",
		"ia": "isis-inter-area",
		"*":  "candidate-default",
		"U":  "per-user-static",
		"H":  "nhrp",
		"G":  "nhrp",
		"l":  "lisp",
		"a":  "application",
		"+":  "replicated",
		"%":  "next-hop-override",
		"p":  "periodic-downloaded-static",
	}

	if protocol, exists := protocolMap[code]; exists {
		return protocol
	}
	return code // Return original if not found
}

/*
Additional parsers needed for full Cisco IOS Forensic Data Collection Procedures compliance:

Core Forensic Parsers (Step 2):
- ParseTechSupport() - Extract key sections from show tech-support
- ParseDirectoryListing() - Parse dir /recursive all-filesystems output

Image Verification Parsers (Step 3):
- ParseVersionImage() - Extract system image file paths
- ParseMemoryRegion() - Parse show region output
- ParseImageVerification() - Parse verify command output

Authentication Parsers (Step 4):
- ParseSoftwareAuthenticity() - Parse show software authenticity output
- ParseSoftwareKeys() - Parse signing key information

ROMMON Parser (Step 7):
- ParseROMMonitor() - Parse show rom-monitor output

Additional Security Parsers:
- ParseLogging() - Parse system logs
- ParseArpTable() - Parse ARP table
- ParseNatTranslations() - Parse NAT translations
- ParseTcpConnections() - Parse TCP connection state
- ParseClock() - Parse clock and timezone information

These parsers should be implemented to provide structured data extraction
from the raw command output for forensic analysis.
*/
