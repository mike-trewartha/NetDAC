package cisco

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"netdac/internal/core"
)

// IOSXEParser implements parsing logic for Cisco IOS XE command outputs
type IOSXEParser struct{}

// NewIOSXEParser creates a new IOS XE parser instance
func NewIOSXEParser() *IOSXEParser {
	return &IOSXEParser{}
}

// ParseAll parses all commands in the device state
func (p *IOSXEParser) ParseAll(result *core.DeviceState) error {
	// Parse raw commands into structured data by extracting information
	// from result.RawCommands and populating structured fields

	for _, rawCmd := range result.RawCommands {
		if rawCmd.ErrorOutput != "" {
			continue // Skip commands that failed
		}

		// Route parsing to appropriate specialized functions
		err := p.parseCommand(rawCmd, result)
		if err != nil {
			// Log error but continue processing other commands
			continue
		}
	}

	return nil
}

// parseCommand routes individual commands to appropriate parsing functions
func (p *IOSXEParser) parseCommand(rawCmd core.RawCommand, result *core.DeviceState) error {
	command := strings.ToLower(rawCmd.Command)

	switch {
	case strings.Contains(command, "show version"):
		return p.parseShowVersion(rawCmd, result)
	case strings.Contains(command, "show interfaces"):
		return p.parseShowInterfaces(rawCmd, result)
	case strings.Contains(command, "show ip route"):
		return p.parseShowIPRoute(rawCmd, result)
	case strings.Contains(command, "show processes"):
		return p.parseShowProcesses(rawCmd, result)
	case strings.Contains(command, "show users"):
		return p.parseShowUsers(rawCmd, result)
	case strings.Contains(command, "show access-lists"):
		return p.parseShowAccessLists(rawCmd, result)
	case strings.Contains(command, "show inventory"):
		return p.parseShowInventory(rawCmd, result)
	case strings.Contains(command, "show environment"):
		return p.parseShowEnvironment(rawCmd, result)
	default:
		// For unrecognized commands, we still preserve the raw output
		return nil
	}
}

// parseShowVersion parses show version command output
func (p *IOSXEParser) parseShowVersion(rawCmd core.RawCommand, result *core.DeviceState) error {
	if parsed, err := p.ParseShowVersion(rawCmd.Output); err == nil {
		// Update device info with parsed data
		if hostname, exists := parsed["hostname"]; exists {
			if hostnameStr, ok := hostname.(string); ok {
				result.DeviceInfo.Hostname = hostnameStr
			}
		}
		if serialNum, exists := parsed["serial_number"]; exists {
			if serialStr, ok := serialNum.(string); ok {
				result.DeviceInfo.SerialNumber = serialStr
			}
		}
	}
	return nil
}

// parseShowInterfaces parses show interfaces command output
func (p *IOSXEParser) parseShowInterfaces(rawCmd core.RawCommand, result *core.DeviceState) error {
	if parsed, err := p.ParseInterfaces(rawCmd.Output); err == nil {
		// Convert parsed interfaces to core.Interface structs
		if interfacesMap, exists := parsed["interfaces"]; exists {
			if interfacesData, ok := interfacesMap.(map[string]map[string]interface{}); ok {
				for name, ifaceData := range interfacesData {
					iface := core.Interface{
						Name: name,
					}
					if status, exists := ifaceData["status"]; exists {
						if statusStr, ok := status.(string); ok {
							iface.Status = statusStr
						}
					}
					if ipAddr, exists := ifaceData["ip_address"]; exists {
						if ipStr, ok := ipAddr.(string); ok {
							iface.IPAddress = ipStr
						}
					}
					if macAddr, exists := ifaceData["mac_address"]; exists {
						if macStr, ok := macAddr.(string); ok {
							iface.MACAddress = macStr
						}
					}
					result.Interfaces = append(result.Interfaces, iface)
				}
			}
		}
	}
	return nil
}

// parseShowIPRoute parses show ip route command output
func (p *IOSXEParser) parseShowIPRoute(rawCmd core.RawCommand, result *core.DeviceState) error {
	if parsed, err := p.ParseIPRoute(rawCmd.Output); err == nil {
		if routesMap, exists := parsed["routes"]; exists {
			if routesData, ok := routesMap.([]map[string]interface{}); ok {
				for _, routeData := range routesData {
					route := core.Route{}
					if dest, exists := routeData["destination"]; exists {
						if destStr, ok := dest.(string); ok {
							route.Destination = destStr
						}
					}
					if gw, exists := routeData["gateway"]; exists {
						if gwStr, ok := gw.(string); ok {
							route.Gateway = gwStr
						}
					}
					if iface, exists := routeData["interface"]; exists {
						if ifaceStr, ok := iface.(string); ok {
							route.Interface = ifaceStr
						}
					}
					result.Routes = append(result.Routes, route)
				}
			}
		}
	}
	return nil
}

// parseShowProcesses parses show processes command output
func (p *IOSXEParser) parseShowProcesses(rawCmd core.RawCommand, result *core.DeviceState) error {
	if parsed, err := p.ParseProcesses(rawCmd.Output); err == nil {
		if processesMap, exists := parsed["processes"]; exists {
			if processesData, ok := processesMap.([]map[string]interface{}); ok {
				for _, processData := range processesData {
					process := core.Process{}
					if pid, exists := processData["pid"]; exists {
						if pidStr, ok := pid.(string); ok {
							process.PID = pidStr
						}
					}
					if name, exists := processData["name"]; exists {
						if nameStr, ok := name.(string); ok {
							process.Name = nameStr
						}
					}
					if cpu, exists := processData["cpu"]; exists {
						if cpuStr, ok := cpu.(string); ok {
							process.CPU = cpuStr
						}
					}
					result.Processes = append(result.Processes, process)
				}
			}
		}
	}
	return nil
}

// parseShowUsers parses show users command output
func (p *IOSXEParser) parseShowUsers(rawCmd core.RawCommand, result *core.DeviceState) error {
	if parsed, err := p.ParseUsers(rawCmd.Output); err == nil {
		if usersMap, exists := parsed["users"]; exists {
			if usersData, ok := usersMap.([]map[string]interface{}); ok {
				for _, userData := range usersData {
					session := core.Session{}
					if user, exists := userData["user"]; exists {
						if userStr, ok := user.(string); ok {
							session.User = userStr
						}
					}
					if line, exists := userData["line"]; exists {
						if lineStr, ok := line.(string); ok {
							session.Line = lineStr
						}
					}
					if location, exists := userData["location"]; exists {
						if locationStr, ok := location.(string); ok {
							session.Location = locationStr
						}
					}
					result.Sessions = append(result.Sessions, session)
				}
			}
		}
	}
	return nil
}

// parseShowAccessLists parses access list information (placeholder for future implementation)
func (p *IOSXEParser) parseShowAccessLists(rawCmd core.RawCommand, result *core.DeviceState) error {
	// This would be similar to the IOS parser ACL implementation
	// For now, just preserve the raw output
	return nil
}

// parseShowInventory parses show inventory command output
func (p *IOSXEParser) parseShowInventory(rawCmd core.RawCommand, result *core.DeviceState) error {
	// Parse inventory information and update device info
	if parsed, err := p.ParseInventory(rawCmd.Output); err == nil {
		if model, exists := parsed["model"]; exists {
			if modelStr, ok := model.(string); ok {
				result.DeviceInfo.Model = modelStr
			}
		}
	}
	return nil
}

// parseShowEnvironment parses environment monitoring information
func (p *IOSXEParser) parseShowEnvironment(rawCmd core.RawCommand, result *core.DeviceState) error {
	// Parse environment data for system monitoring
	// This would extract temperature, fan status, power supply info, etc.
	return nil
}

// ParseShowVersion parses show version output
func (p *IOSXEParser) ParseShowVersion(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Extract IOS XE version
		if strings.Contains(line, "Cisco IOS XE Software, Version ") {
			re := regexp.MustCompile(`Version\s+([^\s,]+)`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 {
				result["ios_xe_version"] = matches[1]
			}
		}

		// Extract IOS version
		if strings.Contains(line, "Cisco IOS Software") {
			re := regexp.MustCompile(`Version\s+([^,]+)`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 {
				result["ios_version"] = strings.TrimSpace(matches[1])
			}
		}

		// Extract uptime
		if strings.Contains(line, " uptime is ") {
			parts := strings.Split(line, " uptime is ")
			if len(parts) > 1 {
				result["hostname"] = strings.TrimSpace(parts[0])
				result["uptime"] = strings.TrimSpace(parts[1])
			}
		}

		// Extract system image
		if strings.Contains(line, "System image file is ") {
			re := regexp.MustCompile(`System image file is "([^"]+)"`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 {
				result["system_image"] = matches[1]
			}
		}

		// Extract processor information
		if strings.Contains(line, "cisco ") && strings.Contains(line, "processor") {
			result["processor_info"] = line
		}

		// Extract serial number
		if strings.Contains(line, "Processor board ID ") {
			parts := strings.Split(line, "Processor board ID ")
			if len(parts) > 1 {
				result["serial_number"] = strings.TrimSpace(parts[1])
			}
		}

		// Extract last reload reason
		if strings.Contains(line, "Last reload reason: ") {
			parts := strings.Split(line, "Last reload reason: ")
			if len(parts) > 1 {
				result["last_reload_reason"] = strings.TrimSpace(parts[1])
			}
		}
	}

	return result, nil
}

// ParseImageVerification parses image verification output for forensic analysis
func (p *IOSXEParser) ParseImageVerification(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	lines := strings.Split(output, "\n")

	var currentFile string
	hashes := make(map[string]map[string]string)

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Extract filename being verified
		if strings.Contains(line, "Verifying file integrity of ") {
			re := regexp.MustCompile(`Verifying file integrity of\s+(.+)`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 {
				currentFile = matches[1]
				hashes[currentFile] = make(map[string]string)
			}
		}

		// Extract embedded and computed hashes
		if strings.Contains(line, "Embedded Hash") && strings.Contains(line, "SHA1") {
			re := regexp.MustCompile(`Embedded Hash\s+SHA1\s*:\s*([A-F0-9]+)`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 && currentFile != "" {
				hashes[currentFile]["embedded_sha1"] = matches[1]
			}
		}

		if strings.Contains(line, "Computed Hash") && strings.Contains(line, "SHA1") {
			re := regexp.MustCompile(`Computed Hash\s+SHA1\s*:\s*([A-F0-9]+)`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 && currentFile != "" {
				hashes[currentFile]["computed_sha1"] = matches[1]
			}
		}

		if strings.Contains(line, "Embedded Hash") && strings.Contains(line, "SHA2") {
			// SHA2 hash might span multiple lines
			re := regexp.MustCompile(`Embedded Hash\s+SHA2:\s*([a-f0-9]+)`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 && currentFile != "" {
				hashes[currentFile]["embedded_sha2"] = matches[1]
			}
		}

		if strings.Contains(line, "Computed Hash") && strings.Contains(line, "SHA2") {
			re := regexp.MustCompile(`Computed Hash\s+SHA2:\s*([a-f0-9]+)`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 && currentFile != "" {
				hashes[currentFile]["computed_sha2"] = matches[1]
			}
		}

		// Check for verification success/failure
		if strings.Contains(line, "Digital signature successfully verified") {
			if currentFile != "" {
				hashes[currentFile]["signature_verification"] = "success"
			}
		}

		if strings.Contains(line, "Embedded hash verification successful") {
			if currentFile != "" {
				hashes[currentFile]["hash_verification"] = "success"
			}
		}
	}

	result["file_verifications"] = hashes

	// Analyze for potential tampering
	tampered := make([]string, 0)
	for file, fileHashes := range hashes {
		embeddedSHA1, hasEmbeddedSHA1 := fileHashes["embedded_sha1"]
		computedSHA1, hasComputedSHA1 := fileHashes["computed_sha1"]

		if hasEmbeddedSHA1 && hasComputedSHA1 && embeddedSHA1 != computedSHA1 {
			tampered = append(tampered, file)
		}
	}

	if len(tampered) > 0 {
		result["potential_tampering"] = tampered
		result["forensic_alert"] = "CRITICAL: Hash mismatch detected - possible image tampering"
	}

	return result, nil
}

// ParseSoftwareAuthenticity parses digital signature verification output
func (p *IOSXEParser) ParseSoftwareAuthenticity(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	lines := strings.Split(output, "\n")

	var currentSection string
	sections := make(map[string]map[string]string)

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Identify sections
		if strings.Contains(line, "SYSTEM IMAGE") {
			currentSection = "system_image"
			sections[currentSection] = make(map[string]string)
		} else if strings.Contains(line, "Microloader") {
			currentSection = "microloader"
			sections[currentSection] = make(map[string]string)
		}

		// Extract signature information
		if currentSection != "" && strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				// Clean up key names
				key = strings.ToLower(strings.ReplaceAll(key, " ", "_"))
				sections[currentSection][key] = value
			}
		}
	}

	result["signature_sections"] = sections

	// Check for valid Cisco signatures
	systemImg, hasSystemImg := sections["system_image"]
	if hasSystemImg {
		if orgName, exists := systemImg["organization_name"]; exists && orgName == "CiscoSystems" {
			result["cisco_signature_valid"] = true
		} else {
			result["cisco_signature_valid"] = false
			result["forensic_alert"] = "WARNING: Non-Cisco signature detected"
		}
	}

	return result, nil
}

// ParseMemoryMaps parses memory map output for tampering detection
func (p *IOSXEParser) ParseMemoryMaps(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	lines := strings.Split(output, "\n")

	var segments []map[string]interface{}
	var currentSegment map[string]interface{}
	suspiciousSegments := make([]map[string]interface{}, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Parse memory segment header
		if strings.Contains(line, "-") && (strings.Contains(line, "r-xp") || strings.Contains(line, "rwxp")) {
			if currentSegment != nil {
				segments = append(segments, currentSegment)
			}

			parts := strings.Fields(line)
			if len(parts) >= 2 {
				currentSegment = map[string]interface{}{
					"address_range": parts[0],
					"permissions":   parts[1],
				}
			}
		}

		// Parse Private_Dirty value
		if currentSegment != nil && strings.Contains(line, "Private_Dirty:") {
			re := regexp.MustCompile(`Private_Dirty:\s*(\d+)\s*kB`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 {
				if privateDirty, err := strconv.Atoi(matches[1]); err == nil {
					currentSegment["private_dirty_kb"] = privateDirty

					// Check for potential tampering
					if permissions, exists := currentSegment["permissions"]; exists {
						if perms, ok := permissions.(string); ok && strings.Contains(perms, "rwxp") && privateDirty > 0 {
							currentSegment["potential_tampering"] = true
							suspiciousSegments = append(suspiciousSegments, currentSegment)
						}
					}
				}
			}
		}

		// Parse other memory statistics
		if currentSegment != nil {
			for _, stat := range []string{"Size", "Rss", "Pss", "Shared_Clean", "Shared_Dirty", "Private_Clean"} {
				if strings.Contains(line, stat+":") {
					re := regexp.MustCompile(stat + `:\s*(\d+)\s*kB`)
					if matches := re.FindStringSubmatch(line); len(matches) > 1 {
						if value, err := strconv.Atoi(matches[1]); err == nil {
							currentSegment[strings.ToLower(stat)+"_kb"] = value
						}
					}
				}
			}
		}
	}

	// Add final segment
	if currentSegment != nil {
		segments = append(segments, currentSegment)
	}

	result["memory_segments"] = segments

	if len(suspiciousSegments) > 0 {
		result["suspicious_segments"] = suspiciousSegments
		result["forensic_alert"] = "CRITICAL: Executable memory segments with write access and dirty pages detected - possible runtime tampering"
	}

	return result, nil
}

// ParseSystemMemory parses system memory directory output
func (p *IOSXEParser) ParseSystemMemory(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	lines := strings.Split(output, "\n")

	var memoryRegions []map[string]interface{}

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Parse memory region entries
		if strings.Contains(line, "-r--") {
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				region := map[string]interface{}{
					"permissions": parts[1],
					"name":        parts[len(parts)-1],
				}

				// Parse size if available
				if len(parts) >= 3 && parts[2] != "-" {
					if size, err := strconv.Atoi(parts[2]); err == nil {
						region["size_bytes"] = size
					}
				}

				memoryRegions = append(memoryRegions, region)
			}
		}
	}

	result["memory_regions"] = memoryRegions

	// Check for text region availability
	for _, region := range memoryRegions {
		if name, exists := region["name"]; exists && name == "text" {
			result["text_region_available"] = true
			result["text_region_size"] = region["size_bytes"]
			break
		}
	}

	return result, nil
}

// ParsePlatformIntegrity parses platform integrity signature output
func (p *IOSXEParser) ParsePlatformIntegrity(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	// This command typically returns a signature or error
	// Implementation depends on actual command output format
	result["integrity_check"] = strings.TrimSpace(output)

	if strings.Contains(output, "Error") || strings.Contains(output, "Failed") {
		result["integrity_status"] = "failed"
		result["forensic_alert"] = "Platform integrity check failed"
	} else if len(strings.TrimSpace(output)) > 0 {
		result["integrity_status"] = "success"
	}

	return result, nil
}

// ParsePackagesConf parses packages.conf file content
func (p *IOSXEParser) ParsePackagesConf(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	lines := strings.Split(output, "\n")

	var packages []map[string]interface{}
	var sha1Hash string

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Extract SHA1 hash
		if strings.Contains(line, "sha1sum:") {
			parts := strings.Split(line, "sha1sum:")
			if len(parts) > 1 {
				sha1Hash = strings.TrimSpace(parts[1])
			}
		}

		// Parse package entries
		if strings.Contains(line, "rp ") || strings.Contains(line, "fp ") {
			parts := strings.Fields(line)
			if len(parts) >= 6 {
				pkg := map[string]interface{}{
					"type":     parts[0],
					"location": parts[1] + " " + parts[2] + " " + parts[3],
					"role":     parts[4],
					"filename": parts[5],
				}
				packages = append(packages, pkg)
			}
		}
	}

	result["sha1_hash"] = sha1Hash
	result["packages"] = packages
	result["unique_packages"] = getUniquePackages(packages)

	return result, nil
}

// getUniquePackages extracts unique package filenames
func getUniquePackages(packages []map[string]interface{}) []string {
	seen := make(map[string]bool)
	var unique []string

	for _, pkg := range packages {
		if filename, exists := pkg["filename"]; exists {
			if filenameStr, ok := filename.(string); ok && !seen[filenameStr] {
				seen[filenameStr] = true
				unique = append(unique, filenameStr)
			}
		}
	}

	return unique
}

// ParseRunningConfig parses running configuration for security analysis
func (p *IOSXEParser) ParseRunningConfig(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	lines := strings.Split(output, "\n")

	var interfaces []string
	var users []string
	var accessLists []string
	var services []string
	securityConcerns := make([]string, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Extract interfaces
		if strings.HasPrefix(line, "interface ") {
			interfaces = append(interfaces, strings.TrimPrefix(line, "interface "))
		}

		// Extract users
		if strings.HasPrefix(line, "username ") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				users = append(users, parts[1])
			}
		}

		// Extract access lists
		if strings.HasPrefix(line, "access-list ") || strings.HasPrefix(line, "ip access-list ") {
			accessLists = append(accessLists, line)
		}

		// Extract services
		if strings.HasPrefix(line, "service ") {
			services = append(services, strings.TrimPrefix(line, "service "))
		}

		// Check for security concerns
		if strings.Contains(line, "no service password-encryption") {
			securityConcerns = append(securityConcerns, "Password encryption disabled")
		}
		if strings.Contains(line, "enable password ") && !strings.Contains(line, "enable secret ") {
			securityConcerns = append(securityConcerns, "Unencrypted enable password")
		}
		if strings.Contains(line, "telnet") {
			securityConcerns = append(securityConcerns, "Telnet service enabled (insecure)")
		}
		if strings.Contains(line, "http server") || strings.Contains(line, "ip http server") {
			securityConcerns = append(securityConcerns, "HTTP server enabled")
		}
	}

	result["interfaces"] = interfaces
	result["users"] = users
	result["access_lists"] = accessLists
	result["services"] = services

	if len(securityConcerns) > 0 {
		result["security_concerns"] = securityConcerns
	}

	return result, nil
}

// ParseInterfaces parses interface information
func (p *IOSXEParser) ParseInterfaces(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	interfaces := make(map[string]map[string]interface{})

	var currentInterface string
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// New interface
		if strings.Contains(line, " is ") && (strings.Contains(line, "up") || strings.Contains(line, "down")) {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				currentInterface = parts[0]
				interfaces[currentInterface] = make(map[string]interface{})

				// Parse status
				if strings.Contains(line, " is up") {
					interfaces[currentInterface]["status"] = "up"
				} else if strings.Contains(line, " is down") {
					interfaces[currentInterface]["status"] = "down"
				}
			}
		}

		// Parse interface details
		if currentInterface != "" {
			if strings.Contains(line, "Internet address is ") {
				re := regexp.MustCompile(`Internet address is ([0-9.]+/[0-9]+)`)
				if matches := re.FindStringSubmatch(line); len(matches) > 1 {
					interfaces[currentInterface]["ip_address"] = matches[1]
				}
			}

			if strings.Contains(line, "MTU ") {
				re := regexp.MustCompile(`MTU ([0-9]+)`)
				if matches := re.FindStringSubmatch(line); len(matches) > 1 {
					if mtu, err := strconv.Atoi(matches[1]); err == nil {
						interfaces[currentInterface]["mtu"] = mtu
					}
				}
			}
		}
	}

	result["interfaces"] = interfaces
	return result, nil
}

// Placeholder implementations for other parsers
func (p *IOSXEParser) ParseIPRoute(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	lines := strings.Split(output, "\n")

	var routes []map[string]interface{}

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
		if strings.Contains(line, "/") {
			route := map[string]interface{}{}
			fields := strings.Fields(line)

			if len(fields) >= 3 {
				// Extract destination
				for _, field := range fields {
					if strings.Contains(field, "/") {
						route["destination"] = field
						break
					}
				}

				// Extract protocol
				if len(fields) > 0 {
					route["protocol"] = mapProtocolCode(fields[0])
				}

				// Extract gateway
				if strings.Contains(line, "via") {
					viaParts := strings.Split(line, "via")
					if len(viaParts) > 1 {
						gatewayInfo := strings.TrimSpace(viaParts[1])
						gatewayFields := strings.Fields(gatewayInfo)
						if len(gatewayFields) > 0 {
							route["gateway"] = gatewayFields[0]
						}
					}
				}

				routes = append(routes, route)
			}
		}
	}

	result["routes"] = routes
	return result, nil
}

func (p *IOSXEParser) ParseARP(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	lines := strings.Split(output, "\n")

	var arpEntries []map[string]interface{}
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
			entry := map[string]interface{}{
				"ip_address":  fields[1],
				"mac_address": fields[3],
				"interface":   fields[len(fields)-1],
			}

			if len(fields) >= 2 {
				entry["age"] = fields[0]
			}

			if len(fields) >= 4 {
				entry["type"] = fields[2]
			}

			arpEntries = append(arpEntries, entry)
		}
	}

	result["arp_entries"] = arpEntries
	return result, nil
}

func (p *IOSXEParser) ParseProcesses(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	lines := strings.Split(output, "\n")

	var processes []map[string]interface{}
	headerFound := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip until header is found
		if !headerFound {
			if strings.Contains(line, "PID") && strings.Contains(line, "Runtime") {
				headerFound = true
			}
			continue
		}

		// Parse process entries
		fields := strings.Fields(line)
		if len(fields) >= 8 {
			process := map[string]interface{}{
				"pid":     fields[0],
				"runtime": fields[1],
				"cpu":     fields[4],
				"name":    strings.Join(fields[7:], " "),
			}

			processes = append(processes, process)
		}
	}

	result["processes"] = processes
	return result, nil
}

func (p *IOSXEParser) ParseProcessesMemory(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	lines := strings.Split(output, "\n")

	var memoryProcesses []map[string]interface{}

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Parse memory usage per process
		if strings.Contains(line, "PID") && strings.Contains(line, "TTY") {
			continue // Skip header
		}

		fields := strings.Fields(line)
		if len(fields) >= 6 {
			process := map[string]interface{}{
				"pid":        fields[0],
				"memory_kb":  fields[1],
				"memory_pct": fields[2],
				"name":       strings.Join(fields[5:], " "),
			}

			memoryProcesses = append(memoryProcesses, process)
		}
	}

	result["memory_processes"] = memoryProcesses
	return result, nil
}

func (p *IOSXEParser) ParseUsers(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	lines := strings.Split(output, "\n")

	var sessions []map[string]interface{}

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip header lines
		if strings.Contains(line, "Line") && strings.Contains(line, "User") {
			continue
		}

		// Parse user sessions
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			session := map[string]interface{}{
				"line": fields[0],
				"user": fields[1],
			}

			if len(fields) > 3 {
				session["location"] = strings.Join(fields[3:], " ")
			}

			if len(fields) > 2 {
				session["idle_time"] = fields[2]
			}

			sessions = append(sessions, session)
		}
	}

	result["sessions"] = sessions
	return result, nil
}

func (p *IOSXEParser) ParseLogging(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	lines := strings.Split(output, "\n")

	var logEntries []map[string]interface{}

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}

		entry := map[string]interface{}{
			"raw_line": line,
		}

		// Extract timestamp
		timestampPattern := `^\*?(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{3})?)`
		if matched := regexp.MustCompile(timestampPattern).FindStringSubmatch(line); len(matched) > 1 {
			entry["timestamp"] = matched[1]
			line = strings.TrimSpace(line[len(matched[0]):])
		}

		// Extract facility-severity-mnemonic
		facilityPattern := `%([A-Z_]+)-(\d+)-([A-Z_]+):`
		if matched := regexp.MustCompile(facilityPattern).FindStringSubmatch(line); len(matched) > 3 {
			entry["facility"] = matched[1]
			entry["severity"] = matched[2]
			entry["mnemonic"] = matched[3]

			msgStart := strings.Index(line, matched[0]) + len(matched[0])
			if msgStart < len(line) {
				entry["message"] = strings.TrimSpace(line[msgStart:])
			}
		} else {
			entry["message"] = line
		}

		logEntries = append(logEntries, entry)
	}

	result["log_entries"] = logEntries
	return result, nil
}

func (p *IOSXEParser) ParseInventory(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	lines := strings.Split(output, "\n")

	var inventory []map[string]interface{}
	var currentItem map[string]interface{}

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Detect new inventory item
		if strings.HasPrefix(line, "NAME: ") {
			if currentItem != nil {
				inventory = append(inventory, currentItem)
			}
			currentItem = map[string]interface{}{
				"name": strings.TrimPrefix(line, "NAME: "),
			}
		}

		// Parse item attributes
		if currentItem != nil {
			if strings.HasPrefix(line, "DESCR: ") {
				currentItem["description"] = strings.TrimPrefix(line, "DESCR: ")
			}
			if strings.HasPrefix(line, "PID: ") {
				parts := strings.Fields(strings.TrimPrefix(line, "PID: "))
				if len(parts) > 0 {
					currentItem["pid"] = parts[0]
				}
			}
			if strings.HasPrefix(line, "SN: ") {
				currentItem["serial_number"] = strings.TrimPrefix(line, "SN: ")
			}
		}
	}

	// Add final item
	if currentItem != nil {
		inventory = append(inventory, currentItem)
	}

	result["inventory"] = inventory
	return result, nil
}

// Helper function to map protocol codes to readable names
func mapProtocolCode(code string) string {
	protocolMap := map[string]string{
		"C":  "Connected",
		"S":  "Static",
		"R":  "RIP",
		"M":  "Mobile",
		"B":  "BGP",
		"D":  "EIGRP",
		"EX": "EIGRP External",
		"O":  "OSPF",
		"IA": "OSPF Inter-Area",
		"N1": "OSPF NSSA External Type 1",
		"N2": "OSPF NSSA External Type 2",
		"E1": "OSPF External Type 1",
		"E2": "OSPF External Type 2",
		"i":  "IS-IS",
		"su": "IS-IS Summary",
		"L1": "IS-IS Level-1",
		"L2": "IS-IS Level-2",
		"ia": "IS-IS Inter-Area",
		"*":  "Default Route",
		"U":  "Per-user Static",
		"o":  "ODR",
		"P":  "Periodic downloaded static route",
		"H":  "Host Route",
		"l":  "LISP",
		"+":  "Replicated route",
	}

	cleanCode := strings.TrimLeft(code, " \t")
	if mapped, exists := protocolMap[cleanCode]; exists {
		return mapped
	}

	return code
}

// Enhanced forensic parsers for IOS XE following Cisco forensic guidelines

// ParseAllForensic parses all commands and populates structured DeviceState for forensic analysis
func (p *IOSXEParser) ParseAllForensic(result *core.DeviceState) error {
	if result.ForensicData == nil {
		result.ForensicData = make(map[string]interface{})
	}

	for _, rawCmd := range result.RawCommands {
		if rawCmd.ErrorOutput != "" {
			continue // Skip commands that failed
		}

		switch {
		case strings.Contains(rawCmd.Command, "show version"):
			if parsed, err := p.ParseShowVersionForensic(rawCmd.Output); err == nil {
				result.ForensicData["version_info"] = parsed
				// Update basic device info
				if hostname, exists := parsed["hostname"]; exists {
					if hostnameStr, ok := hostname.(string); ok {
						result.DeviceInfo.Hostname = hostnameStr
					}
				}
				if serialNum, exists := parsed["serial_number"]; exists {
					if serialStr, ok := serialNum.(string); ok {
						result.DeviceInfo.SerialNumber = serialStr
					}
				}
				if version, exists := parsed["ios_xe_version"]; exists {
					if versionStr, ok := version.(string); ok {
						result.DeviceInfo.Version = versionStr
					}
				}
			}

		case strings.Contains(rawCmd.Command, "show platform integrity"):
			if parsed, err := p.ParsePlatformIntegrity(rawCmd.Output); err == nil {
				result.ForensicData["platform_integrity"] = parsed
			}

		case strings.Contains(rawCmd.Command, "show software authenticity"):
			if parsed, err := p.ParseSoftwareAuthenticity(rawCmd.Output); err == nil {
				result.ForensicData["software_authenticity"] = parsed
			}

		case strings.Contains(rawCmd.Command, "show package"):
			if parsed, err := p.ParsePackagesConf(rawCmd.Output); err == nil {
				result.ForensicData["package_info"] = parsed
			}

		case strings.Contains(rawCmd.Command, "verify") && strings.Contains(rawCmd.Command, "/md5"):
			if parsed, err := p.ParseImageVerification(rawCmd.Output); err == nil {
				result.ForensicData["image_verification"] = parsed
			}

		case strings.Contains(rawCmd.Command, "show memory") && strings.Contains(rawCmd.Command, "mapping"):
			if parsed, err := p.ParseMemoryMapsForensic(rawCmd.Output); err == nil {
				result.ForensicData["memory_maps"] = parsed
			}

		case strings.Contains(rawCmd.Command, "show ip route"):
			if parsed, err := p.ParseIPRoute(rawCmd.Output); err == nil {
				// Convert to core.Route structs
				if routes, exists := parsed["routes"]; exists {
					if routesSlice, ok := routes.([]map[string]interface{}); ok {
						for _, routeMap := range routesSlice {
							route := core.Route{}
							if dest, exists := routeMap["destination"]; exists {
								if destStr, ok := dest.(string); ok {
									route.Destination = destStr
								}
							}
							if gateway, exists := routeMap["gateway"]; exists {
								if gwStr, ok := gateway.(string); ok {
									route.Gateway = gwStr
								}
							}
							if protocol, exists := routeMap["protocol"]; exists {
								if protoStr, ok := protocol.(string); ok {
									route.Protocol = protoStr
								}
							}
							result.Routes = append(result.Routes, route)
						}
					}
				}
			}

		case strings.Contains(rawCmd.Command, "show ip arp"):
			if parsed, err := p.ParseARP(rawCmd.Output); err == nil {
				result.ForensicData["arp_table"] = parsed
			}

		case strings.Contains(rawCmd.Command, "show processes"):
			if parsed, err := p.ParseProcesses(rawCmd.Output); err == nil {
				// Convert to core.Process structs
				if processes, exists := parsed["processes"]; exists {
					if processSlice, ok := processes.([]map[string]interface{}); ok {
						for _, procMap := range processSlice {
							process := core.Process{}
							if pid, exists := procMap["pid"]; exists {
								if pidStr, ok := pid.(string); ok {
									process.PID = pidStr
								}
							}
							if name, exists := procMap["name"]; exists {
								if nameStr, ok := name.(string); ok {
									process.Name = nameStr
								}
							}
							if cpu, exists := procMap["cpu"]; exists {
								if cpuStr, ok := cpu.(string); ok {
									process.CPU = cpuStr
								}
							}
							if runtime, exists := procMap["runtime"]; exists {
								if runtimeStr, ok := runtime.(string); ok {
									process.Runtime = runtimeStr
								}
							}
							result.Processes = append(result.Processes, process)
						}
					}
				}
			}

		case strings.Contains(rawCmd.Command, "show users"):
			if parsed, err := p.ParseUsers(rawCmd.Output); err == nil {
				// Convert to core.Session structs
				if sessions, exists := parsed["sessions"]; exists {
					if sessionSlice, ok := sessions.([]map[string]interface{}); ok {
						for _, sessionMap := range sessionSlice {
							session := core.Session{}
							if user, exists := sessionMap["user"]; exists {
								if userStr, ok := user.(string); ok {
									session.User = userStr
								}
							}
							if line, exists := sessionMap["line"]; exists {
								if lineStr, ok := line.(string); ok {
									session.Line = lineStr
								}
							}
							if location, exists := sessionMap["location"]; exists {
								if locStr, ok := location.(string); ok {
									session.Location = locStr
								}
							}
							if idleTime, exists := sessionMap["idle_time"]; exists {
								if idleStr, ok := idleTime.(string); ok {
									session.IdleTime = idleStr
								}
							}
							result.Sessions = append(result.Sessions, session)
						}
					}
				}
			}

		case strings.Contains(rawCmd.Command, "show interfaces"):
			if parsed, err := p.ParseInterfaces(rawCmd.Output); err == nil {
				// Convert to core.Interface structs
				if interfaces, exists := parsed["interfaces"]; exists {
					if interfacesMap, ok := interfaces.(map[string]map[string]interface{}); ok {
						for name, ifaceData := range interfacesMap {
							iface := core.Interface{Name: name}
							if status, exists := ifaceData["status"]; exists {
								if statusStr, ok := status.(string); ok {
									iface.Status = statusStr
								}
							}
							if ipAddr, exists := ifaceData["ip_address"]; exists {
								if ipStr, ok := ipAddr.(string); ok {
									iface.IPAddress = ipStr
								}
							}
							if mtu, exists := ifaceData["mtu"]; exists {
								if mtuInt, ok := mtu.(int); ok {
									iface.MTU = strconv.Itoa(mtuInt)
								}
							}
							result.Interfaces = append(result.Interfaces, iface)
						}
					}
				}
			}

		case strings.Contains(rawCmd.Command, "show logging"):
			if parsed, err := p.ParseLogging(rawCmd.Output); err == nil {
				// Convert to core.LogEntry structs
				if logEntries, exists := parsed["log_entries"]; exists {
					if logSlice, ok := logEntries.([]map[string]interface{}); ok {
						for _, logMap := range logSlice {
							logEntry := core.LogEntry{}
							if timestamp, exists := logMap["timestamp"]; exists {
								if tsStr, ok := timestamp.(string); ok {
									// Try to parse the timestamp, if it fails use current time
									if parsedTime, err := time.Parse("Jan 2 15:04:05", tsStr); err == nil {
										logEntry.Timestamp = parsedTime
									} else {
										logEntry.Timestamp = time.Now()
									}
								}
							}
							if facility, exists := logMap["facility"]; exists {
								if facStr, ok := facility.(string); ok {
									logEntry.Facility = facStr
								}
							}
							if severity, exists := logMap["severity"]; exists {
								if sevStr, ok := severity.(string); ok {
									logEntry.Severity = sevStr
								}
							}
							if mnemonic, exists := logMap["mnemonic"]; exists {
								if mnStr, ok := mnemonic.(string); ok {
									logEntry.Mnemonic = mnStr
								}
							}
							if message, exists := logMap["message"]; exists {
								if msgStr, ok := message.(string); ok {
									logEntry.Message = msgStr
								}
							}
							if rawLine, exists := logMap["raw_line"]; exists {
								if rawStr, ok := rawLine.(string); ok {
									logEntry.RawLine = rawStr
								}
							}
							result.Security.Logs = append(result.Security.Logs, logEntry)
						}
					}
				}
			}

		case strings.Contains(rawCmd.Command, "show inventory"):
			if parsed, err := p.ParseInventory(rawCmd.Output); err == nil {
				result.ForensicData["inventory"] = parsed
			}

		case strings.Contains(rawCmd.Command, "show platform"):
			result.ForensicData["platform_info"] = map[string]interface{}{
				"raw_output": rawCmd.Output,
				"parsed_at":  time.Now(),
			}
		}
	}

	return nil
}

// ParseShowVersionForensic provides enhanced version parsing for forensic analysis
func (p *IOSXEParser) ParseShowVersionForensic(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	lines := strings.Split(output, "\n")

	result["parsed_at"] = time.Now()
	result["line_count"] = len(lines)

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Extract IOS XE version with enhanced details
		if strings.Contains(line, "Cisco IOS XE Software, Version ") {
			re := regexp.MustCompile(`Version\s+([^\s,]+)`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 {
				result["ios_xe_version"] = matches[1]
			}
			result["ios_xe_full_line"] = line
		}

		// Extract IOS version
		if strings.Contains(line, "Cisco IOS Software") {
			re := regexp.MustCompile(`Version\s+([^,]+)`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 {
				result["ios_version"] = strings.TrimSpace(matches[1])
			}
			result["ios_full_line"] = line
		}

		// Extract uptime with enhanced parsing
		if strings.Contains(line, " uptime is ") {
			parts := strings.Split(line, " uptime is ")
			if len(parts) > 1 {
				result["hostname"] = strings.TrimSpace(parts[0])
				result["uptime"] = strings.TrimSpace(parts[1])
				result["uptime_line"] = line
			}
		}

		// Extract system image with verification info
		if strings.Contains(line, "System image file is ") {
			re := regexp.MustCompile(`System image file is "([^"]+)"`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 {
				result["system_image"] = matches[1]
				result["system_image_line"] = line
			}
		}

		// Extract compilation information for forensic analysis
		if strings.Contains(line, "Compiled ") {
			result["compilation_info"] = line
			// Extract compilation date/time
			if strings.Contains(line, " by ") {
				parts := strings.Split(line, " by ")
				if len(parts) > 0 {
					result["compilation_date"] = strings.TrimSpace(strings.TrimPrefix(parts[0], "Compiled"))
				}
				if len(parts) > 1 {
					result["compiled_by"] = parts[1]
				}
			}
		}

		// Extract processor information for hardware verification
		if strings.Contains(line, "cisco ") && strings.Contains(line, "processor") {
			result["processor_info"] = line
			// Extract model
			re := regexp.MustCompile(`cisco\s+([^\s]+)`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 {
				result["model"] = matches[1]
			}
		}

		// Extract serial number for device identification
		if strings.Contains(line, "Processor board ID ") {
			parts := strings.Split(line, "Processor board ID ")
			if len(parts) > 1 {
				result["serial_number"] = strings.TrimSpace(parts[1])
				result["serial_line"] = line
			}
		}

		// Extract last reload reason for incident analysis
		if strings.Contains(line, "Last reload reason: ") {
			parts := strings.Split(line, "Last reload reason: ")
			if len(parts) > 1 {
				result["last_reload_reason"] = strings.TrimSpace(parts[1])
				result["reload_line"] = line
			}
		}

		// Extract memory information
		if strings.Contains(line, "bytes of memory") {
			result["memory_info"] = line
		}

		// Extract license information
		if strings.Contains(line, "License level") || strings.Contains(line, "License type") {
			result["license_info"] = line
		}

		// Extract technology package information
		if strings.Contains(line, "Technology package") {
			result["technology_package"] = line
		}
	}

	return result, nil
}

// ParseMemoryMapsForensic parses memory maps for advanced tampering detection
func (p *IOSXEParser) ParseMemoryMapsForensic(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	lines := strings.Split(output, "\n")

	var segments []map[string]interface{}
	var suspiciousSegments []map[string]interface{}
	var currentSegment map[string]interface{}

	result["parsed_at"] = time.Now()
	result["analysis_level"] = "forensic"

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Parse memory segment information
		if strings.Contains(line, "-") && (strings.Contains(line, "r-xp") || strings.Contains(line, "rwxp") || strings.Contains(line, "rw-p")) {
			if currentSegment != nil {
				segments = append(segments, currentSegment)

				// Check for suspicious segments
				if perms, exists := currentSegment["permissions"]; exists {
					if permsStr, ok := perms.(string); ok {
						// Flag writable executable segments as suspicious
						if strings.Contains(permsStr, "rwx") {
							suspiciousSegments = append(suspiciousSegments, currentSegment)
						}
					}
				}
			}

			parts := strings.Fields(line)
			if len(parts) >= 2 {
				currentSegment = map[string]interface{}{
					"address_range": parts[0],
					"permissions":   parts[1],
					"raw_line":      line,
				}

				if len(parts) >= 3 {
					currentSegment["offset"] = parts[2]
				}
				if len(parts) >= 4 {
					currentSegment["device"] = parts[3]
				}
				if len(parts) >= 5 {
					currentSegment["inode"] = parts[4]
				}
				if len(parts) >= 6 {
					currentSegment["pathname"] = strings.Join(parts[5:], " ")
				}
			}
		}
	}

	// Add final segment
	if currentSegment != nil {
		segments = append(segments, currentSegment)
		if perms, exists := currentSegment["permissions"]; exists {
			if permsStr, ok := perms.(string); ok {
				if strings.Contains(permsStr, "rwx") {
					suspiciousSegments = append(suspiciousSegments, currentSegment)
				}
			}
		}
	}

	result["memory_segments"] = segments
	result["total_segments"] = len(segments)

	if len(suspiciousSegments) > 0 {
		result["suspicious_segments"] = suspiciousSegments
		result["suspicious_count"] = len(suspiciousSegments)
		result["forensic_alert"] = "WARNING: Suspicious writable-executable memory segments detected"
	}

	// Calculate memory usage statistics
	executableSegments := 0
	writableSegments := 0

	for _, segment := range segments {
		if perms, exists := segment["permissions"]; exists {
			if permsStr, ok := perms.(string); ok {
				if strings.Contains(permsStr, "x") {
					executableSegments++
				}
				if strings.Contains(permsStr, "w") {
					writableSegments++
				}
			}
		}
	}

	result["executable_segments"] = executableSegments
	result["writable_segments"] = writableSegments

	return result, nil
}
