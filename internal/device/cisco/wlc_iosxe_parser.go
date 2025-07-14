package cisco

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"netdac/internal/core"
)

// WLCIOSXEParser implements parsing for Cisco WLC IOS XE forensic command outputs
type WLCIOSXEParser struct {
	patterns map[string]*regexp.Regexp
}

// NewWLCIOSXEParser creates a new WLC IOS XE parser instance
func NewWLCIOSXEParser() *WLCIOSXEParser {
	return &WLCIOSXEParser{
		patterns: map[string]*regexp.Regexp{
			// Version and System Information Patterns
			"ios_version":   regexp.MustCompile(`Cisco IOS XE Software, Version (\S+)`),
			"system_image":  regexp.MustCompile(`System image file is "(.+)"`),
			"uptime":        regexp.MustCompile(`uptime is (.+)`),
			"hostname":      regexp.MustCompile(`(\S+) uptime is`),
			"hardware":      regexp.MustCompile(`cisco (\S+) \((.+)\) processor`),
			"serial_number": regexp.MustCompile(`System Serial Number\s*:\s*(\S+)`),
			"mac_address":   regexp.MustCompile(`Base Ethernet MAC Address\s*:\s*([a-fA-F0-9:.-]+)`),

			// Package and Image Patterns
			"package_entry":  regexp.MustCompile(`^(boot|iso)\s+\w+\s+\d+\s+\d+\s+\w+\s+(.+\.pkg)$`),
			"sha1_hash":      regexp.MustCompile(`sha1sum:\s+([a-fA-F0-9]{40})`),
			"embedded_hash":  regexp.MustCompile(`Embedded Hash\s+SHA1\s*:\s*([A-F0-9]{40})`),
			"computed_hash":  regexp.MustCompile(`Computed Hash\s+SHA1\s*:\s*([A-F0-9]{40})`),
			"embedded_sha2":  regexp.MustCompile(`Embedded Hash\s+SHA2:\s*([a-fA-F0-9\s]+)`),
			"computed_sha2":  regexp.MustCompile(`Computed Hash\s+SHA2:\s*([a-fA-F0-9\s]+)`),
			"verify_success": regexp.MustCompile(`Digital signature successfully verified`),

			// Software Authenticity Patterns
			"image_type":       regexp.MustCompile(`Image type\s*:\s*(\S+)`),
			"common_name":      regexp.MustCompile(`Common Name\s*:\s*(.+)`),
			"organization":     regexp.MustCompile(`Organization Name\s*:\s*(.+)`),
			"org_unit":         regexp.MustCompile(`Organization Unit\s*:\s*(.+)`),
			"cert_serial":      regexp.MustCompile(`Certificate Serial Number\s*:\s*([a-fA-F0-9]+)`),
			"hash_algorithm":   regexp.MustCompile(`Hash Algorithm\s*:\s*(\S+)`),
			"sig_algorithm":    regexp.MustCompile(`Signature Algorithm\s*:\s*(.+)`),
			"key_version":      regexp.MustCompile(`Key Version\s*:\s*(\S+)`),
			"verifier_name":    regexp.MustCompile(`Verifier Name\s*:\s*(.+)`),
			"verifier_version": regexp.MustCompile(`Verifier Version\s*:\s*(.+)`),

			// Process and Memory Patterns
			"process_entry":    regexp.MustCompile(`^\s*(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+\s+\S+\s+\S+)\s+(\S+)\s+(.+)$`),
			"memory_segment":   regexp.MustCompile(`^([a-fA-F0-9-]+)\s+([-rwxp]+)\s+([a-fA-F0-9]+)\s+([a-fA-F0-9:]+)\s+(\d+)\s*(.*)$`),
			"memory_size":      regexp.MustCompile(`Size:\s+(\d+)\s+kB`),
			"memory_rss":       regexp.MustCompile(`Rss:\s+(\d+)\s+kB`),
			"private_dirty":    regexp.MustCompile(`Private_Dirty:\s+(\d+)\s+kB`),
			"private_clean":    regexp.MustCompile(`Private_Clean:\s+(\d+)\s+kB`),
			"memory_text_size": regexp.MustCompile(`(\d+)\s+-r--\s+(\d+)\s+<no date>\s+text`),

			// Wireless-Specific Patterns
			"ap_count":         regexp.MustCompile(`Number of APs:\s+(\d+)`),
			"client_count":     regexp.MustCompile(`Total Number of Clients:\s+(\d+)`),
			"wlan_count":       regexp.MustCompile(`Number of WLANs:\s+(\d+)`),
			"ap_name":          regexp.MustCompile(`^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$`),
			"wireless_profile": regexp.MustCompile(`Profile Name:\s+(.+)`),
			"ssid_entry":       regexp.MustCompile(`SSID:\s+(.+)`),

			// Platform and Hardware Patterns
			"platform_info": regexp.MustCompile(`Platform:\s+(.+)`),
			"cpu_usage":     regexp.MustCompile(`CPU utilization for five seconds:\s+([\d.]+)%`),
			"memory_usage":  regexp.MustCompile(`Processor Pool Total:\s+(\d+)\s+Used:\s+(\d+)\s+Free:\s+(\d+)`),
			"flash_size":    regexp.MustCompile(`(\d+)\s+bytes total \((\d+)\s+bytes free\)`),

			// Network and Interface Patterns
			"interface_line": regexp.MustCompile(`^(\S+)\s+is\s+(\S+),\s+line\s+protocol\s+is\s+(\S+)`),
			"ip_address":     regexp.MustCompile(`Internet address is (\S+)`),
			"interface_mac":  regexp.MustCompile(`Hardware is .+, address is ([a-fA-F0-9.:-]+)`),
			"route_entry":    regexp.MustCompile(`^([CDIRSL*+])\s+(\S+)\s+\[(\d+)/(\d+)\]\s+via\s+(\S+),\s+(.+)`),
			"arp_entry":      regexp.MustCompile(`Internet\s+(\S+)\s+\d+\s+([a-fA-F0-9.:-]+)\s+ARPA\s+(\S+)`),

			// Security and Certificate Patterns
			"cert_subject":   regexp.MustCompile(`Subject:\s+(.+)`),
			"cert_issuer":    regexp.MustCompile(`Issuer:\s+(.+)`),
			"cert_validity":  regexp.MustCompile(`Not After\s*:\s*(.+)`),
			"crypto_session": regexp.MustCompile(`^\s*(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)`),

			// IOX and Application Hosting Patterns
			"iox_status": regexp.MustCompile(`IOx Infrastructure Summary:\s*(\S+)`),
			"app_status": regexp.MustCompile(`^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)`),

			// Hash and Integrity Patterns
			"md5_result":       regexp.MustCompile(`verify /md5 \((.+)\) = ([a-fA-F0-9]{32})`),
			"sha512_result":    regexp.MustCompile(`verify /sha512 \((.+)\) = ([a-fA-F0-9]{128})`),
			"integrity_nonce":  regexp.MustCompile(`Nonce used: (\d+)`),
			"integrity_result": regexp.MustCompile(`Platform Integrity Verification: (\S+)`),

			// Directory and File Patterns
			"dir_entry": regexp.MustCompile(`^\s*(\d+)\s+([-drwx]+)\s+(\d+)\s+(.+)\s+(.+)$`),
			"file_size": regexp.MustCompile(`^\s*(\d+)\s+\S+\s+(\d+)\s+`),

			// Error and Status Patterns
			"error_message":   regexp.MustCompile(`%Error:\s*(.+)`),
			"warning_message": regexp.MustCompile(`%Warning:\s*(.+)`),
			"success_message": regexp.MustCompile(`Success:\s*(.+)`),
		},
	}
}

// ParseCommand parses command output based on the command type
func (p *WLCIOSXEParser) ParseCommand(command, output string) (interface{}, error) {
	switch {
	case strings.Contains(command, "show version"):
		return p.ParseVersion(output)
	case strings.Contains(command, "show tech-support") && strings.Contains(command, "wireless"):
		return p.ParseTechSupportWireless(output)
	case strings.Contains(command, "show tech-support"):
		return p.ParseTechSupport(output)
	case strings.Contains(command, "dir") && strings.Contains(command, "recursive"):
		return p.ParseDirectoryListing(output)
	case strings.Contains(command, "show iox"):
		return p.ParseIOXInfo(output)
	case strings.Contains(command, "show app-hosting"):
		return p.ParseAppHosting(output)
	case strings.Contains(command, "show platform software process memory") && strings.Contains(command, "maps"):
		return p.ParseMemoryMaps(output)
	case strings.Contains(command, "show platform software process memory") && strings.Contains(command, "smaps"):
		return p.ParseIOSDSmaps(output)
	case strings.Contains(command, "show platform integrity"):
		return p.ParseIntegrityCheck(output)
	case strings.Contains(command, "more") && strings.Contains(command, "packages.conf"):
		return p.ParsePackagesConf(output)
	case strings.Contains(command, "verify") && strings.Contains(command, "packages.conf"):
		return p.ParseVerifyPackages(output)
	case strings.Contains(command, "verify") && (strings.Contains(command, ".pkg") || strings.Contains(command, ".bin")):
		return p.ParseImageVerify(output)
	case strings.Contains(command, "show software authenticity file"):
		return p.ParseSoftwareAuthenticity(output)
	case strings.Contains(command, "show software authenticity running"):
		return p.ParseRunningAuthenticity(output)
	case strings.Contains(command, "show software authenticity keys"):
		return p.ParseAuthKeys(output)
	case strings.Contains(command, "dir system:memory/text"):
		return p.ParseMemoryTextDir(output)
	case strings.Contains(command, "verify") && strings.Contains(command, "system:memory/text"):
		return p.ParseMemoryTextHash(output)
	case strings.Contains(command, "show wireless summary"):
		return p.ParseWirelessSummary(output)
	case strings.Contains(command, "show ap summary"):
		return p.ParseAPSummary(output)
	case strings.Contains(command, "show wireless client summary"):
		return p.ParseClientSummary(output)
	case strings.Contains(command, "show processes"):
		return p.ParseProcesses(output)
	case strings.Contains(command, "show interfaces"):
		return p.ParseInterfaces(output)
	case strings.Contains(command, "show ip route"):
		return p.ParseRoutes(output)
	case strings.Contains(command, "show arp"):
		return p.ParseARP(output)
	default:
		// Return raw output for unsupported commands
		return map[string]string{"raw_output": output}, nil
	}
}

// ParseVersion extracts version and system information
func (p *WLCIOSXEParser) ParseVersion(output string) (*core.DeviceInfo, error) {
	info := &core.DeviceInfo{
		Vendor: "Cisco",
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if match := p.patterns["ios_version"].FindStringSubmatch(line); match != nil {
			info.Version = match[1]
		}
		if match := p.patterns["hostname"].FindStringSubmatch(line); match != nil {
			info.Hostname = match[1]
		}
		if match := p.patterns["uptime"].FindStringSubmatch(line); match != nil {
			info.Uptime = match[1]
		}
		if match := p.patterns["hardware"].FindStringSubmatch(line); match != nil {
			info.Model = match[1]
		}
		if match := p.patterns["serial_number"].FindStringSubmatch(line); match != nil {
			info.SerialNumber = match[1]
		}
	}

	return info, nil
}

// ParseTechSupport extracts key information from tech-support output
func (p *WLCIOSXEParser) ParseTechSupport(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	// Extract key sections
	sections := map[string]string{
		"version":        "",
		"running-config": "",
		"interfaces":     "",
		"processes":      "",
		"memory":         "",
	}

	currentSection := ""
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Detect section headers
		if strings.Contains(line, "show version") {
			currentSection = "version"
		} else if strings.Contains(line, "show running-config") {
			currentSection = "running-config"
		} else if strings.Contains(line, "show interfaces") {
			currentSection = "interfaces"
		} else if strings.Contains(line, "show processes") {
			currentSection = "processes"
		} else if strings.Contains(line, "show memory") {
			currentSection = "memory"
		}

		if currentSection != "" {
			sections[currentSection] += line + "\n"
		}
	}

	result["sections"] = sections
	result["size"] = len(output)
	result["collection_time"] = time.Now().Format(time.RFC3339)

	return result, nil
}

// ParseTechSupportWireless extracts wireless-specific information
func (p *WLCIOSXEParser) ParseTechSupportWireless(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	lines := strings.Split(output, "\n")
	var aps []map[string]string
	var clients []map[string]string
	var wlans []map[string]string

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Extract AP information
		if match := p.patterns["ap_count"].FindStringSubmatch(line); match != nil {
			result["ap_count"] = match[1]
		}

		// Extract client information
		if match := p.patterns["client_count"].FindStringSubmatch(line); match != nil {
			result["client_count"] = match[1]
		}

		// Extract WLAN information
		if match := p.patterns["wlan_count"].FindStringSubmatch(line); match != nil {
			result["wlan_count"] = match[1]
		}
	}

	result["access_points"] = aps
	result["clients"] = clients
	result["wlans"] = wlans
	result["size"] = len(output)

	return result, nil
}

// ParseDirectoryListing extracts file system information
func (p *WLCIOSXEParser) ParseDirectoryListing(output string) ([]map[string]interface{}, error) {
	var files []map[string]interface{}
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if match := p.patterns["dir_entry"].FindStringSubmatch(line); match != nil {
			file := map[string]interface{}{
				"inode":       match[1],
				"permissions": match[2],
				"size":        match[3],
				"date":        match[4],
				"name":        match[5],
			}
			files = append(files, file)
		}
	}

	return files, nil
}

// ParseIOXInfo extracts IOx infrastructure information
func (p *WLCIOSXEParser) ParseIOXInfo(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if match := p.patterns["iox_status"].FindStringSubmatch(line); match != nil {
			result["iox_status"] = match[1]
		}
	}

	result["raw_output"] = output
	return result, nil
}

// ParseAppHosting extracts application hosting information
func (p *WLCIOSXEParser) ParseAppHosting(output string) ([]map[string]string, error) {
	var apps []map[string]string
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if match := p.patterns["app_status"].FindStringSubmatch(line); match != nil {
			app := map[string]string{
				"name":   match[1],
				"state":  match[2],
				"status": match[3],
				"ip":     match[4],
				"port":   match[5],
			}
			apps = append(apps, app)
		}
	}

	return apps, nil
}

// ParseMemoryMaps extracts memory mapping information
func (p *WLCIOSXEParser) ParseMemoryMaps(output string) ([]map[string]interface{}, error) {
	var maps []map[string]interface{}
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if match := p.patterns["memory_segment"].FindStringSubmatch(line); match != nil {
			segment := map[string]interface{}{
				"address":     match[1],
				"permissions": match[2],
				"offset":      match[3],
				"device":      match[4],
				"inode":       match[5],
				"pathname":    match[6],
			}
			maps = append(maps, segment)
		}
	}

	return maps, nil
}

// ParseIOSDSmaps extracts detailed IOS daemon memory mapping information
func (p *WLCIOSXEParser) ParseIOSDSmaps(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	var segments []map[string]interface{}
	var currentSegment map[string]interface{}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// New memory segment
		if match := p.patterns["memory_segment"].FindStringSubmatch(line); match != nil {
			if currentSegment != nil {
				segments = append(segments, currentSegment)
			}
			currentSegment = map[string]interface{}{
				"address":     match[1],
				"permissions": match[2],
				"offset":      match[3],
				"device":      match[4],
				"inode":       match[5],
				"pathname":    match[6],
			}
		}

		// Memory details for current segment
		if currentSegment != nil {
			if match := p.patterns["memory_size"].FindStringSubmatch(line); match != nil {
				currentSegment["size_kb"] = match[1]
			}
			if match := p.patterns["memory_rss"].FindStringSubmatch(line); match != nil {
				currentSegment["rss_kb"] = match[1]
			}
			if match := p.patterns["private_dirty"].FindStringSubmatch(line); match != nil {
				currentSegment["private_dirty_kb"] = match[1]
				// Flag potential tampering indicators
				if dirty, err := strconv.Atoi(match[1]); err == nil && dirty > 0 {
					perms := currentSegment["permissions"].(string)
					if strings.Contains(perms, "x") && strings.Contains(perms, "w") {
						currentSegment["tamper_indicator"] = "executable segment with write permissions and dirty pages"
					}
				}
			}
			if match := p.patterns["private_clean"].FindStringSubmatch(line); match != nil {
				currentSegment["private_clean_kb"] = match[1]
			}
		}
	}

	// Add last segment
	if currentSegment != nil {
		segments = append(segments, currentSegment)
	}

	result["memory_segments"] = segments
	result["total_segments"] = len(segments)
	result["analysis_time"] = time.Now().Format(time.RFC3339)

	return result, nil
}

// ParseIntegrityCheck extracts platform integrity verification results
func (p *WLCIOSXEParser) ParseIntegrityCheck(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if match := p.patterns["integrity_nonce"].FindStringSubmatch(line); match != nil {
			result["nonce"] = match[1]
		}
		if match := p.patterns["integrity_result"].FindStringSubmatch(line); match != nil {
			result["verification_result"] = match[1]
		}
	}

	result["raw_output"] = output
	return result, nil
}

// ParsePackagesConf extracts package configuration information
func (p *WLCIOSXEParser) ParsePackagesConf(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	var packages []map[string]string
	uniquePackages := make(map[string]bool)

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Extract SHA1 hash of packages.conf
		if match := p.patterns["sha1_hash"].FindStringSubmatch(line); match != nil {
			result["packages_conf_sha1"] = match[1]
		}

		// Extract package entries
		if match := p.patterns["package_entry"].FindStringSubmatch(line); match != nil {
			packageFile := match[2]
			if !uniquePackages[packageFile] {
				packages = append(packages, map[string]string{
					"type":     match[1],
					"filename": packageFile,
				})
				uniquePackages[packageFile] = true
			}
		}
	}

	result["packages"] = packages
	result["unique_package_count"] = len(packages)
	result["raw_output"] = output

	return result, nil
}

// ParseVerifyPackages extracts package verification results
func (p *WLCIOSXEParser) ParseVerifyPackages(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if match := p.patterns["embedded_hash"].FindStringSubmatch(line); match != nil {
			result["embedded_sha1"] = match[1]
		}
		if match := p.patterns["computed_hash"].FindStringSubmatch(line); match != nil {
			result["computed_sha1"] = match[1]
		}
		if p.patterns["verify_success"].MatchString(line) {
			result["verification_status"] = "success"
		}
	}

	// Check hash consistency
	if embeddedHash, ok := result["embedded_sha1"]; ok {
		if computedHash, ok := result["computed_sha1"]; ok {
			result["hash_match"] = embeddedHash == computedHash
		}
	}

	return result, nil
}

// ParseImageVerify extracts image file verification results
func (p *WLCIOSXEParser) ParseImageVerify(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	lines := strings.Split(output, "\n")

	var embeddedSha2Lines []string
	var computedSha2Lines []string
	inEmbeddedSha2 := false
	inComputedSha2 := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if match := p.patterns["embedded_hash"].FindStringSubmatch(line); match != nil {
			result["embedded_sha1"] = match[1]
		}
		if match := p.patterns["computed_hash"].FindStringSubmatch(line); match != nil {
			result["computed_sha1"] = match[1]
		}

		// Handle multiline SHA2 hashes
		if strings.Contains(line, "Embedded Hash   SHA2:") {
			inEmbeddedSha2 = true
			inComputedSha2 = false
			// Extract hash from this line if present
			if match := p.patterns["embedded_sha2"].FindStringSubmatch(line); match != nil {
				embeddedSha2Lines = append(embeddedSha2Lines, match[1])
			}
		} else if strings.Contains(line, "Computed Hash   SHA2:") {
			inComputedSha2 = true
			inEmbeddedSha2 = false
			// Extract hash from this line if present
			if match := p.patterns["computed_sha2"].FindStringSubmatch(line); match != nil {
				computedSha2Lines = append(computedSha2Lines, match[1])
			}
		} else if inEmbeddedSha2 && strings.Contains(line, "Embedded Hash") {
			inEmbeddedSha2 = false
		} else if inComputedSha2 && strings.Contains(line, "Digital signature") {
			inComputedSha2 = false
		} else if (inEmbeddedSha2 || inComputedSha2) && len(line) > 0 && !strings.Contains(line, ":") {
			// This is a continuation line of SHA2 hash
			hashLine := strings.TrimSpace(line)
			if inEmbeddedSha2 {
				embeddedSha2Lines = append(embeddedSha2Lines, hashLine)
			} else if inComputedSha2 {
				computedSha2Lines = append(computedSha2Lines, hashLine)
			}
		}

		if p.patterns["verify_success"].MatchString(line) {
			result["verification_status"] = "success"
		}
	}

	// Combine SHA2 lines
	if len(embeddedSha2Lines) > 0 {
		cleanHash := strings.ReplaceAll(strings.Join(embeddedSha2Lines, ""), " ", "")
		result["embedded_sha2"] = cleanHash
	}
	if len(computedSha2Lines) > 0 {
		cleanHash := strings.ReplaceAll(strings.Join(computedSha2Lines, ""), " ", "")
		result["computed_sha2"] = cleanHash
	}

	// Check hash consistency
	if embeddedSha1, ok := result["embedded_sha1"]; ok {
		if computedSha1, ok := result["computed_sha1"]; ok {
			result["sha1_match"] = embeddedSha1 == computedSha1
		}
	}
	if embeddedSha2, ok := result["embedded_sha2"]; ok {
		if computedSha2, ok := result["computed_sha2"]; ok {
			result["sha2_match"] = embeddedSha2 == computedSha2
		}
	}

	return result, nil
}

// ParseSoftwareAuthenticity extracts software authenticity verification results
func (p *WLCIOSXEParser) ParseSoftwareAuthenticity(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if match := p.patterns["image_type"].FindStringSubmatch(line); match != nil {
			result["image_type"] = match[1]
		}
		if match := p.patterns["common_name"].FindStringSubmatch(line); match != nil {
			result["signer_common_name"] = strings.TrimSpace(match[1])
		}
		if match := p.patterns["organization"].FindStringSubmatch(line); match != nil {
			result["signer_organization"] = strings.TrimSpace(match[1])
		}
		if match := p.patterns["org_unit"].FindStringSubmatch(line); match != nil {
			result["signer_org_unit"] = strings.TrimSpace(match[1])
		}
		if match := p.patterns["cert_serial"].FindStringSubmatch(line); match != nil {
			result["certificate_serial"] = match[1]
		}
		if match := p.patterns["hash_algorithm"].FindStringSubmatch(line); match != nil {
			result["hash_algorithm"] = match[1]
		}
		if match := p.patterns["sig_algorithm"].FindStringSubmatch(line); match != nil {
			result["signature_algorithm"] = strings.TrimSpace(match[1])
		}
		if match := p.patterns["key_version"].FindStringSubmatch(line); match != nil {
			result["key_version"] = match[1]
		}
	}

	return result, nil
}

// ParseRunningAuthenticity extracts running image authenticity information
func (p *WLCIOSXEParser) ParseRunningAuthenticity(output string) ([]map[string]interface{}, error) {
	var components []map[string]interface{}
	var currentComponent map[string]interface{}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// New component section
		if strings.HasPrefix(line, "PACKAGE ") || strings.HasPrefix(line, "SYSTEM IMAGE") ||
			strings.HasPrefix(line, "ROMMON") || strings.HasPrefix(line, "Microloader") {
			if currentComponent != nil {
				components = append(components, currentComponent)
			}
			currentComponent = map[string]interface{}{
				"component_type": line,
			}
		}

		// Component details
		if currentComponent != nil {
			if match := p.patterns["image_type"].FindStringSubmatch(line); match != nil {
				currentComponent["image_type"] = match[1]
			}
			if match := p.patterns["common_name"].FindStringSubmatch(line); match != nil {
				currentComponent["signer_common_name"] = strings.TrimSpace(match[1])
			}
			if match := p.patterns["organization"].FindStringSubmatch(line); match != nil {
				currentComponent["signer_organization"] = strings.TrimSpace(match[1])
			}
			if match := p.patterns["org_unit"].FindStringSubmatch(line); match != nil {
				currentComponent["signer_org_unit"] = strings.TrimSpace(match[1])
			}
			if match := p.patterns["cert_serial"].FindStringSubmatch(line); match != nil {
				currentComponent["certificate_serial"] = match[1]
			}
			if match := p.patterns["hash_algorithm"].FindStringSubmatch(line); match != nil {
				currentComponent["hash_algorithm"] = match[1]
			}
			if match := p.patterns["sig_algorithm"].FindStringSubmatch(line); match != nil {
				currentComponent["signature_algorithm"] = strings.TrimSpace(match[1])
			}
			if match := p.patterns["key_version"].FindStringSubmatch(line); match != nil {
				currentComponent["key_version"] = match[1]
			}
			if match := p.patterns["verifier_name"].FindStringSubmatch(line); match != nil {
				currentComponent["verifier_name"] = strings.TrimSpace(match[1])
			}
			if match := p.patterns["verifier_version"].FindStringSubmatch(line); match != nil {
				currentComponent["verifier_version"] = strings.TrimSpace(match[1])
			}
		}
	}

	// Add last component
	if currentComponent != nil {
		components = append(components, currentComponent)
	}

	return components, nil
}

// ParseAuthKeys extracts public key information
func (p *WLCIOSXEParser) ParseAuthKeys(output string) ([]map[string]interface{}, error) {
	var keys []map[string]interface{}
	var currentKey map[string]interface{}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// New key section
		if strings.Contains(line, "Public Key #") {
			if currentKey != nil {
				keys = append(keys, currentKey)
			}
			currentKey = map[string]interface{}{}
		}

		// Key details
		if currentKey != nil && strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				currentKey[key] = value
			}
		}
	}

	// Add last key
	if currentKey != nil {
		keys = append(keys, currentKey)
	}

	return keys, nil
}

// ParseMemoryTextDir extracts memory text directory information
func (p *WLCIOSXEParser) ParseMemoryTextDir(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if match := p.patterns["memory_text_size"].FindStringSubmatch(line); match != nil {
			result["text_size_bytes"] = match[2]
		}
	}

	result["raw_output"] = output
	return result, nil
}

// ParseMemoryTextHash extracts memory text hash verification
func (p *WLCIOSXEParser) ParseMemoryTextHash(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if match := p.patterns["md5_result"].FindStringSubmatch(line); match != nil {
			result["file_path"] = match[1]
			result["md5_hash"] = match[2]
			result["hash_algorithm"] = "MD5"
		}
		if match := p.patterns["sha512_result"].FindStringSubmatch(line); match != nil {
			result["file_path"] = match[1]
			result["sha512_hash"] = match[2]
			result["hash_algorithm"] = "SHA512"
		}
	}

	result["verification_time"] = time.Now().Format(time.RFC3339)
	return result, nil
}

// ParseWirelessSummary extracts wireless network summary
func (p *WLCIOSXEParser) ParseWirelessSummary(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if match := p.patterns["ap_count"].FindStringSubmatch(line); match != nil {
			result["access_point_count"] = match[1]
		}
		if match := p.patterns["client_count"].FindStringSubmatch(line); match != nil {
			result["client_count"] = match[1]
		}
		if match := p.patterns["wlan_count"].FindStringSubmatch(line); match != nil {
			result["wlan_count"] = match[1]
		}
	}

	result["raw_output"] = output
	return result, nil
}

// ParseAPSummary extracts access point summary information
func (p *WLCIOSXEParser) ParseAPSummary(output string) ([]map[string]string, error) {
	var aps []map[string]string
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if match := p.patterns["ap_name"].FindStringSubmatch(line); match != nil {
			ap := map[string]string{
				"name":     match[1],
				"mac":      match[2],
				"status":   match[3],
				"location": match[4],
				"ip":       match[5],
				"model":    match[6],
			}
			aps = append(aps, ap)
		}
	}

	return aps, nil
}

// ParseClientSummary extracts wireless client summary
func (p *WLCIOSXEParser) ParseClientSummary(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if match := p.patterns["client_count"].FindStringSubmatch(line); match != nil {
			result["total_clients"] = match[1]
		}
	}

	result["raw_output"] = output
	return result, nil
}

// ParseProcesses extracts process information
func (p *WLCIOSXEParser) ParseProcesses(output string) ([]core.Process, error) {
	var processes []core.Process
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if match := p.patterns["process_entry"].FindStringSubmatch(line); match != nil {
			process := core.Process{
				PID:         match[1],
				Name:        match[10], // CMD column
				CPU:         match[3],  // PRI column
				Memory:      match[4],  // NI column
				State:       match[2],  // USERNAME column
				CommandLine: match[10], // CMD column
			}
			processes = append(processes, process)
		}
	}

	return processes, nil
}

// ParseInterfaces extracts interface information
func (p *WLCIOSXEParser) ParseInterfaces(output string) ([]core.Interface, error) {
	var interfaces []core.Interface
	lines := strings.Split(output, "\n")
	var currentInterface *core.Interface

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// New interface
		if match := p.patterns["interface_line"].FindStringSubmatch(line); match != nil {
			if currentInterface != nil {
				interfaces = append(interfaces, *currentInterface)
			}
			currentInterface = &core.Interface{
				Name:   match[1],
				Status: match[2],
			}
		}

		// Interface details
		if currentInterface != nil {
			if match := p.patterns["ip_address"].FindStringSubmatch(line); match != nil {
				currentInterface.IPAddress = match[1]
			}
			if match := p.patterns["interface_mac"].FindStringSubmatch(line); match != nil {
				currentInterface.MACAddress = match[1]
			}
		}
	}

	// Add last interface
	if currentInterface != nil {
		interfaces = append(interfaces, *currentInterface)
	}

	return interfaces, nil
}

// ParseRoutes extracts routing table information
func (p *WLCIOSXEParser) ParseRoutes(output string) ([]core.Route, error) {
	var routes []core.Route
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if match := p.patterns["route_entry"].FindStringSubmatch(line); match != nil {
			route := core.Route{
				Protocol:      match[1],
				Destination:   match[2],
				NextHop:       match[5],
				Interface:     match[6],
				Metric:        match[4],
				AdminDistance: match[3],
			}
			routes = append(routes, route)
		}
	}

	return routes, nil
}

// ParseARP extracts ARP table information
func (p *WLCIOSXEParser) ParseARP(output string) ([]map[string]string, error) {
	var entries []map[string]string
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if match := p.patterns["arp_entry"].FindStringSubmatch(line); match != nil {
			entry := map[string]string{
				"ip_address":  match[1],
				"mac_address": match[2],
				"interface":   match[3],
			}
			entries = append(entries, entry)
		}
	}

	return entries, nil
}

// GetCommandType returns the type of command for parsing routing
func (p *WLCIOSXEParser) GetCommandType(command string) string {
	switch {
	case strings.Contains(command, "show version"):
		return "version"
	case strings.Contains(command, "show tech-support"):
		return "tech_support"
	case strings.Contains(command, "show processes"):
		return "processes"
	case strings.Contains(command, "show interfaces"):
		return "interfaces"
	case strings.Contains(command, "show ip route"):
		return "routes"
	case strings.Contains(command, "show arp"):
		return "arp"
	case strings.Contains(command, "show software authenticity"):
		return "authenticity"
	case strings.Contains(command, "verify") && strings.Contains(command, "system:memory/text"):
		return "memory_hash"
	case strings.Contains(command, "show wireless"):
		return "wireless"
	case strings.Contains(command, "show ap"):
		return "access_points"
	case strings.Contains(command, "show platform"):
		return "platform"
	default:
		return "unknown"
	}
}

// SupportedCommands returns the list of supported commands for parsing
func (p *WLCIOSXEParser) SupportedCommands() []string {
	return []string{
		"show version", "show tech-support", "show tech-support wireless", "show tech-support diagnostic",
		"dir /recursive all-filesystems", "show iox", "show app-hosting list",
		"show platform software process memory", "show platform integrity sign nonce",
		"more bootflash:packages.conf", "verify", "show software authenticity",
		"show wireless summary", "show ap summary", "show wireless client summary",
		"show processes", "show interfaces", "show ip route", "show arp",
		"show platform hardware", "show crypto pki certificates", "show logging",
	}
}
