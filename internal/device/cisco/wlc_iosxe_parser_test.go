package cisco

import (
	"testing"

	"netdac/internal/core"
)

func TestNewWLCIOSXEParser(t *testing.T) {
	parser := NewWLCIOSXEParser()

	if parser == nil {
		t.Fatal("Expected parser to be non-nil")
	}

	if parser.patterns == nil {
		t.Fatal("Expected patterns to be initialized")
	}

	// Test some key patterns exist
	expectedPatterns := []string{
		"ios_version", "system_image", "uptime", "hostname", "hardware",
		"package_entry", "embedded_hash", "computed_hash", "verify_success",
		"image_type", "common_name", "organization", "cert_serial",
		"process_entry", "memory_segment", "ap_count", "client_count",
	}

	for _, pattern := range expectedPatterns {
		if parser.patterns[pattern] == nil {
			t.Errorf("Expected pattern '%s' to be defined", pattern)
		}
	}
}

func TestWLCIOSXEParser_ParseVersion(t *testing.T) {
	parser := NewWLCIOSXEParser()

	// Sample WLC version output
	output := `WLC-9800 uptime is 2 weeks, 3 days, 4 hours, 30 minutes
System returned to ROM by reload at 10:15:06 UTC Mon Jan 8 2024
System restarted at 10:18:32 UTC Mon Jan 8 2024
System image file is "bootflash:packages.conf"

cisco C9800-L-C-K9 (X86_64_LINUX_IOSD-UNIVERSALK9_WLC-M) processor (revision V04) with 8110072K/6147K bytes of memory.
Processor board ID FCW2315L0B0
32 Gigabit Ethernet interfaces
2 Twenty Five Gigabit Ethernet interfaces
32768K bytes of non-volatile configuration memory.
8388608K bytes of physical memory.
1638400K bytes of crash dump memory.
7774208K bytes of eUSB flash at bootflash:.

Base Ethernet MAC Address          : 70:69:5a:0e:c6:40
Motherboard Assembly Number        : 73-18748-06
Motherboard Serial Number          : FOC23140J7L
Model Revision Number              : V04
Motherboard Revision Number        : A0
Model Number                       : C9800-L-C-K9
System Serial Number               : FCW2315L0B0

Cisco IOS XE Software, Version 17.12.04
Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_WLC), Version 17.12.04, RELEASE SOFTWARE (fc3)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2024 by Cisco Systems, Inc.
Compiled Wed 06-Mar-24 03:51 by mcpre`

	info, err := parser.ParseVersion(output)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if info.Hostname != "WLC-9800" {
		t.Errorf("Expected hostname 'WLC-9800', got '%s'", info.Hostname)
	}

	if info.Version != "17.12.04" {
		t.Errorf("Expected version '17.12.04', got '%s'", info.Version)
	}

	if info.Model != "C9800-L-C-K9" {
		t.Errorf("Expected model 'C9800-L-C-K9', got '%s'", info.Model)
	}

	if info.SerialNumber != "FCW2315L0B0" {
		t.Errorf("Expected serial number 'FCW2315L0B0', got '%s'", info.SerialNumber)
	}

	if info.Vendor != "Cisco" {
		t.Errorf("Expected vendor 'Cisco', got '%s'", info.Vendor)
	}

	if info.Uptime != "2 weeks, 3 days, 4 hours, 30 minutes" {
		t.Errorf("Expected uptime '2 weeks, 3 days, 4 hours, 30 minutes', got '%s'", info.Uptime)
	}
}

func TestWLCIOSXEParser_ParsePackagesConf(t *testing.T) {
	parser := NewWLCIOSXEParser()

	// Sample packages.conf output
	output := `#! /usr/binos/bin/packages_conf.sh
sha1sum: 1d206d5536d48eee6c79e11aa9a7f0f7b9fda874
# sha1sum above - used to verify that this file is not corrupted.
#
# package.conf: provisioned software file for build 2024-11-21_00.33
#
boot  rp 0 0   rp_boot     C9800-L-rpboot.V1712_4_ESW13.SPA.pkg
iso   rp 0 0   rp_base     C9800-L-mono-universalk9_wlc.V1712_4_ESW13.SPA.pkg
iso   rp 0 1   rp_base     C9800-L-mono-universalk9_wlc.V1712_4_ESW13.SPA.pkg
iso   rp 0 0   rp_daemons  C9800-L-mono-universalk9_wlc.V1712_4_ESW13.SPA.pkg
iso   rp 0 1   rp_daemons  C9800-L-mono-universalk9_wlc.V1712_4_ESW13.SPA.pkg
iso   rp 0 0   rp_iosd     C9800-L-mono-universalk9_wlc.V1712_4_ESW13.SPA.pkg
iso   rp 0 1   rp_iosd     C9800-L-mono-universalk9_wlc.V1712_4_ESW13.SPA.pkg`

	resultMap, err := parser.ParsePackagesConf(output)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if resultMap["packages_conf_sha1"] != "1d206d5536d48eee6c79e11aa9a7f0f7b9fda874" {
		t.Errorf("Expected SHA1 '1d206d5536d48eee6c79e11aa9a7f0f7b9fda874', got '%v'", resultMap["packages_conf_sha1"])
	}

	packages, ok := resultMap["packages"].([]map[string]string)
	if !ok {
		t.Fatal("Expected packages to be []map[string]string")
	}

	if len(packages) != 2 { // Should have 2 unique packages
		t.Errorf("Expected 2 unique packages, got %d", len(packages))
	}

	// Check unique package count
	if resultMap["unique_package_count"] != 2 {
		t.Errorf("Expected unique package count 2, got %v", resultMap["unique_package_count"])
	}
}

func TestWLCIOSXEParser_ParseImageVerify(t *testing.T) {
	parser := NewWLCIOSXEParser()

	// Sample verify output
	output := `Verifying file integrity of bootflash:C9800-L-rpboot.V1712_4_ESW13.SPA.pkg ..................
Embedded Hash   SHA1 : 58399C2563376C5741790570E0C463C02F001B7D
Computed Hash   SHA1 : 58399C2563376C5741790570E0C463C02F001B7D
Starting image verification
Hash Computation:    100%Done!
Computed Hash   SHA2: 39251a15f8b81046f87085857672c70a
                      faecd5d70f1c32c86a38b1143a58e50b
                      b596158c08f7c65c37a006dd498c5e34
                      56f89398123786db481298e08538d212
                      
Embedded Hash   SHA2: 39251a15f8b81046f87085857672c70a
                      faecd5d70f1c32c86a38b1143a58e50b
                      b596158c08f7c65c37a006dd498c5e34
                      56f89398123786db481298e08538d212

Digital signature successfully verified in file bootflash:C9800-L-rpboot.V1712_4_ESW13.SPA.pkg`

	resultMap, err := parser.ParseImageVerify(output)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if resultMap["embedded_sha1"] != "58399C2563376C5741790570E0C463C02F001B7D" {
		t.Errorf("Expected embedded SHA1 '58399C2563376C5741790570E0C463C02F001B7D', got '%v'", resultMap["embedded_sha1"])
	}

	if resultMap["computed_sha1"] != "58399C2563376C5741790570E0C463C02F001B7D" {
		t.Errorf("Expected computed SHA1 '58399C2563376C5741790570E0C463C02F001B7D', got '%v'", resultMap["computed_sha1"])
	}

	if resultMap["verification_status"] != "success" {
		t.Errorf("Expected verification status 'success', got '%v'", resultMap["verification_status"])
	}

	if resultMap["sha1_match"] != true {
		t.Errorf("Expected SHA1 match to be true, got %v", resultMap["sha1_match"])
	}

	expectedSha2 := "39251a15f8b81046f87085857672c70afaecd5d70f1c32c86a38b1143a58e50bb596158c08f7c65c37a006dd498c5e3456f89398123786db481298e08538d212"
	if resultMap["embedded_sha2"] != expectedSha2 {
		t.Errorf("Expected embedded SHA2 to be cleaned, got '%v'", resultMap["embedded_sha2"])
	}
}

func TestWLCIOSXEParser_ParseSoftwareAuthenticity(t *testing.T) {
	parser := NewWLCIOSXEParser()

	// Sample software authenticity output
	output := `File Name                     : bootflash:C9800-L-rpboot.V1712_4_ESW13.SPA.pkg
Image type                    : Production
    Signer Information
        Common Name           : CiscoSystems
        Organization Unit     : EWLC
        Organization Name     : CiscoSystems
    Certificate Serial Number : 673F86FE
    Hash Algorithm            : SHA512
    Signature Algorithm       : 2048-bit RSA
    Key Version               : A`

	resultMap, err := parser.ParseSoftwareAuthenticity(output)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if resultMap["image_type"] != "Production" {
		t.Errorf("Expected image type 'Production', got '%v'", resultMap["image_type"])
	}

	if resultMap["signer_common_name"] != "CiscoSystems" {
		t.Errorf("Expected signer common name 'CiscoSystems', got '%v'", resultMap["signer_common_name"])
	}

	if resultMap["signer_organization"] != "CiscoSystems" {
		t.Errorf("Expected signer organization 'CiscoSystems', got '%v'", resultMap["signer_organization"])
	}

	if resultMap["signer_org_unit"] != "EWLC" {
		t.Errorf("Expected signer org unit 'EWLC', got '%v'", resultMap["signer_org_unit"])
	}

	if resultMap["certificate_serial"] != "673F86FE" {
		t.Errorf("Expected certificate serial '673F86FE', got '%v'", resultMap["certificate_serial"])
	}

	if resultMap["hash_algorithm"] != "SHA512" {
		t.Errorf("Expected hash algorithm 'SHA512', got '%v'", resultMap["hash_algorithm"])
	}

	if resultMap["signature_algorithm"] != "2048-bit RSA" {
		t.Errorf("Expected signature algorithm '2048-bit RSA', got '%v'", resultMap["signature_algorithm"])
	}

	if resultMap["key_version"] != "A" {
		t.Errorf("Expected key version 'A', got '%v'", resultMap["key_version"])
	}
}

func TestWLCIOSXEParser_ParseIOSDSmaps(t *testing.T) {
	parser := NewWLCIOSXEParser()

	// Sample smaps output with potential tampering indicator
	output := `smaps for process 7438:
address          perms offset   dev   inode      pathname
5d08b11a8000-5d08b518d000 rw-p 19ba5000 07:00 11704                      
Size:              65428 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:               61928 kB
Pss:               61928 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:      6044 kB
Private_Dirty:     55884 kB
Referenced:        61928 kB
Anonymous:         55884 kB

70feac6ef000-70feac75d000 rwxp 007d5000 07:00 23264
Size:                440 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                 432 kB
Pss:                 432 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:       432 kB
Referenced:          432 kB
Anonymous:           432 kB`

	resultMap, err := parser.ParseIOSDSmaps(output)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	segments, ok := resultMap["memory_segments"].([]map[string]interface{})
	if !ok {
		t.Fatal("Expected memory_segments to be []map[string]interface{}")
	}

	if len(segments) != 2 {
		t.Errorf("Expected 2 memory segments, got %d", len(segments))
	}

	// Check first segment (rw-p - normal)
	if segments[0]["permissions"] != "rw-p" {
		t.Errorf("Expected first segment permissions 'rw-p', got '%v'", segments[0]["permissions"])
	}

	if segments[0]["private_dirty_kb"] != "55884" {
		t.Errorf("Expected first segment private dirty '55884', got '%v'", segments[0]["private_dirty_kb"])
	}

	// Check second segment (rwxp - potential tampering)
	if segments[1]["permissions"] != "rwxp" {
		t.Errorf("Expected second segment permissions 'rwxp', got '%v'", segments[1]["permissions"])
	}

	if segments[1]["private_dirty_kb"] != "432" {
		t.Errorf("Expected second segment private dirty '432', got '%v'", segments[1]["private_dirty_kb"])
	}

	// Check tampering indicator
	if segments[1]["tamper_indicator"] == nil {
		t.Error("Expected tamper indicator for rwxp segment with dirty pages")
	}

	expectedTamperMsg := "executable segment with write permissions and dirty pages"
	if segments[1]["tamper_indicator"] != expectedTamperMsg {
		t.Errorf("Expected tamper indicator '%s', got '%v'", expectedTamperMsg, segments[1]["tamper_indicator"])
	}

	if resultMap["total_segments"] != 2 {
		t.Errorf("Expected total segments 2, got %v", resultMap["total_segments"])
	}
}

func TestWLCIOSXEParser_ParseMemoryTextHash(t *testing.T) {
	parser := NewWLCIOSXEParser()

	// Sample memory text hash output
	output := `............................................................................................................................................................
[output omitted]
.......................................................................................................................................................Done!
verify /md5 (system:memory/text) = ce1eec8ada35e22a130888517f7db019`

	resultMap, err := parser.ParseMemoryTextHash(output)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if resultMap["file_path"] != "system:memory/text" {
		t.Errorf("Expected file path 'system:memory/text', got '%v'", resultMap["file_path"])
	}

	if resultMap["md5_hash"] != "ce1eec8ada35e22a130888517f7db019" {
		t.Errorf("Expected MD5 hash 'ce1eec8ada35e22a130888517f7db019', got '%v'", resultMap["md5_hash"])
	}

	if resultMap["hash_algorithm"] != "MD5" {
		t.Errorf("Expected hash algorithm 'MD5', got '%v'", resultMap["hash_algorithm"])
	}

	if resultMap["verification_time"] == nil {
		t.Error("Expected verification time to be set")
	}
}

func TestWLCIOSXEParser_ParseInterfaces(t *testing.T) {
	parser := NewWLCIOSXEParser()

	// Sample interface output
	output := `GigabitEthernet1/0/1 is up, line protocol is up
  Hardware is Catalyst L3 Switch, address is 70ee.5074.2b01 (bia 70ee.5074.2b01)
  Internet address is 192.168.1.100/24
  MTU 1500 bytes, BW 1000000 Kbit/sec
GigabitEthernet1/0/2 is down, line protocol is down
  Hardware is Catalyst L3 Switch, address is 70ee.5074.2b02 (bia 70ee.5074.2b02)
Vlan1 is up, line protocol is up
  Hardware is Catalyst L3 Switch, address is 70ee.5074.2b40 (bia 70ee.5074.2b40)
  Internet address is 10.0.0.10/24`

	interfaces, err := parser.ParseInterfaces(output)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(interfaces) != 3 {
		t.Fatalf("Expected 3 interfaces, got %d", len(interfaces))
	}

	// Test first interface
	if interfaces[0].Name != "GigabitEthernet1/0/1" {
		t.Errorf("Expected interface name 'GigabitEthernet1/0/1', got '%s'", interfaces[0].Name)
	}

	if interfaces[0].Status != "up" {
		t.Errorf("Expected interface status 'up', got '%s'", interfaces[0].Status)
	}

	if interfaces[0].IPAddress != "192.168.1.100/24" {
		t.Errorf("Expected IP address '192.168.1.100/24', got '%s'", interfaces[0].IPAddress)
	}

	if interfaces[0].MACAddress != "70ee.5074.2b01" {
		t.Errorf("Expected MAC address '70ee.5074.2b01', got '%s'", interfaces[0].MACAddress)
	}

	// Test down interface
	if interfaces[1].Status != "down" {
		t.Errorf("Expected interface status 'down', got '%s'", interfaces[1].Status)
	}
}

func TestWLCIOSXEParser_ParseProcesses(t *testing.T) {
	parser := NewWLCIOSXEParser()

	// Sample process output
	output := `PID  USERNAME      PRI  NI    VSZ   RSS STAT            STARTED    TIME CMD
  122 root          20   0  48652  2088 S    Jan 8 11:21      0:00 /usr/bin/wncd
  145 root          20   0 142456  4112 S    Jan 8 11:21      0:03 /usr/bin/wncmgrd
  200 root          20   0  98234  3456 S    Jan 8 11:22      0:01 /usr/bin/mobilityd`

	processes, err := parser.ParseProcesses(output)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(processes) != 3 {
		t.Fatalf("Expected 3 processes, got %d", len(processes))
	}

	// Test first process
	if processes[0].PID != "122" {
		t.Errorf("Expected PID '122', got '%s'", processes[0].PID)
	}

	if processes[0].Name != "/usr/bin/wncd" {
		t.Errorf("Expected name '/usr/bin/wncd', got '%s'", processes[0].Name)
	}

	if processes[0].State != "root" {
		t.Errorf("Expected state 'root', got '%s'", processes[0].State)
	}

	if processes[0].CPU != "20" {
		t.Errorf("Expected CPU '20', got '%s'", processes[0].CPU)
	}

	if processes[0].Memory != "0" {
		t.Errorf("Expected memory '0', got '%s'", processes[0].Memory)
	}
}

func TestWLCIOSXEParser_GetCommandType(t *testing.T) {
	parser := NewWLCIOSXEParser()

	tests := []struct {
		command  string
		expected string
	}{
		{"show version", "version"},
		{"show tech-support", "tech_support"},
		{"show tech-support wireless", "tech_support"},
		{"show processes cpu", "processes"},
		{"show interfaces", "interfaces"},
		{"show ip route", "routes"},
		{"show arp", "arp"},
		{"show software authenticity running", "authenticity"},
		{"verify /md5 system:memory/text", "memory_hash"},
		{"show wireless summary", "wireless"},
		{"show ap summary", "access_points"},
		{"show platform hardware", "platform"},
		{"unknown command", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			result := parser.GetCommandType(tt.command)
			if result != tt.expected {
				t.Errorf("Expected command type '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestWLCIOSXEParser_SupportedCommands(t *testing.T) {
	parser := NewWLCIOSXEParser()

	commands := parser.SupportedCommands()
	if len(commands) == 0 {
		t.Error("Expected non-empty list of supported commands")
	}

	// Check for key supported commands
	expectedCommands := []string{
		"show version", "show tech-support", "show tech-support wireless",
		"show software authenticity", "show wireless summary", "show ap summary",
		"show platform hardware", "verify",
	}

	for _, expected := range expectedCommands {
		found := false
		for _, cmd := range commands {
			if cmd == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected supported command '%s' not found", expected)
		}
	}
}

func TestWLCIOSXEParser_ParseCommand(t *testing.T) {
	parser := NewWLCIOSXEParser()

	tests := []struct {
		name     string
		command  string
		output   string
		expected string
	}{
		{
			name:     "version",
			command:  "show version",
			output:   "cisco C9800-L-C-K9 (X86_64_LINUX_IOSD-UNIVERSALK9_WLC-M) processor\nSystem Serial Number: FCW2315L0B0\nCisco IOS XE Software, Version 17.12.04",
			expected: "DeviceInfo",
		},
		{
			name:     "tech_support",
			command:  "show tech-support",
			output:   "show version\nshow running-config\nshow interfaces",
			expected: "map",
		},
		{
			name:     "processes",
			command:  "show processes cpu",
			output:   "122 root          20   0  48652  2088 S    Jan 8 11:21      0:00 /usr/bin/wncd",
			expected: "[]Process",
		},
		{
			name:     "authenticity",
			command:  "show software authenticity running",
			output:   "Image type: Production\nCommon Name: CiscoSystems",
			expected: "[]map",
		},
		{
			name:     "memory_hash",
			command:  "verify /md5 system:memory/text",
			output:   "verify /md5 (system:memory/text) = ce1eec8ada35e22a130888517f7db019",
			expected: "map",
		},
		{
			name:     "unsupported",
			command:  "unsupported command",
			output:   "some output",
			expected: "raw",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parser.ParseCommand(tt.command, tt.output)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result == nil {
				t.Fatal("Expected non-nil result")
			}

			// Basic type checking
			switch tt.expected {
			case "DeviceInfo":
				if _, ok := result.(*core.DeviceInfo); !ok {
					t.Errorf("Expected *core.DeviceInfo, got %T", result)
				}
			case "[]Process":
				if _, ok := result.([]core.Process); !ok {
					t.Errorf("Expected []core.Process, got %T", result)
				}
			case "[]map":
				if _, ok := result.([]map[string]interface{}); !ok {
					t.Errorf("Expected []map[string]interface{}, got %T", result)
				}
			case "map":
				if _, ok := result.(map[string]interface{}); !ok {
					t.Errorf("Expected map[string]interface{}, got %T", result)
				}
			case "raw":
				if rawMap, ok := result.(map[string]string); ok {
					if rawMap["raw_output"] != tt.output {
						t.Errorf("Expected raw output to match input")
					}
				} else {
					t.Errorf("Expected map[string]string for raw output, got %T", result)
				}
			}
		})
	}
}
