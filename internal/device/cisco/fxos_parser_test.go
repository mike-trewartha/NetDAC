package cisco

import (
	"testing"

	"netdac/internal/core"
)

func TestNewFXOSParser(t *testing.T) {
	parser := NewFXOSParser()

	if parser == nil {
		t.Fatal("NewFXOSParser() returned nil")
	}

	if parser.patterns == nil {
		t.Fatal("Parser patterns map is nil")
	}

	// Check that essential patterns are present
	requiredPatterns := []string{
		"fxos_hostname", "fxos_version", "fxos_model", "fxos_serial", "fxos_uptime",
		"ftd_hostname", "ftd_version", "ftd_model", "ftd_serial", "ftd_uptime",
		"process", "ftd_process", "interface", "ip_address", "mac_address",
		"tcp_conn", "udp_conn", "route", "connected_route",
		"auth_signature", "auth_serial", "auth_hash", "memory_hash",
	}

	for _, pattern := range requiredPatterns {
		if _, exists := parser.patterns[pattern]; !exists {
			t.Errorf("Required pattern '%s' not found in parser", pattern)
		}
	}
}

func TestFXOSParser_ParseFXOSVersion(t *testing.T) {
	parser := NewFXOSParser()

	versionOutput := `Cisco Firepower Extensible Operating System (FXOS) Software, Version 2.14.1
Copyright (c) 2013-2024 by Cisco Systems, Inc.

ROM: GRUB 0.97

cisco FPR-1120 with 16384 MBytes of main memory.
Processor board ID JAD123456789

System uptime is 2 weeks, 3 days, 4 hours, 15 minutes
hostname firepower-1120

Package active on node 1/1:
fxos-k8-fp1k-lfbff.2.14.1.69.SPA, V 2.14.1, Cisco Systems`

	result, err := parser.ParseFXOSVersion(versionOutput)
	if err != nil {
		t.Fatalf("ParseFXOSVersion() failed: %v", err)
	}

	if result == nil {
		t.Fatal("ParseFXOSVersion() returned nil result")
	}

	// Check that device info was populated correctly
	if result.Vendor != "cisco" {
		t.Errorf("Expected vendor 'cisco', got '%s'", result.Vendor)
	}

	if result.Version != "2.14.1" {
		t.Errorf("Expected version '2.14.1', got '%s'", result.Version)
	}

	if result.Model != "FPR-1120" {
		t.Errorf("Expected model 'FPR-1120', got '%s'", result.Model)
	}

	if result.SerialNumber != "JAD123456789" {
		t.Errorf("Expected serial 'JAD123456789', got '%s'", result.SerialNumber)
	}

	if result.Hostname != "firepower-1120" {
		t.Errorf("Expected hostname 'firepower-1120', got '%s'", result.Hostname)
	}

	if result.Uptime == "" {
		t.Error("Expected uptime to be populated")
	}
}

func TestFXOSParser_ParseFTDVersion(t *testing.T) {
	parser := NewFXOSParser()

	versionOutput := `Cisco Firepower Threat Defense for FPR-1120 Version 7.4.2
By Cisco Systems, Inc.
Version 7.4.2 (Build 8)
Compiled on Tue Jun 6 14:30:42 2024 by builder

Model                   : Cisco FPR-1120 (1 Network Module)
Hardware Version        : 1.0
Serial Number           : JAD123456789
Software Version        : 7.4.2
Mac Address             : 6c:03:b5:27:e8:00 
hostname ftd-device
up 15 days, 3 hours, 45 minutes

Licensed features for this platform:
Maximum Physical Interfaces       : 8
VLANs                            : 3
Security Contexts                : 2
Carrier                          : Disabled`

	result, err := parser.ParseFTDVersion(versionOutput)
	if err != nil {
		t.Fatalf("ParseFTDVersion() failed: %v", err)
	}

	if result == nil {
		t.Fatal("ParseFTDVersion() returned nil result")
	}

	// Check that device info was populated correctly
	if result.Vendor != "cisco" {
		t.Errorf("Expected vendor 'cisco', got '%s'", result.Vendor)
	}

	if result.Version != "7.4.2" {
		t.Errorf("Expected version '7.4.2', got '%s'", result.Version)
	}

	if result.Model != "FPR-1120" {
		t.Errorf("Expected model 'FPR-1120', got '%s'", result.Model)
	}

	if result.SerialNumber != "JAD123456789" {
		t.Errorf("Expected serial 'JAD123456789', got '%s'", result.SerialNumber)
	}

	if result.Hostname != "ftd-device" {
		t.Errorf("Expected hostname 'ftd-device', got '%s'", result.Hostname)
	}
}

func TestFXOSParser_ParseProcesses(t *testing.T) {
	parser := NewFXOSParser()

	processOutput := `PID    PPID  PGRP   SID USER     %CPU  %MEM    VSZ   RSS TTY        COMMAND
    1       0     1     1 root      0.0   0.1  19724  1512 ?          init [3]
   25       1    25    25 root      0.0   0.0      0     0 ?          [pdflush]
  123     1    123   123 root      0.1   0.5  12345  6789 ?          /usr/sbin/sshd
  456   123    456   456 admin     0.0   0.2   8901  2345 pts/0      -bash
  789     1    789   789 root      0.2   1.0  15678  9012 ?          /opt/cisco/platform/bin/ftd`

	result, err := parser.ParseProcesses(processOutput)
	if err != nil {
		t.Fatalf("ParseProcesses() failed: %v", err)
	}

	if result == nil {
		t.Fatal("ParseProcesses() returned nil result")
	}

	// Should have parsed some processes
	if len(result) == 0 {
		t.Error("Expected some processes to be parsed, got none")
	}

	// Check for specific processes
	foundInit := false
	foundSSHD := false

	for _, proc := range result {
		if proc.Name == "init" {
			foundInit = true
			if proc.PID != "1" {
				t.Errorf("Expected init PID '1', got '%s'", proc.PID)
			}
		}
		if proc.Name == "/usr/sbin/sshd" {
			foundSSHD = true
			if proc.PID != "123" {
				t.Errorf("Expected sshd PID '123', got '%s'", proc.PID)
			}
		}
	}

	if !foundInit {
		t.Error("Expected to find init process")
	}

	if !foundSSHD {
		t.Error("Expected to find sshd process")
	}
}

func TestFXOSParser_ParseInterfaces(t *testing.T) {
	parser := NewFXOSParser()

	interfaceOutput := `GigabitEthernet1/1 is up, line protocol is up
  Hardware is GigE, address is 6c03.b527.e800 (bia 6c03.b527.e800)
  Description: Management Interface
  Internet address is 192.168.1.100/24
  MTU 1500 bytes, BW 1000000 Kbit (Max: 1000000 Kbit)
  Full-duplex, 1000Mb/s, link type is autonegotiation
  
GigabitEthernet1/2 is down, line protocol is down
  Hardware is GigE, address is 6c03.b527.e801 (bia 6c03.b527.e801)
  Description: Unused Interface
  MTU 1500 bytes, BW 1000000 Kbit (Max: 1000000 Kbit)`

	result, err := parser.ParseInterfaces(interfaceOutput)
	if err != nil {
		t.Fatalf("ParseInterfaces() failed: %v", err)
	}

	if result == nil {
		t.Fatal("ParseInterfaces() returned nil result")
	}

	if len(result) != 2 {
		t.Fatalf("Expected 2 interfaces, got %d", len(result))
	}

	// Check first interface
	intf1 := result[0]
	if intf1.Name != "GigabitEthernet1/1" {
		t.Errorf("Expected interface name 'GigabitEthernet1/1', got '%s'", intf1.Name)
	}

	if intf1.AdminStatus != "up" {
		t.Errorf("Expected admin status 'up', got '%s'", intf1.AdminStatus)
	}

	if intf1.Status != "up" {
		t.Errorf("Expected status 'up', got '%s'", intf1.Status)
	}

	if intf1.IPAddress != "192.168.1.100" {
		t.Errorf("Expected IP '192.168.1.100', got '%s'", intf1.IPAddress)
	}

	if intf1.SubnetMask != "/24" {
		t.Errorf("Expected subnet mask '/24', got '%s'", intf1.SubnetMask)
	}

	if intf1.MACAddress != "6c03.b527.e800" {
		t.Errorf("Expected MAC '6c03.b527.e800', got '%s'", intf1.MACAddress)
	}

	// Check second interface
	intf2 := result[1]
	if intf2.Name != "GigabitEthernet1/2" {
		t.Errorf("Expected interface name 'GigabitEthernet1/2', got '%s'", intf2.Name)
	}

	if intf2.AdminStatus != "down" {
		t.Errorf("Expected admin status 'down', got '%s'", intf2.AdminStatus)
	}
}

func TestFXOSParser_ParseSoftwareAuthenticity(t *testing.T) {
	parser := NewFXOSParser()

	authOutput := `File Name                     : <local>/fxos-k8-fp1k-lfbff.2.14.1.69.SPA
Image type                    : Release
    Signer Information
        Common Name           : abraxas
        Organization Unit     : FXOS
        Organization Name     : CiscoSystems
    Certificate Serial Number : 65313942
    Hash Algorithm            : SHA2 512
    Signature Algorithm       : 2048-bit RSA
    Key Version               : A`

	result, err := parser.ParseSoftwareAuthenticity(authOutput)
	if err != nil {
		t.Fatalf("ParseSoftwareAuthenticity() failed: %v", err)
	}

	if result == nil {
		t.Fatal("ParseSoftwareAuthenticity() returned nil result")
	}

	authInfo, ok := result["authenticity_info"].(map[string]string)
	if !ok {
		t.Fatal("Expected authenticity_info to be map[string]string")
	}

	expectedValues := map[string]string{
		"common_name":         "abraxas",
		"organization_unit":   "FXOS",
		"organization_name":   "CiscoSystems",
		"certificate_serial":  "65313942",
		"hash_algorithm":      "SHA2 512",
		"signature_algorithm": "2048-bit RSA",
	}

	for key, expectedValue := range expectedValues {
		if actualValue, exists := authInfo[key]; !exists {
			t.Errorf("Expected authenticity field '%s' not found", key)
		} else if actualValue != expectedValue {
			t.Errorf("Expected %s '%s', got '%s'", key, expectedValue, actualValue)
		}
	}
}

func TestFXOSParser_ParseMemoryTextHash(t *testing.T) {
	parser := NewFXOSParser()

	hashOutput := `!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
[output truncated]
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!Done!
verify /SHA-512 (system:memory/text) = 2289796c12ee7d909ccac135e1b2075bc54d5c7a38300265dda95d5eb665a51b3f45b4fcdc8c17b69c7baa735972aac1a62d2a79530daad67d2aac3dec043b37`

	result, err := parser.ParseMemoryTextHash(hashOutput)
	if err != nil {
		t.Fatalf("ParseMemoryTextHash() failed: %v", err)
	}

	if result == nil {
		t.Fatal("ParseMemoryTextHash() returned nil result")
	}

	expectedHash := "2289796c12ee7d909ccac135e1b2075bc54d5c7a38300265dda95d5eb665a51b3f45b4fcdc8c17b69c7baa735972aac1a62d2a79530daad67d2aac3dec043b37"

	if hash, ok := result["memory_text_hash"].(string); !ok {
		t.Error("Expected memory_text_hash to be string")
	} else if hash != expectedHash {
		t.Errorf("Expected hash '%s', got '%s'", expectedHash, hash)
	}

	if algorithm, ok := result["hash_algorithm"].(string); !ok {
		t.Error("Expected hash_algorithm to be string")
	} else if algorithm != "SHA-512" {
		t.Errorf("Expected algorithm 'SHA-512', got '%s'", algorithm)
	}
}

func TestFXOSParser_ParseDirectoryListing(t *testing.T) {
	parser := NewFXOSParser()

	dirOutput := `Directory of disk0:/

    1  -rw-   119406136   Mar 17 19:20  asdm.bin
    2  -rw-         0   Mar 17 13:08  coredumpfsysimage.bin
    3  -rw-      1109   Mar 17 13:36  asa-cmd-server.log
    4  -rw-        39   Mar 17 13:36  snortpacketinfo.conf
    5  -rw-      1901   Mar 17 13:08  cspCfg.xml

16383066112 bytes total (15739285504 bytes free)`

	result, err := parser.ParseDirectoryListing(dirOutput)
	if err != nil {
		t.Fatalf("ParseDirectoryListing() failed: %v", err)
	}

	if result == nil {
		t.Fatal("ParseDirectoryListing() returned nil result")
	}

	files, ok := result["files"].([]map[string]string)
	if !ok {
		t.Fatal("Expected files to be []map[string]string")
	}

	if len(files) != 5 {
		t.Fatalf("Expected 5 files, got %d", len(files))
	}

	// Check first file
	firstFile := files[0]
	if firstFile["name"] != "asdm.bin" {
		t.Errorf("Expected filename 'asdm.bin', got '%s'", firstFile["name"])
	}

	if firstFile["size"] != "119406136" {
		t.Errorf("Expected size '119406136', got '%s'", firstFile["size"])
	}

	if firstFile["permissions"] != "-rw-" {
		t.Errorf("Expected permissions '-rw-', got '%s'", firstFile["permissions"])
	}

	// Check file count
	if fileCount, ok := result["file_count"].(int); !ok {
		t.Error("Expected file_count to be int")
	} else if fileCount != 5 {
		t.Errorf("Expected file count 5, got %d", fileCount)
	}
}

func TestFXOSParser_GetCommandType(t *testing.T) {
	parser := NewFXOSParser()

	testCases := []struct {
		command      string
		expectedType string
	}{
		{"show version", "device_info"},
		{"show processes", "processes"},
		{"show interface", "interfaces"},
		{"show route", "routes"},
		{"show connection", "connections"},
		{"show software authenticity running", "security_verification"},
		{"verify /sha-512 system:memory/text", "memory_integrity"},
		{"show tech-support detail", "comprehensive_diagnostics"},
		{"dir disk0:", "filesystem_analysis"},
		{"unknown command", "raw_output"},
	}

	for _, tc := range testCases {
		result := parser.GetCommandType(tc.command)
		if result != tc.expectedType {
			t.Errorf("GetCommandType('%s'): expected '%s', got '%s'",
				tc.command, tc.expectedType, result)
		}
	}
}

func TestFXOSParser_SupportedCommands(t *testing.T) {
	parser := NewFXOSParser()

	commands := parser.SupportedCommands()

	if len(commands) == 0 {
		t.Error("Expected some supported commands, got none")
	}

	// Check for essential commands
	requiredCommands := []string{
		"show version",
		"show tech-support fprm detail",
		"show tech-support detail",
		"show processes",
		"show interface",
		"show software authenticity running",
		"verify /sha-512 system:memory/text",
	}

	for _, required := range requiredCommands {
		found := false
		for _, supported := range commands {
			if supported == required {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Required command '%s' not found in supported commands", required)
		}
	}
}

func TestFXOSParser_ParseCommand(t *testing.T) {
	parser := NewFXOSParser()

	// Test version parsing with FXOS output
	fxosVersionOutput := `Cisco Firepower Extensible Operating System (FXOS) Software, Version 2.14.1
cisco FPR-1120 with 16384 MBytes of main memory.`

	result, err := parser.ParseCommand("show version", fxosVersionOutput)
	if err != nil {
		t.Fatalf("ParseCommand failed for FXOS version: %v", err)
	}

	if deviceInfo, ok := result.(*core.DeviceInfo); !ok {
		t.Error("Expected result to be *core.DeviceInfo for version command")
	} else if deviceInfo.Vendor != "cisco" {
		t.Errorf("Expected vendor 'cisco', got '%s'", deviceInfo.Vendor)
	}

	// Test FTD version parsing
	ftdVersionOutput := `Cisco Firepower Threat Defense for FPR-1120 Version 7.4.2
Model                   : Cisco FPR-1120`

	result, err = parser.ParseCommand("show version", ftdVersionOutput)
	if err != nil {
		t.Fatalf("ParseCommand failed for FTD version: %v", err)
	}

	if deviceInfo, ok := result.(*core.DeviceInfo); !ok {
		t.Error("Expected result to be *core.DeviceInfo for FTD version command")
	} else if deviceInfo.Vendor != "cisco" {
		t.Errorf("Expected vendor 'cisco', got '%s'", deviceInfo.Vendor)
	}

	// Test unsupported command
	result, err = parser.ParseCommand("unsupported command", "some output")
	if err != nil {
		t.Fatalf("ParseCommand failed for unsupported command: %v", err)
	}

	if rawResult, ok := result.(map[string]string); !ok {
		t.Error("Expected result to be map[string]string for unsupported command")
	} else if rawResult["raw_output"] != "some output" {
		t.Error("Expected raw_output to contain the original output")
	}
}
