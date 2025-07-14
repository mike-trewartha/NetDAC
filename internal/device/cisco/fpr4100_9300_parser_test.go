package cisco

import (
	"strings"
	"testing"

	"netdac/internal/core"
)

func TestNewFPR4100_9300Parser(t *testing.T) {
	parser := NewFPR4100_9300Parser()

	if parser == nil {
		t.Fatal("Expected parser to be non-nil")
	}

	if parser.patterns == nil {
		t.Fatal("Expected patterns to be initialized")
	}

	// Test that essential patterns are present
	essentialPatterns := []string{
		"fxos_version", "ftd_version", "app_instance", "process",
		"adapter_process", "interface", "auth_signature", "memory_hash",
	}

	for _, pattern := range essentialPatterns {
		if parser.patterns[pattern] == nil {
			t.Errorf("Expected pattern '%s' to be initialized", pattern)
		}
	}
}

func TestFPR4100_9300Parser_ParseFXOSVersion(t *testing.T) {
	parser := NewFPR4100_9300Parser()

	// Sample FXOS version output
	output := `Firepower Extensible Operating System (FXOS) Version 2.13.1.135
Model: Cisco FPR-4150-NGFW
hostname FPR4150-1
Serial Number: JMX2147L05K
System uptime: 17 days, 9 hours, 47 minutes
Platform FPR-4150 with 8192 Mbytes of main memory`

	info, err := parser.ParseFXOSVersion(output)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if info.Vendor != "cisco" {
		t.Errorf("Expected vendor 'cisco', got '%s'", info.Vendor)
	}

	if info.Version != "2.13.1.135" {
		t.Errorf("Expected version '2.13.1.135', got '%s'", info.Version)
	}

	if info.Model != "FPR-4150" {
		t.Errorf("Expected model 'FPR-4150', got '%s'", info.Model)
	}

	if info.Hostname != "FPR4150-1" {
		t.Errorf("Expected hostname 'FPR4150-1', got '%s'", info.Hostname)
	}

	if info.SerialNumber != "JMX2147L05K" {
		t.Errorf("Expected serial 'JMX2147L05K', got '%s'", info.SerialNumber)
	}

	if info.Uptime != "17 days, 9 hours, 47 minutes" {
		t.Errorf("Expected uptime '17 days, 9 hours, 47 minutes', got '%s'", info.Uptime)
	}
}

func TestFPR4100_9300Parser_ParseFTDVersion(t *testing.T) {
	parser := NewFPR4100_9300Parser()

	// Sample FTD version output
	output := `Cisco Firepower Threat Defense for Firepower 4100 Series Version 7.3.1.1 (Build 22)
Model: Cisco FPR-4150-NGFW
hostname firepower
Serial Number: JMX2147L05K
up 17 days, 9 hours, 47 minutes`

	info, err := parser.ParseFTDVersion(output)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if info.Vendor != "cisco" {
		t.Errorf("Expected vendor 'cisco', got '%s'", info.Vendor)
	}

	if info.Version != "7.3.1.1" {
		t.Errorf("Expected version '7.3.1.1', got '%s'", info.Version)
	}

	if info.Model != "FPR-4150-NGFW" {
		t.Errorf("Expected model 'FPR-4150-NGFW', got '%s'", info.Model)
	}

	if info.Hostname != "firepower" {
		t.Errorf("Expected hostname 'firepower', got '%s'", info.Hostname)
	}

	if info.SerialNumber != "JMX2147L05K" {
		t.Errorf("Expected serial 'JMX2147L05K', got '%s'", info.SerialNumber)
	}
}

func TestFPR4100_9300Parser_ParseAppInstances(t *testing.T) {
	parser := NewFPR4100_9300Parser()

	// Sample app instance output
	output := `Application instances:
Slot 1    Application Name           Type Status      Version
--------- -------------------------- ---- ----------- -----------
1         ftd                        Native Deployed  7.3.1.1-22
2         asa                        Native Deployed  9.18.4.1-1
3         radware                    Container Running 1.0.0-1`

	instances, err := parser.ParseAppInstances(output)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(instances) != 3 {
		t.Fatalf("Expected 3 instances, got %d", len(instances))
	}

	// Test first instance
	if instances[0]["slot"] != "1" {
		t.Errorf("Expected slot '1', got '%s'", instances[0]["slot"])
	}
	if instances[0]["name"] != "ftd" {
		t.Errorf("Expected name 'ftd', got '%s'", instances[0]["name"])
	}
	if instances[0]["type"] != "Native" {
		t.Errorf("Expected type 'Native', got '%s'", instances[0]["type"])
	}
	if instances[0]["status"] != "Deployed" {
		t.Errorf("Expected status 'Deployed', got '%s'", instances[0]["status"])
	}
	if instances[0]["version"] != "7.3.1.1-22" {
		t.Errorf("Expected version '7.3.1.1-22', got '%s'", instances[0]["version"])
	}
}

func TestFPR4100_9300Parser_ParseProcesses(t *testing.T) {
	parser := NewFPR4100_9300Parser()

	// Sample process output from FTD
	output := `PID    PPID  PGRP   SID USER     %CPU  %MEM    VSZ   RSS TTY        COMMAND
1       0     1     1 root      0.0   0.1  19724  1512 ?          init [3]
25       1    25    25 root      0.0   0.0      0     0 ?          [pdflush]
123     1    123   123 root      0.1   0.5  12345  6789 ?          /usr/sbin/sshd
456   123    456   456 admin     0.0   0.2   8901  2345 pts/0      -bash
789     1    789   789 root      0.2   1.0  15678  9012 ?          /opt/cisco/platform/bin/ftd`

	processes, err := parser.ParseProcesses(output)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(processes) != 5 {
		t.Fatalf("Expected 5 processes, got %d", len(processes))
	}

	// Test init process
	found := false
	for _, process := range processes {
		if process.PID == "1" && strings.Contains(process.CommandLine, "init") {
			found = true
			if process.Name != "init" {
				t.Errorf("Expected process name 'init', got '%s'", process.Name)
			}
			break
		}
	}
	if !found {
		t.Error("Expected to find init process")
	}

	// Test sshd process
	found = false
	for _, process := range processes {
		if process.PID == "123" && strings.Contains(process.CommandLine, "sshd") {
			found = true
			if process.Name != "/usr/sbin/sshd" {
				t.Errorf("Expected process name '/usr/sbin/sshd', got '%s'", process.Name)
			}
			break
		}
	}
	if !found {
		t.Error("Expected to find sshd process")
	}
}

func TestFPR4100_9300Parser_ParseAdapterStatus(t *testing.T) {
	parser := NewFPR4100_9300Parser()

	// Sample adapter status output
	output := `fwvers=5.4(1.10)
last pid:   835;  load avg:  0.08,  0.09,  0.06;  up 17+09:47:14       09:42:49
50 processes: 1 running, 49 sleeping
CPU states:  0.0% user, 0.0% nice,  0.0% system,  100.0% idle,  0.0% iowait
Memory: 43M used, 131M free, 16M cached

  PID USERNAME  THR PRI NICE  SIZE  RES   SHR STATE   TIME    CPU COMMAND
  122 root        1  20    0  475M   14M 2548K sleep  14:10  0.00% mcp
  127 root        1  20    0 5328K  964K  764K sleep   2:06  0.00% /bin/memmon`

	result, err := parser.ParseAdapterStatus(output)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	systemInfo, ok := result["system_info"].(map[string]string)
	if !ok {
		t.Fatal("Expected system_info to be map[string]string")
	}

	if systemInfo["load_1min"] != "0.08" {
		t.Errorf("Expected load_1min '0.08', got '%s'", systemInfo["load_1min"])
	}

	if systemInfo["memory_used"] != "43M" {
		t.Errorf("Expected memory_used '43M', got '%s'", systemInfo["memory_used"])
	}

	if systemInfo["cpu_idle"] != "100.0" {
		t.Errorf("Expected cpu_idle '100.0', got '%s'", systemInfo["cpu_idle"])
	}

	processes, ok := result["processes"].([]map[string]string)
	if !ok {
		t.Fatal("Expected processes to be []map[string]string")
	}

	if len(processes) != 2 {
		t.Fatalf("Expected 2 processes, got %d", len(processes))
	}

	if processes[0]["pid"] != "122" {
		t.Errorf("Expected first process PID '122', got '%s'", processes[0]["pid"])
	}

	if processes[0]["command"] != "mcp" {
		t.Errorf("Expected first process command 'mcp', got '%s'", processes[0]["command"])
	}
}

func TestFPR4100_9300Parser_ParseInterfaces(t *testing.T) {
	parser := NewFPR4100_9300Parser()

	// Sample interface output
	output := `GigabitEthernet0/0 is up, line protocol is up
  Hardware is i82574L Gigabit Ethernet, address is 0050.56b4.6c8a (bia 0050.56b4.6c8a)
  Internet address is 192.168.1.100/24
  MTU 1500 bytes, BW 1000000 Kbit/sec
GigabitEthernet0/1 is down, line protocol is down
  Hardware is i82574L Gigabit Ethernet, address is 0050.56b4.6c8b (bia 0050.56b4.6c8b)
Management0/0 is up, line protocol is up
  Hardware is i82574L Gigabit Ethernet, address is 0050.56b4.6c8c (bia 0050.56b4.6c8c)
  Internet address is 10.0.0.10/24`

	interfaces, err := parser.ParseInterfaces(output)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(interfaces) != 3 {
		t.Fatalf("Expected 3 interfaces, got %d", len(interfaces))
	}

	// Test first interface
	if interfaces[0].Name != "GigabitEthernet0/0" {
		t.Errorf("Expected interface name 'GigabitEthernet0/0', got '%s'", interfaces[0].Name)
	}

	if interfaces[0].Status != "up" {
		t.Errorf("Expected interface status 'up', got '%s'", interfaces[0].Status)
	}

	if interfaces[0].IPAddress != "192.168.1.100/24" {
		t.Errorf("Expected IP address '192.168.1.100/24', got '%s'", interfaces[0].IPAddress)
	}

	if interfaces[0].MACAddress != "0050.56b4.6c8a" {
		t.Errorf("Expected MAC address '0050.56b4.6c8a', got '%s'", interfaces[0].MACAddress)
	}

	// Test down interface
	if interfaces[1].Status != "down" {
		t.Errorf("Expected interface status 'down', got '%s'", interfaces[1].Status)
	}
}

func TestFPR4100_9300Parser_ParseSoftwareAuthenticity(t *testing.T) {
	parser := NewFPR4100_9300Parser()

	// Sample software authenticity output
	output := `MANAGER IMAGE
=============
File Name                     : /bootflash/nuova-sim-mgmt-nsg.0.1.0.001.bin
Image type                    : Release
    Signer Information
        Common Name           : abraxas
        Organization Unit     : FXOS
        Organization Name     : CiscoSystems
    Certificate Serial Number : 5D795456
    Hash Algorithm            : SHA2 512
    Signature Algorithm       : 2048-bit RSA
    Key Version               : A

SYSTEM IMAGE
============
File Name                     : /bootflash/installables/switch/fxos-k9-system.5.0.3.N2.4.71.83.SPA
Image type                    : Release
    Signer Information
        Common Name           : abraxas
        Organization Unit     : FXOS
        Organization Name     : CiscoSystems
    Certificate Serial Number : 5D795240
    Hash Algorithm            : SHA2 512
    Signature Algorithm       : 2048-bit RSA
    Key Version               : A`

	result, err := parser.ParseSoftwareAuthenticity(output)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	managerImage, ok := result["manager"].(map[string]string)
	if !ok {
		t.Fatal("Expected manager image to be map[string]string")
	}

	if managerImage["file_name"] != "/bootflash/nuova-sim-mgmt-nsg.0.1.0.001.bin" {
		t.Errorf("Expected file name '/bootflash/nuova-sim-mgmt-nsg.0.1.0.001.bin', got '%s'", managerImage["file_name"])
	}

	if managerImage["common_name"] != "abraxas" {
		t.Errorf("Expected common name 'abraxas', got '%s'", managerImage["common_name"])
	}

	if managerImage["organization_unit"] != "FXOS" {
		t.Errorf("Expected organization unit 'FXOS', got '%s'", managerImage["organization_unit"])
	}

	if managerImage["certificate_serial"] != "5D795456" {
		t.Errorf("Expected certificate serial '5D795456', got '%s'", managerImage["certificate_serial"])
	}

	systemImage, ok := result["system"].(map[string]string)
	if !ok {
		t.Fatal("Expected system image to be map[string]string")
	}

	if systemImage["certificate_serial"] != "5D795240" {
		t.Errorf("Expected system certificate serial '5D795240', got '%s'", systemImage["certificate_serial"])
	}
}

func TestFPR4100_9300Parser_ParseMemoryTextHash(t *testing.T) {
	parser := NewFPR4100_9300Parser()

	// Sample memory hash output
	output := `!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
[output truncated]
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!Done!
verify /SHA-512 (system:memory/text) = a03a15444f0995f578e9aa6cbc8feed2a3f2dd8accca919b7b2b54836ba3d4b763372f58029e66fa64aafa8eea2b79d5f0c7ea65cde0d813aef17e436e49b85`

	result, err := parser.ParseMemoryTextHash(output)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	expectedHash := "a03a15444f0995f578e9aa6cbc8feed2a3f2dd8accca919b7b2b54836ba3d4b763372f58029e66fa64aafa8eea2b79d5f0c7ea65cde0d813aef17e436e49b85"

	if result["hash_algorithm"] != "SHA-512" {
		t.Errorf("Expected hash algorithm 'SHA-512', got '%s'", result["hash_algorithm"])
	}

	if result["hash_value"] != expectedHash {
		t.Errorf("Expected hash value '%s', got '%s'", expectedHash, result["hash_value"])
	}

	if result["segment"] != "memory/text" {
		t.Errorf("Expected segment 'memory/text', got '%s'", result["segment"])
	}
}

func TestFPR4100_9300Parser_ParseICDBHashes(t *testing.T) {
	parser := NewFPR4100_9300Parser()

	// Sample ICDB hash output
	output := `b5800901d4ccb1df48b648edcda9b40b6766f86eee77ac700bd9e2921ebdd7e645bb8912592627ffd6a54b7d8c82a55876724602a7c77764bb38367cf4adf2f4 /ngfw/var/sf/.icdb/0000/base-intel-6.4.0-102.icdb.RELEASE.tar
63c99b2b92895188f921bfbde6f000d670b65ac07642375b9d9ed8aedb63761441241006a86afb047f7e27d02c10b4df4df8c860b8fba601f91b3a36bebf2cd8 /ngfw/var/sf/.icdb/0000/base-6.4.0-102.icdb.RELEASE.tar`

	hashes, err := parser.ParseICDBHashes(output)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(hashes) != 2 {
		t.Fatalf("Expected 2 hash entries, got %d", len(hashes))
	}

	// Test first hash
	if hashes[0]["algorithm"] != "SHA-512" {
		t.Errorf("Expected algorithm 'SHA-512', got '%s'", hashes[0]["algorithm"])
	}

	if hashes[0]["type"] != "ICDB" {
		t.Errorf("Expected type 'ICDB', got '%s'", hashes[0]["type"])
	}

	expectedHash := "b5800901d4ccb1df48b648edcda9b40b6766f86eee77ac700bd9e2921ebdd7e645bb8912592627ffd6a54b7d8c82a55876724602a7c77764bb38367cf4adf2f4"
	if hashes[0]["hash_value"] != expectedHash {
		t.Errorf("Expected hash value '%s', got '%s'", expectedHash, hashes[0]["hash_value"])
	}

	expectedFile := "/ngfw/var/sf/.icdb/0000/base-intel-6.4.0-102.icdb.RELEASE.tar"
	if hashes[0]["file_path"] != expectedFile {
		t.Errorf("Expected file path '%s', got '%s'", expectedFile, hashes[0]["file_path"])
	}
}

func TestFPR4100_9300Parser_ParseFileIntegrity(t *testing.T) {
	parser := NewFPR4100_9300Parser()

	// Test successful verification
	successOutput := `Running file integrity checks...
Successfully verified file integrity`

	result, err := parser.ParseFileIntegrity(successOutput)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result["status"] != "PASS" {
		t.Errorf("Expected status 'PASS', got '%s'", result["status"])
	}

	if result["result"] != "File integrity verification successful" {
		t.Errorf("Expected result 'File integrity verification successful', got '%s'", result["result"])
	}

	// Test failed verification
	failureOutput := `Running file integrity checks...
Error: Failed to verify file integrity against the signed database`

	result, err = parser.ParseFileIntegrity(failureOutput)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result["status"] != "FAIL" {
		t.Errorf("Expected status 'FAIL', got '%s'", result["status"])
	}
}

func TestFPR4100_9300Parser_GetCommandType(t *testing.T) {
	parser := NewFPR4100_9300Parser()

	testCases := []struct {
		command      string
		expectedType string
	}{
		{"show version", "version"},
		{"show app-instance", "app_instances"},
		{"show tech-support detail", "tech_support"},
		{"show processes", "processes"},
		{"show-systemstatus", "adapter_status"},
		{"show interface", "interfaces"},
		{"show route", "routes"},
		{"show connection", "connections"},
		{"show software authenticity running", "software_authenticity"},
		{"verify /sha-512 system:memory/text", "memory_hash"},
		{"unknown command", "raw"},
	}

	for _, test := range testCases {
		t.Run(test.command, func(t *testing.T) {
			result := parser.GetCommandType(test.command)
			if result != test.expectedType {
				t.Errorf("Expected type '%s' for command '%s', got '%s'",
					test.expectedType, test.command, result)
			}
		})
	}
}

func TestFPR4100_9300Parser_SupportedCommands(t *testing.T) {
	parser := NewFPR4100_9300Parser()
	commands := parser.SupportedCommands()

	if len(commands) == 0 {
		t.Error("Expected some supported commands")
	}

	// Verify essential commands are supported
	essentialCommands := []string{
		"show version",
		"show app-instance",
		"show tech-support detail",
		"show processes",
		"show software authenticity running",
		"verify /sha-512 system:memory/text",
	}

	commandMap := make(map[string]bool)
	for _, cmd := range commands {
		commandMap[cmd] = true
	}

	for _, essential := range essentialCommands {
		if !commandMap[essential] {
			t.Errorf("Essential command '%s' not found in supported commands", essential)
		}
	}
}

func TestFPR4100_9300Parser_ParseCommand(t *testing.T) {
	parser := NewFPR4100_9300Parser()

	testCases := []struct {
		name     string
		command  string
		output   string
		expected string // Expected type or content
	}{
		{
			name:     "version",
			command:  "show version",
			output:   "Firepower Extensible Operating System (FXOS) Version 2.13.1.135",
			expected: "DeviceInfo",
		},
		{
			name:     "tech_support",
			command:  "show tech-support detail",
			output:   "Tech support output...",
			expected: "map",
		},
		{
			name:     "processes",
			command:  "show processes",
			output:   "PID COMMAND\n1 init",
			expected: "[]Process",
		},
		{
			name:     "authenticity",
			command:  "show software authenticity running",
			output:   "MANAGER IMAGE\n=============",
			expected: "map",
		},
		{
			name:     "memory_hash",
			command:  "verify /sha-512 system:memory/text",
			output:   "verify /SHA-512 (system:memory/text) = abc123",
			expected: "map",
		},
		{
			name:     "unsupported",
			command:  "unsupported command",
			output:   "some output",
			expected: "raw",
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			result, err := parser.ParseCommand(test.command, test.output)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result == nil {
				t.Fatal("Expected non-nil result")
			}

			// Basic type checking
			switch test.expected {
			case "DeviceInfo":
				if _, ok := result.(*core.DeviceInfo); !ok {
					t.Errorf("Expected *core.DeviceInfo, got %T", result)
				}
			case "[]Process":
				if _, ok := result.([]core.Process); !ok {
					t.Errorf("Expected []core.Process, got %T", result)
				}
			case "map":
				if _, ok := result.(map[string]interface{}); !ok {
					t.Errorf("Expected map[string]interface{}, got %T", result)
				}
			case "raw":
				if rawMap, ok := result.(map[string]string); ok {
					if rawMap["raw_output"] != test.output {
						t.Errorf("Expected raw output to match input")
					}
				} else {
					t.Errorf("Expected map[string]string for raw output, got %T", result)
				}
			}
		})
	}
}
