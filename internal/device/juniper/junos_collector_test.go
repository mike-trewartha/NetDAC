package juniper

import (
	"strings"
	"testing"
	"time"
)

func TestJunOSCollector_Creation(t *testing.T) {
	collector := NewJunOSCollector("192.168.1.1", "admin", "password", 30*time.Second)

	if collector == nil {
		t.Error("Expected collector to be created")
	}

	if collector.Target != "192.168.1.1" {
		t.Errorf("Expected target '192.168.1.1', got '%s'", collector.Target)
	}

	if collector.Username != "admin" {
		t.Errorf("Expected username 'admin', got '%s'", collector.Username)
	}

	if collector.Password != "password" {
		t.Errorf("Expected password 'password', got '%s'", collector.Password)
	}

	if collector.Timeout != 30*time.Second {
		t.Errorf("Expected timeout 30s, got %v", collector.Timeout)
	}

	if collector.parser == nil {
		t.Error("Expected parser to be initialized")
	}

	if collector.connected {
		t.Error("Expected collector to start disconnected")
	}
}

func TestJunOSCollector_SetSSHKey(t *testing.T) {
	collector := NewJunOSCollector("192.168.1.1", "admin", "password", 30*time.Second)

	testKey := []byte("test-ssh-key-data")
	collector.SetSSHKey(testKey)

	if len(collector.SSHKey) != len(testKey) {
		t.Errorf("Expected SSH key length %d, got %d", len(testKey), len(collector.SSHKey))
	}

	for i, b := range testKey {
		if collector.SSHKey[i] != b {
			t.Errorf("SSH key mismatch at position %d", i)
		}
	}
}

func TestJunOSCollector_SetSkipHostKeyVerification(t *testing.T) {
	collector := NewJunOSCollector("192.168.1.1", "admin", "password", 30*time.Second)

	// Test setting to true
	collector.SetSkipHostKeyVerification(true)
	if !collector.SkipHostKeyVerification {
		t.Error("Expected SkipHostKeyVerification to be true")
	}

	// Test setting to false
	collector.SetSkipHostKeyVerification(false)
	if collector.SkipHostKeyVerification {
		t.Error("Expected SkipHostKeyVerification to be false")
	}
}

func TestJunOSCollector_CommandSets(t *testing.T) {
	collector := NewJunOSCollector("192.168.1.1", "admin", "password", 30*time.Second)

	// Test minimal command set
	collector.CommandSet = "minimal"
	minimalCommands := collector.getCommandSet()
	if len(minimalCommands) == 0 {
		t.Error("Expected minimal command set to have commands")
	}

	// Test standard command set
	collector.CommandSet = "standard"
	standardCommands := collector.getCommandSet()
	if len(standardCommands) <= len(minimalCommands) {
		t.Error("Expected standard command set to have more commands than minimal")
	}

	// Test full command set
	collector.CommandSet = "full"
	fullCommands := collector.getCommandSet()
	if len(fullCommands) <= len(standardCommands) {
		t.Error("Expected full command set to have more commands than standard")
	}

	// Test default command set (should be standard)
	collector.CommandSet = ""
	defaultCommands := collector.getCommandSet()
	if len(defaultCommands) != len(standardCommands) {
		t.Error("Expected default command set to be standard")
	}
}

func TestJunOSCollector_MinimalCommandSet(t *testing.T) {
	collector := NewJunOSCollector("192.168.1.1", "admin", "password", 30*time.Second)
	commands := collector.getMinimalCommandSet()

	expectedCommands := []string{
		"show version",
		"show system hostname",
		"show chassis hardware",
		"show system processes",
		"show interfaces terse",
		"show route summary",
		"show system users",
		"show system uptime",
	}

	if len(commands) != len(expectedCommands) {
		t.Errorf("Expected %d commands, got %d", len(expectedCommands), len(commands))
	}

	// Check that critical commands are marked correctly
	criticalFound := false
	for _, cmd := range commands {
		if cmd.Command == "show version" && cmd.Critical {
			criticalFound = true
		}
		if cmd.Timeout == 0 {
			t.Errorf("Command '%s' has zero timeout", cmd.Command)
		}
		if cmd.Context == "" {
			t.Errorf("Command '%s' has empty context", cmd.Command)
		}
	}

	if !criticalFound {
		t.Error("Expected 'show version' to be marked as critical")
	}
}

func TestJunOSCollector_StandardCommandSet(t *testing.T) {
	collector := NewJunOSCollector("192.168.1.1", "admin", "password", 30*time.Second)
	commands := collector.getStandardCommandSet()

	// Should include minimal commands plus additional ones
	minimalCommands := collector.getMinimalCommandSet()
	if len(commands) <= len(minimalCommands) {
		t.Error("Standard command set should be larger than minimal")
	}

	// Check for some expected additional commands
	commandMap := make(map[string]bool)
	for _, cmd := range commands {
		commandMap[cmd.Command] = true
	}

	expectedAdditional := []string{
		"show security policies",
		"show security zones",
		"show configuration | display set",
		"show system storage",
		"show system memory",
	}

	for _, expectedCmd := range expectedAdditional {
		if !commandMap[expectedCmd] {
			t.Errorf("Expected command '%s' not found in standard set", expectedCmd)
		}
	}
}

func TestJunOSCollector_FullCommandSet(t *testing.T) {
	collector := NewJunOSCollector("192.168.1.1", "admin", "password", 30*time.Second)
	commands := collector.getFullCommandSet()

	// Should be the largest command set
	standardCommands := collector.getStandardCommandSet()
	if len(commands) <= len(standardCommands) {
		t.Error("Full command set should be larger than standard")
	}

	// Check for shell commands
	shellCommandFound := false
	for _, cmd := range commands {
		if cmd.Context == "shell" {
			shellCommandFound = true
			break
		}
	}

	if !shellCommandFound {
		t.Error("Expected at least one shell command in full command set")
	}

	// Check for advanced commands
	commandMap := make(map[string]bool)
	for _, cmd := range commands {
		commandMap[cmd.Command] = true
	}

	expectedAdvanced := []string{
		"show security ike security-associations",
		"show bgp summary",
		"show system commit",
		"ps aux",
		"netstat -an",
	}

	for _, expectedCmd := range expectedAdvanced {
		if !commandMap[expectedCmd] {
			t.Errorf("Expected advanced command '%s' not found in full set", expectedCmd)
		}
	}
}

func TestJunOSCollector_ContextTypes(t *testing.T) {
	collector := NewJunOSCollector("192.168.1.1", "admin", "password", 30*time.Second)
	commands := collector.getFullCommandSet()

	contexts := make(map[string]int)
	for _, cmd := range commands {
		contexts[cmd.Context]++
	}

	if contexts["cli"] == 0 {
		t.Error("Expected at least one CLI command")
	}

	if contexts["shell"] == 0 {
		t.Error("Expected at least one shell command")
	}

	// Check that contexts are valid
	for context := range contexts {
		if context != "cli" && context != "shell" && context != "both" {
			t.Errorf("Invalid context type: %s", context)
		}
	}
}

func TestJunOSCollector_ExtractMethods(t *testing.T) {
	collector := NewJunOSCollector("192.168.1.1", "admin", "password", 30*time.Second)

	// Test model extraction
	chassisOutput := `Hardware inventory:
Item             Version  Part number  Serial number     Description
Chassis                                ABC123456         MX480 Base Chassis
Midplane         REV 06   750-025780   ACC234567         MX480 Backplane`

	model := collector.extractModel(chassisOutput)
	if !strings.Contains(model, "MX480") {
		t.Errorf("Expected model to contain 'MX480', got '%s'", model)
	}

	// Test serial extraction
	serial := collector.extractSerial(chassisOutput)
	if serial != "ABC123456" && serial != "ACC234567" {
		t.Errorf("Expected valid serial number, got '%s'", serial)
	}

	// Test OS version extraction
	versionOutput := `Hostname: test-router
Model: mx480
Junos: 20.2R3.8
JUNOS OS Kernel 64-bit  [20200909.075910_builder_stable_12]
JUNOS OS libs [20200909.075910_builder_stable_12]`

	osVersion := collector.extractOSVersion(versionOutput)
	if !strings.Contains(osVersion, "20.2R3.8") && !strings.Contains(osVersion, "JUNOS") {
		t.Errorf("Expected OS version to contain version info, got '%s'", osVersion)
	}

	// Test uptime extraction
	uptimeOutput := `Current time: 2024-01-15 10:30:00 UTC
Time Source:  NTP CLOCK 
Boot time: 2024-01-10 14:20:00 UTC (4d 20:10 ago)
Uptime: 4 days, 20 hours, 10 minutes, 0 seconds`

	uptime := collector.extractUptime(uptimeOutput)
	if uptime == "unknown" {
		t.Errorf("Expected to extract uptime, got '%s'", uptime)
	}
}

func TestJunOSCollector_GetSupportedCommands(t *testing.T) {
	collector := NewJunOSCollector("192.168.1.1", "admin", "password", 30*time.Second)

	// Test with different command sets
	testCases := []string{"minimal", "standard", "full"}

	for _, commandSet := range testCases {
		collector.CommandSet = commandSet
		supportedCommands := collector.GetSupportedCommands()

		if len(supportedCommands) == 0 {
			t.Errorf("Expected supported commands for %s set, got none", commandSet)
		}

		// Check that all commands are strings
		for _, cmd := range supportedCommands {
			if cmd == "" {
				t.Errorf("Found empty command in %s set", commandSet)
			}
		}
	}
}

func TestJunOSCollector_ValidateConnection(t *testing.T) {
	collector := NewJunOSCollector("192.168.1.1", "admin", "password", 30*time.Second)

	// Test validation when not connected
	err := collector.ValidateConnection()
	if err == nil {
		t.Error("Expected error when validating disconnected collector")
	}

	if collector.IsConnected() {
		t.Error("Expected IsConnected to return false")
	}
}

func TestJunOSCollector_Collect(t *testing.T) {
	collector := NewJunOSCollector("192.168.1.1", "admin", "password", 30*time.Second)

	// Test collection when not connected
	_, err := collector.Collect()
	if err == nil {
		t.Error("Expected error when collecting from disconnected collector")
	}
}

func TestJunOSCollector_GetDeviceInfo(t *testing.T) {
	collector := NewJunOSCollector("192.168.1.1", "admin", "password", 30*time.Second)

	// Test getting device info when not connected
	_, err := collector.GetDeviceInfo()
	if err == nil {
		t.Error("Expected error when getting device info from disconnected collector")
	}
}
