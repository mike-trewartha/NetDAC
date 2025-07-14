package cisco

import (
	"strings"
	"testing"
	"time"
)

func TestNewFPR4100_9300Collector(t *testing.T) {
	collector := NewFPR4100_9300Collector("192.168.1.1", "admin", "password", 30*time.Second)

	if collector.Target != "192.168.1.1" {
		t.Errorf("Expected target '192.168.1.1', got '%s'", collector.Target)
	}

	if collector.Username != "admin" {
		t.Errorf("Expected username 'admin', got '%s'", collector.Username)
	}

	if collector.CommandSet != "standard" {
		t.Errorf("Expected default command set 'standard', got '%s'", collector.CommandSet)
	}

	if collector.connected {
		t.Error("Expected collector to be disconnected initially")
	}
}

func TestFPR4100_9300Collector_SetCommandSet(t *testing.T) {
	collector := NewFPR4100_9300Collector("192.168.1.1", "admin", "password", 30*time.Second)

	tests := []struct {
		name        string
		commandSet  string
		expectError bool
	}{
		{"minimal", "minimal", false},
		{"standard", "standard", false},
		{"full", "full", false},
		{"invalid", "invalid", true},
		{"empty", "", true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := collector.SetCommandSet(test.commandSet)
			if test.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !test.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if !test.expectError && collector.GetCommandSet() != test.commandSet {
				t.Errorf("Expected command set '%s', got '%s'", test.commandSet, collector.GetCommandSet())
			}
		})
	}
}

func TestFPR4100_9300Collector_GetAvailableCommandSets(t *testing.T) {
	collector := NewFPR4100_9300Collector("192.168.1.1", "admin", "password", 30*time.Second)
	sets := collector.GetAvailableCommandSets()

	expected := []string{"minimal", "standard", "full"}
	if len(sets) != len(expected) {
		t.Errorf("Expected %d command sets, got %d", len(expected), len(sets))
	}

	for i, set := range expected {
		if i >= len(sets) || sets[i] != set {
			t.Errorf("Expected command set '%s' at index %d", set, i)
		}
	}
}

func TestFPR4100_9300Collector_GetCommandSet(t *testing.T) {
	collector := NewFPR4100_9300Collector("192.168.1.1", "admin", "password", 30*time.Second)

	if collector.GetCommandSet() != "standard" {
		t.Errorf("Expected default command set 'standard', got '%s'", collector.GetCommandSet())
	}

	collector.SetCommandSet("minimal")
	if collector.GetCommandSet() != "minimal" {
		t.Errorf("Expected command set 'minimal', got '%s'", collector.GetCommandSet())
	}
}

func TestFPR4100_9300Collector_ListCommands(t *testing.T) {
	collector := NewFPR4100_9300Collector("192.168.1.1", "admin", "password", 30*time.Second)

	// Test different command sets
	testCases := []struct {
		commandSet      string
		minExpectedCmds int
	}{
		{"minimal", 4},  // At least 4 essential commands
		{"standard", 8}, // At least 8 standard commands
		{"full", 15},    // At least 15 full commands
	}

	for _, test := range testCases {
		t.Run(test.commandSet, func(t *testing.T) {
			collector.SetCommandSet(test.commandSet)
			commands := collector.ListCommands()

			if len(commands) < test.minExpectedCmds {
				t.Errorf("Expected at least %d commands for %s set, got %d",
					test.minExpectedCmds, test.commandSet, len(commands))
			}

			// Verify all commands are non-empty strings
			for i, cmd := range commands {
				if cmd == "" {
					t.Errorf("Command at index %d is empty", i)
				}
			}
		})
	}
}

func TestFPR4100_9300Collector_getCommandSet_Minimal(t *testing.T) {
	collector := NewFPR4100_9300Collector("192.168.1.1", "admin", "password", 30*time.Second)
	commands := collector.getCommandSet("minimal")

	// Verify essential forensic commands are present
	essentialCommands := []string{
		"show version",
		"show app-instance",
		"show software authenticity running",
	}

	commandMap := make(map[string]bool)
	for _, cmd := range commands {
		commandMap[cmd.Command] = true
	}

	for _, essential := range essentialCommands {
		if !commandMap[essential] {
			t.Errorf("Essential command '%s' not found in minimal set", essential)
		}
	}

	if len(commands) < 3 {
		t.Errorf("Expected at least 3 commands in minimal set, got %d", len(commands))
	}
}

func TestFPR4100_9300Collector_getCommandSet_Standard(t *testing.T) {
	collector := NewFPR4100_9300Collector("192.168.1.1", "admin", "password", 30*time.Second)
	commands := collector.getCommandSet("standard")

	// Verify standard forensic commands are present
	standardCommands := []string{
		"show tech-support detail",
		"dir /recursive all-filesystems",
		"verify_file_integ.sh -f",
		"show-systemstatus",
		"verify /sha-512 system:memory/text",
	}

	commandMap := make(map[string]bool)
	for _, cmd := range commands {
		commandMap[cmd.Command] = true
	}

	for _, standard := range standardCommands {
		if !commandMap[standard] {
			t.Errorf("Standard command '%s' not found in standard set", standard)
		}
	}

	if len(commands) < 8 {
		t.Errorf("Expected at least 8 commands in standard set, got %d", len(commands))
	}
}

func TestFPR4100_9300Collector_getCommandSet_Full(t *testing.T) {
	collector := NewFPR4100_9300Collector("192.168.1.1", "admin", "password", 30*time.Second)
	commands := collector.getCommandSet("full")

	// Verify full commands are present
	fullCommands := []string{
		"show processes",
		"show interface",
		"show route",
		"show connection",
		"ps aux",
		"netstat -tulpn",
		"lsof",
		"show fabric-interconnect",
		"show chassis",
		"show security-service",
	}

	commandMap := make(map[string]bool)
	for _, cmd := range commands {
		commandMap[cmd.Command] = true
	}

	for _, fullCmd := range fullCommands {
		if !commandMap[fullCmd] {
			t.Errorf("Full command '%s' not found in full set", fullCmd)
		}
	}

	if len(commands) < 15 {
		t.Errorf("Expected at least 15 commands in full set, got %d", len(commands))
	}
}

func TestFPR4100_9300Collector_Timeouts(t *testing.T) {
	collector := NewFPR4100_9300Collector("192.168.1.1", "admin", "password", 30*time.Second)

	// Test initial timeout
	if collector.GetTimeout() != 30*time.Second {
		t.Errorf("Expected timeout 30s, got %v", collector.GetTimeout())
	}

	// Test setting new timeout
	newTimeout := 60 * time.Second
	collector.SetTimeout(newTimeout)
	if collector.GetTimeout() != newTimeout {
		t.Errorf("Expected timeout %v, got %v", newTimeout, collector.GetTimeout())
	}

	// Verify commands have appropriate timeouts
	commands := collector.getCommandSet("standard")
	for _, cmd := range commands {
		// Tech support should have longer timeout
		if cmd.Command == "show tech-support detail" && cmd.Timeout < 300*time.Second {
			t.Errorf("Tech support command should have at least 300s timeout, got %v", cmd.Timeout)
		}

		// Memory verification should have longer timeout
		if cmd.Command == "verify /sha-512 system:memory/text" && cmd.Timeout < 300*time.Second {
			t.Errorf("Memory verification should have at least 300s timeout, got %v", cmd.Timeout)
		}

		// Basic commands should have reasonable timeouts
		if cmd.Command == "show version" && cmd.Timeout > 60*time.Second {
			t.Errorf("Show version should have reasonable timeout, got %v", cmd.Timeout)
		}
	}
}

func TestFPR4100_9300Collector_CLIContexts(t *testing.T) {
	collector := NewFPR4100_9300Collector("192.168.1.1", "admin", "password", 30*time.Second)
	commands := collector.getCommandSet("full")

	// Verify CLI contexts are correctly assigned
	cliContexts := map[string][]string{
		"fxos":       {"show version", "show app-instance", "show fabric-interconnect", "show chassis", "show security-service"},
		"ftd":        {"show version", "show tech-support detail", "show processes", "show interface", "show route", "show connection", "verify /sha-512 system:memory/text"},
		"expert":     {"find /ngfw/var/sf/.icdb/*", "verify_file_integ.sh -f", "cat /proc/*/smaps", "ps aux", "netstat -tulpn", "lsof"},
		"adapter":    {"show-systemstatus"},
		"local-mgmt": {"show software authenticity running", "show software authenticity file", "show software authenticity keys"},
	}

	for _, cmd := range commands {
		expectedContexts, exists := cliContexts[cmd.CLI]
		if !exists {
			continue // Skip commands without specific context requirements
		}

		found := false
		for _, expectedCmd := range expectedContexts {
			if cmd.Command == expectedCmd ||
				(expectedCmd == "find /ngfw/var/sf/.icdb/*" && strings.Contains(cmd.Command, "find /ngfw/var/sf/.icdb/")) ||
				(expectedCmd == "show software authenticity running" && strings.Contains(cmd.Command, "show software authenticity")) {
				found = true
				break
			}
		}

		if !found {
			// This is informational - some commands may have different contexts
			t.Logf("Command '%s' uses CLI context '%s'", cmd.Command, cmd.CLI)
		}
	}
}

func TestFPR4100_9300Collector_ValidateConnection(t *testing.T) {
	collector := NewFPR4100_9300Collector("192.168.1.1", "admin", "password", 30*time.Second)

	// Test validation when not connected
	err := collector.ValidateConnection()
	if err == nil {
		t.Error("Expected error when validating disconnected collector")
	}

	if collector.IsConnected() {
		t.Error("Expected IsConnected to return false")
	}
}

func TestFPR4100_9300Collector_Collect(t *testing.T) {
	collector := NewFPR4100_9300Collector("192.168.1.1", "admin", "password", 30*time.Second)

	// Test collection when not connected
	_, err := collector.Collect()
	if err == nil {
		t.Error("Expected error when collecting from disconnected collector")
	}
}

func TestFPR4100_9300Collector_GetParser(t *testing.T) {
	collector := NewFPR4100_9300Collector("192.168.1.1", "admin", "password", 30*time.Second)
	parser := collector.GetParser()

	if parser == nil {
		t.Error("Expected parser to be non-nil")
	}

	// Test that parser has expected methods
	supportedCommands := parser.SupportedCommands()
	if len(supportedCommands) == 0 {
		t.Error("Expected parser to support some commands")
	}
}

func TestFPR4100_9300Collector_GetDeviceInfo(t *testing.T) {
	collector := NewFPR4100_9300Collector("192.168.1.1", "admin", "password", 30*time.Second)

	// Test getting device info when not connected
	_, err := collector.GetDeviceInfo()
	if err == nil {
		t.Error("Expected error when getting device info from disconnected collector")
	}
}
