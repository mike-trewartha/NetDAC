package cisco

import (
	"testing"
	"time"
)

func TestNewWLCIOSXECollector(t *testing.T) {
	collector := NewWLCIOSXECollector("192.168.1.1", "admin", "password", 30*time.Second)

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

	if collector.CommandSet != "standard" {
		t.Errorf("Expected default command set 'standard', got '%s'", collector.CommandSet)
	}

	if collector.parser == nil {
		t.Error("Expected parser to be initialized")
	}

	if collector.connected {
		t.Error("Expected connected to be false initially")
	}
}

func TestWLCIOSXECollector_SetCommandSet(t *testing.T) {
	collector := NewWLCIOSXECollector("192.168.1.1", "admin", "password", 30*time.Second)

	tests := []struct {
		name     string
		cmdSet   string
		wantErr  bool
		expected string
	}{
		{"minimal", "minimal", false, "minimal"},
		{"standard", "standard", false, "standard"},
		{"full", "full", false, "full"},
		{"invalid", "invalid", true, "standard"},
		{"empty", "", false, "standard"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := collector.SetCommandSet(tt.cmdSet)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetCommandSet() error = %v, wantErr %v", err, tt.wantErr)
			}
			if collector.GetCommandSet() != tt.expected {
				t.Errorf("Expected command set '%s', got '%s'", tt.expected, collector.GetCommandSet())
			}
		})
	}
}

func TestWLCIOSXECollector_GetAvailableCommandSets(t *testing.T) {
	collector := NewWLCIOSXECollector("192.168.1.1", "admin", "password", 30*time.Second)

	sets := collector.GetAvailableCommandSets()
	expected := []string{"minimal", "standard", "full"}

	if len(sets) != len(expected) {
		t.Errorf("Expected %d command sets, got %d", len(expected), len(sets))
	}

	for i, expectedSet := range expected {
		if sets[i] != expectedSet {
			t.Errorf("Expected command set '%s' at index %d, got '%s'", expectedSet, i, sets[i])
		}
	}
}

func TestWLCIOSXECollector_GetCommandSet(t *testing.T) {
	collector := NewWLCIOSXECollector("192.168.1.1", "admin", "password", 30*time.Second)

	if collector.GetCommandSet() != "standard" {
		t.Errorf("Expected default command set 'standard', got '%s'", collector.GetCommandSet())
	}

	collector.SetCommandSet("minimal")
	if collector.GetCommandSet() != "minimal" {
		t.Errorf("Expected command set 'minimal', got '%s'", collector.GetCommandSet())
	}
}

func TestWLCIOSXECollector_ListCommands(t *testing.T) {
	collector := NewWLCIOSXECollector("192.168.1.1", "admin", "password", 30*time.Second)

	tests := []struct {
		name          string
		commandSet    string
		expectedCount int
		shouldContain []string
	}{
		{
			name:          "minimal",
			commandSet:    "minimal",
			expectedCount: 4,
			shouldContain: []string{"show version", "show tech-support", "show software authenticity running"},
		},
		{
			name:          "standard",
			commandSet:    "standard",
			expectedCount: 18, // minimal + 14 additional
			shouldContain: []string{"show version", "show tech-support wireless", "verify bootflash:packages.conf"},
		},
		{
			name:          "full",
			commandSet:    "full",
			expectedCount: 43, // standard + 25 additional
			shouldContain: []string{"show wireless summary", "show ap summary", "show platform hardware"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector.SetCommandSet(tt.commandSet)
			commands := collector.ListCommands()

			if len(commands) != tt.expectedCount {
				t.Errorf("Expected %d commands for %s set, got %d", tt.expectedCount, tt.commandSet, len(commands))
			}

			for _, expectedCmd := range tt.shouldContain {
				found := false
				for _, cmd := range commands {
					if cmd == expectedCmd {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected command '%s' not found in %s set", expectedCmd, tt.commandSet)
				}
			}
		})
	}
}

func TestWLCIOSXECollector_getCommandSet_Minimal(t *testing.T) {
	collector := NewWLCIOSXECollector("192.168.1.1", "admin", "password", 30*time.Second)
	commands := collector.getCommandSet("minimal")

	expectedCommands := []string{
		"show version",
		"show tech-support",
		"show version | inc System image",
		"show software authenticity running",
	}

	if len(commands) != len(expectedCommands) {
		t.Errorf("Expected %d commands, got %d", len(expectedCommands), len(commands))
	}

	for i, expected := range expectedCommands {
		if commands[i].Command != expected {
			t.Errorf("Expected command '%s' at index %d, got '%s'", expected, i, commands[i].Command)
		}
	}
}

func TestWLCIOSXECollector_getCommandSet_Standard(t *testing.T) {
	collector := NewWLCIOSXECollector("192.168.1.1", "admin", "password", 30*time.Second)
	commands := collector.getCommandSet("standard")

	// Should include minimal + standard commands
	if len(commands) < 4 { // At least the minimal commands
		t.Errorf("Expected at least 4 commands, got %d", len(commands))
	}

	// Check for standard-specific commands
	standardCommands := []string{
		"show tech-support wireless",
		"show tech-support diagnostic",
		"dir /recursive all-filesystems",
		"show platform software process memory chassis active r0 name iosd smaps",
		"verify bootflash:packages.conf",
	}

	commandList := make([]string, len(commands))
	for i, cmd := range commands {
		commandList[i] = cmd.Command
	}

	for _, expectedCmd := range standardCommands {
		found := false
		for _, cmd := range commandList {
			if cmd == expectedCmd {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected standard command '%s' not found", expectedCmd)
		}
	}
}

func TestWLCIOSXECollector_getCommandSet_Full(t *testing.T) {
	collector := NewWLCIOSXECollector("192.168.1.1", "admin", "password", 30*time.Second)
	commands := collector.getCommandSet("full")

	// Should include standard + full commands
	if len(commands) < 18 { // At least the standard commands
		t.Errorf("Expected at least 18 commands, got %d", len(commands))
	}

	// Check for full-specific commands
	fullCommands := []string{
		"show wireless summary",
		"show ap summary",
		"show wireless client summary",
		"show platform hardware",
		"show crypto pki certificates",
		"show logging",
	}

	commandList := make([]string, len(commands))
	for i, cmd := range commands {
		commandList[i] = cmd.Command
	}

	for _, expectedCmd := range fullCommands {
		found := false
		for _, cmd := range commandList {
			if cmd == expectedCmd {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected full command '%s' not found", expectedCmd)
		}
	}
}

func TestWLCIOSXECollector_Timeouts(t *testing.T) {
	collector := NewWLCIOSXECollector("192.168.1.1", "admin", "password", 30*time.Second)

	if collector.GetTimeout() != 30*time.Second {
		t.Errorf("Expected timeout 30s, got %v", collector.GetTimeout())
	}

	collector.SetTimeout(60 * time.Second)
	if collector.GetTimeout() != 60*time.Second {
		t.Errorf("Expected timeout 60s, got %v", collector.GetTimeout())
	}
}

func TestWLCIOSXECollector_CommandTimeouts(t *testing.T) {
	collector := NewWLCIOSXECollector("192.168.1.1", "admin", "password", 30*time.Second)
	commands := collector.getCommandSet("standard")

	// Verify that certain commands have appropriate timeouts
	timeoutTests := []struct {
		command string
		timeout time.Duration
	}{
		{"show version", 30 * time.Second},
		{"show tech-support", 300 * time.Second},
		{"show tech-support wireless", 300 * time.Second},
		{"show platform software process memory chassis active r0 name iosd smaps", 300 * time.Second},
		{"request platform software trace archive", 180 * time.Second},
	}

	for _, tt := range timeoutTests {
		found := false
		for _, cmd := range commands {
			if cmd.Command == tt.command {
				found = true
				if cmd.Timeout != tt.timeout {
					t.Errorf("Expected timeout %v for command '%s', got %v", tt.timeout, tt.command, cmd.Timeout)
				}
				break
			}
		}
		if !found {
			t.Errorf("Command '%s' not found in command set", tt.command)
		}
	}
}

func TestWLCIOSXECollector_ValidateConnection(t *testing.T) {
	collector := NewWLCIOSXECollector("192.168.1.1", "admin", "password", 30*time.Second)

	// Should fail when not connected
	err := collector.ValidateConnection()
	if err == nil {
		t.Error("Expected error when not connected")
	}

	if collector.IsConnected() {
		t.Error("Expected IsConnected to return false")
	}
}

func TestWLCIOSXECollector_Collect(t *testing.T) {
	collector := NewWLCIOSXECollector("192.168.1.1", "admin", "password", 30*time.Second)

	// Should fail when not connected
	_, err := collector.Collect()
	if err == nil {
		t.Error("Expected error when not connected")
	}
}

func TestWLCIOSXECollector_GetParser(t *testing.T) {
	collector := NewWLCIOSXECollector("192.168.1.1", "admin", "password", 30*time.Second)

	parser := collector.GetParser()
	if parser == nil {
		t.Error("Expected parser to be non-nil")
	}

	if parser != collector.parser {
		t.Error("Expected parser to be the same instance")
	}
}

func TestWLCIOSXECollector_GetDeviceInfo(t *testing.T) {
	collector := NewWLCIOSXECollector("192.168.1.1", "admin", "password", 30*time.Second)

	// Should fail when not connected
	_, err := collector.GetDeviceInfo()
	if err == nil {
		t.Error("Expected error when not connected")
	}
}
