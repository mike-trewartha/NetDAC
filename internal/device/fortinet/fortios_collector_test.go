package fortinet

import (
	"testing"
	"time"
)

// TestNewFortiOSCollector tests FortiOS collector creation
func TestNewFortiOSCollector(t *testing.T) {
	target := "192.168.1.1"
	username := "admin"
	password := "password"
	timeout := 30 * time.Second

	collector := NewFortiOSCollector(target, username, password, timeout)

	if collector == nil {
		t.Fatal("NewFortiOSCollector() returned nil")
	}

	if collector.Target != target {
		t.Errorf("Expected target '%s', got '%s'", target, collector.Target)
	}

	if collector.Username != username {
		t.Errorf("Expected username '%s', got '%s'", username, collector.Username)
	}

	if collector.Password != password {
		t.Errorf("Expected password '%s', got '%s'", password, collector.Password)
	}

	if collector.Timeout != timeout {
		t.Errorf("Expected timeout %v, got %v", timeout, collector.Timeout)
	}

	if collector.parser == nil {
		t.Error("Parser not initialized")
	}

	if collector.connected {
		t.Error("Expected collector to start disconnected")
	}
}

// TestFortiOSCollector_CommandSet tests command set configuration
func TestFortiOSCollector_CommandSet(t *testing.T) {
	collector := NewFortiOSCollector("192.168.1.1", "admin", "password", 30*time.Second)

	testCases := []struct {
		name       string
		commandSet string
	}{
		{
			name:       "minimal_command_set",
			commandSet: "minimal",
		},
		{
			name:       "standard_command_set",
			commandSet: "standard",
		},
		{
			name:       "full_command_set",
			commandSet: "full",
		},
		{
			name:       "default_command_set",
			commandSet: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			collector.CommandSet = tc.commandSet

			// Test that getCommandSet returns appropriate commands
			commands := collector.getCommandSet()

			if len(commands) == 0 {
				t.Error("getCommandSet() returned empty command list")
			}

			// Verify all commands have required fields
			for i, cmd := range commands {
				if cmd.Command == "" {
					t.Errorf("Command %d has empty Command field", i)
				}
				if cmd.Parser == "" {
					t.Errorf("Command %d has empty Parser field", i)
				}
				if cmd.Description == "" {
					t.Errorf("Command %d has empty Description field", i)
				}
				if cmd.Timeout == 0 {
					t.Errorf("Command %d has zero Timeout", i)
				}
			}
		})
	}
}

// TestFortiOSCollector_GetSupportedCommands tests supported commands listing
func TestFortiOSCollector_GetSupportedCommands(t *testing.T) {
	collector := NewFortiOSCollector("192.168.1.1", "admin", "password", 30*time.Second)

	commands := collector.GetSupportedCommands()

	if len(commands) == 0 {
		t.Error("GetSupportedCommands() returned empty list")
	}

	// Verify some expected commands are present
	expectedCommands := []string{
		"get system status",
		"get system interface",
		"get router info routing-table all",
	}

	commandsMap := make(map[string]bool)
	for _, cmd := range commands {
		commandsMap[cmd] = true
	}

	for _, expected := range expectedCommands {
		if !commandsMap[expected] {
			t.Errorf("Expected command '%s' not found in supported commands", expected)
		}
	}
}

// TestFortiOSCollector_ValidateConnection tests connection validation
func TestFortiOSCollector_ValidateConnection(t *testing.T) {
	collector := NewFortiOSCollector("192.168.1.1", "admin", "password", 30*time.Second)

	// This should fail since we're not actually connected
	err := collector.ValidateConnection()
	if err == nil {
		t.Error("Expected ValidateConnection() to fail when not connected")
	}
}

// TestFortiOSCollector_ConnectionState tests connection state management
func TestFortiOSCollector_ConnectionState(t *testing.T) {
	collector := NewFortiOSCollector("192.168.1.1", "admin", "password", 30*time.Second)

	// Initially should not be connected
	if collector.connected {
		t.Error("Expected collector to start disconnected")
	}

	// Note: We don't test actual connection here as it requires a real device
	// These tests focus on the state management logic
}

// TestFortiOSCollector_Timeout tests timeout configuration
func TestFortiOSCollector_Timeout(t *testing.T) {
	testCases := []struct {
		name    string
		timeout time.Duration
	}{
		{
			name:    "short_timeout",
			timeout: 10 * time.Second,
		},
		{
			name:    "standard_timeout",
			timeout: 30 * time.Second,
		},
		{
			name:    "long_timeout",
			timeout: 60 * time.Second,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			collector := NewFortiOSCollector("192.168.1.1", "admin", "password", tc.timeout)

			if collector.Timeout != tc.timeout {
				t.Errorf("Expected timeout %v, got %v", tc.timeout, collector.Timeout)
			}
		})
	}
}

// TestFortiOSCollector_MinimalCommandSet tests minimal command set
func TestFortiOSCollector_MinimalCommandSet(t *testing.T) {
	collector := NewFortiOSCollector("192.168.1.1", "admin", "password", 30*time.Second)

	commands := collector.getMinimalCommandSet()

	if len(commands) == 0 {
		t.Error("getMinimalCommandSet() returned empty list")
	}

	// Should have at least basic system commands
	foundSystemStatus := false
	for _, cmd := range commands {
		if cmd.Parser == "system_status" {
			foundSystemStatus = true
			break
		}
	}

	if !foundSystemStatus {
		t.Error("Minimal command set should include system_status")
	}
}

// TestFortiOSCollector_StandardCommandSet tests standard command set
func TestFortiOSCollector_StandardCommandSet(t *testing.T) {
	collector := NewFortiOSCollector("192.168.1.1", "admin", "password", 30*time.Second)

	commands := collector.getStandardCommandSet()

	if len(commands) == 0 {
		t.Error("getStandardCommandSet() returned empty list")
	}

	// Should have more commands than minimal
	minimalCommands := collector.getMinimalCommandSet()
	if len(commands) <= len(minimalCommands) {
		t.Error("Standard command set should have more commands than minimal")
	}
}

// TestFortiOSCollector_FullCommandSet tests full command set
func TestFortiOSCollector_FullCommandSet(t *testing.T) {
	collector := NewFortiOSCollector("192.168.1.1", "admin", "password", 30*time.Second)

	commands := collector.getFullCommandSet()

	if len(commands) == 0 {
		t.Error("getFullCommandSet() returned empty list")
	}

	// Should have more commands than standard
	standardCommands := collector.getStandardCommandSet()
	if len(commands) <= len(standardCommands) {
		t.Error("Full command set should have more commands than standard")
	}
}

// TestFortiOSCollector_CommandSetSelection tests command set selection logic
func TestFortiOSCollector_CommandSetSelection(t *testing.T) {
	collector := NewFortiOSCollector("192.168.1.1", "admin", "password", 30*time.Second)

	testCases := []struct {
		name       string
		commandSet string
		expectFunc func(*FortiOSCollector) []FortiOSCommand
	}{
		{
			name:       "minimal_selection",
			commandSet: "minimal",
			expectFunc: (*FortiOSCollector).getMinimalCommandSet,
		},
		{
			name:       "standard_selection",
			commandSet: "standard",
			expectFunc: (*FortiOSCollector).getStandardCommandSet,
		},
		{
			name:       "full_selection",
			commandSet: "full",
			expectFunc: (*FortiOSCollector).getFullCommandSet,
		},
		{
			name:       "default_selection",
			commandSet: "",
			expectFunc: (*FortiOSCollector).getStandardCommandSet, // Default should be standard
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			collector.CommandSet = tc.commandSet

			actualCommands := collector.getCommandSet()
			expectedCommands := tc.expectFunc(collector)

			if len(actualCommands) != len(expectedCommands) {
				t.Errorf("Expected %d commands, got %d for command set '%s'",
					len(expectedCommands), len(actualCommands), tc.commandSet)
			}
		})
	}
}

// TestFortiOSCollector_Disconnect tests disconnection
func TestFortiOSCollector_Disconnect(t *testing.T) {
	collector := NewFortiOSCollector("192.168.1.1", "admin", "password", 30*time.Second)

	// Should handle disconnect gracefully even when not connected
	err := collector.Disconnect()
	if err != nil {
		t.Errorf("Disconnect() failed when not connected: %v", err)
	}
}

// BenchmarkFortiOSCollector_GetCommandSet benchmarks command set retrieval
func BenchmarkFortiOSCollector_GetCommandSet(b *testing.B) {
	collector := NewFortiOSCollector("192.168.1.1", "admin", "password", 30*time.Second)
	collector.CommandSet = "full"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = collector.getCommandSet()
	}
}

// BenchmarkFortiOSCollector_GetSupportedCommands benchmarks supported commands listing
func BenchmarkFortiOSCollector_GetSupportedCommands(b *testing.B) {
	collector := NewFortiOSCollector("192.168.1.1", "admin", "password", 30*time.Second)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = collector.GetSupportedCommands()
	}
}
