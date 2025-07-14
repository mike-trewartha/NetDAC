package paloalto

import (
	"testing"
	"time"
)

// TestNewPANOSCollector tests PANOS collector creation
func TestNewPANOSCollector(t *testing.T) {
	target := "192.168.1.1"
	username := "admin"
	password := "password"
	timeout := 30 * time.Second

	collector := NewPANOSCollector(target, username, password, timeout)

	if collector == nil {
		t.Fatal("NewPANOSCollector() returned nil")
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

// TestPANOSCollector_CommandSet tests command set configuration
func TestPANOSCollector_CommandSet(t *testing.T) {
	collector := NewPANOSCollector("192.168.1.1", "admin", "password", 30*time.Second)

	testCases := []struct {
		name       string
		commandSet string
		expected   bool
	}{
		{
			name:       "basic_set",
			commandSet: "basic",
			expected:   true,
		},
		{
			name:       "operational_set",
			commandSet: "operational",
			expected:   true,
		},
		{
			name:       "full_set",
			commandSet: "full",
			expected:   true,
		},
		{
			name:       "empty_set",
			commandSet: "",
			expected:   true, // Should default to basic
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			collector.CommandSet = tc.commandSet
			commands := collector.getCommandSet()

			if len(commands) == 0 && tc.expected {
				t.Errorf("Expected commands for set '%s', got empty set", tc.commandSet)
			}
		})
	}
}

// TestPANOSCollector_ValidateConnection tests connection validation
func TestPANOSCollector_ValidateConnection(t *testing.T) {
	collector := NewPANOSCollector("192.168.1.1", "admin", "password", 30*time.Second)

	// Test with disconnected state
	if collector.connected {
		t.Error("Expected collector to start disconnected")
	}

	// Test connection parameters validation
	if collector.Target == "" {
		t.Error("Target should not be empty")
	}

	if collector.Username == "" {
		t.Error("Username should not be empty")
	}

	if collector.Password == "" {
		t.Error("Password should not be empty")
	}

	if collector.Timeout <= 0 {
		t.Error("Timeout should be positive")
	}
}

// TestPANOSCollector_BasicCommands tests basic command set
func TestPANOSCollector_BasicCommands(t *testing.T) {
	collector := NewPANOSCollector("192.168.1.1", "admin", "password", 30*time.Second)
	collector.CommandSet = "basic"

	commands := collector.getCommandSet()

	// Basic command set should contain essential commands
	if len(commands) == 0 {
		t.Error("Basic command set should not be empty")
	}

	// Verify show system info is included (essential for device identification)
	foundSystemInfo := false
	for _, cmd := range commands {
		if cmd.Command == "show system info" {
			foundSystemInfo = true
			break
		}
	}

	if !foundSystemInfo {
		t.Error("Basic command set should include 'show system info'")
	}
}
