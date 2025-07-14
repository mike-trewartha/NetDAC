package cisco

import (
	"testing"
	"time"
)

func TestNewFXOSCollector(t *testing.T) {
	collector := NewFXOSCollector("192.168.1.1", "admin", "password", 30*time.Second)

	if collector == nil {
		t.Fatal("NewFXOSCollector() returned nil")
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

	if collector.CommandSet != "standard" {
		t.Errorf("Expected default command set 'standard', got '%s'", collector.CommandSet)
	}

	if collector.parser == nil {
		t.Error("Expected parser to be initialized")
	}

	if collector.connected != false {
		t.Error("Expected connected to be false initially")
	}
}

func TestFXOSCollector_SetCommandSet(t *testing.T) {
	collector := NewFXOSCollector("192.168.1.1", "admin", "password", 30*time.Second)

	testCases := []string{"minimal", "standard", "full"}

	for _, testCase := range testCases {
		collector.SetCommandSet(testCase)
		if collector.CommandSet != testCase {
			t.Errorf("Expected command set '%s', got '%s'", testCase, collector.CommandSet)
		}
	}
}

func TestFXOSCollector_GetAvailableCommandSets(t *testing.T) {
	collector := NewFXOSCollector("192.168.1.1", "admin", "password", 30*time.Second)

	commandSets := collector.GetAvailableCommandSets()
	expected := []string{"minimal", "standard", "full"}

	if len(commandSets) != len(expected) {
		t.Fatalf("Expected %d command sets, got %d", len(expected), len(commandSets))
	}

	for i, expectedSet := range expected {
		if commandSets[i] != expectedSet {
			t.Errorf("Expected command set '%s' at index %d, got '%s'", expectedSet, i, commandSets[i])
		}
	}
}

func TestFXOSCollector_GetCommandSet(t *testing.T) {
	collector := NewFXOSCollector("192.168.1.1", "admin", "password", 30*time.Second)

	// Test default
	if collector.GetCommandSet() != "standard" {
		t.Errorf("Expected default command set 'standard', got '%s'", collector.GetCommandSet())
	}

	// Test after setting
	collector.SetCommandSet("full")
	if collector.GetCommandSet() != "full" {
		t.Errorf("Expected command set 'full', got '%s'", collector.GetCommandSet())
	}
}

func TestFXOSCollector_ListCommands(t *testing.T) {
	collector := NewFXOSCollector("192.168.1.1", "admin", "password", 30*time.Second)

	// Test minimal command set
	collector.SetCommandSet("minimal")
	commands := collector.ListCommands()

	if len(commands) == 0 {
		t.Error("Expected some commands for minimal set, got none")
	}

	// Check that FXOS and FTD CLI contexts are indicated
	foundFXOS := false
	foundFTD := false

	for _, cmd := range commands {
		if len(cmd) > 6 && cmd[:6] == "[FXOS]" {
			foundFXOS = true
		}
		if len(cmd) > 5 && cmd[:5] == "[FTD]" {
			foundFTD = true
		}
	}

	if !foundFXOS {
		t.Error("Expected to find FXOS CLI commands in minimal set")
	}

	if !foundFTD {
		t.Error("Expected to find FTD CLI commands in minimal set")
	}
}

func TestFXOSCollector_getCommandSet_Minimal(t *testing.T) {
	collector := NewFXOSCollector("192.168.1.1", "admin", "password", 30*time.Second)
	collector.SetCommandSet("minimal")

	commands := collector.getCommandSet()

	if len(commands) == 0 {
		t.Error("Expected some commands for minimal set, got none")
	}

	// Verify we have essential FXOS and FTD commands
	hasVersionFXOS := false
	hasVersionFTD := false
	hasProcesses := false

	for _, cmd := range commands {
		if cmd.Command == "show version" && cmd.CLI == "fxos" {
			hasVersionFXOS = true
		}
		if cmd.Command == "show version" && cmd.CLI == "ftd" {
			hasVersionFTD = true
		}
		if cmd.Command == "show processes" {
			hasProcesses = true
		}
	}

	if !hasVersionFXOS {
		t.Error("Expected 'show version' command for FXOS CLI in minimal set")
	}

	if !hasVersionFTD {
		t.Error("Expected 'show version' command for FTD CLI in minimal set")
	}

	if !hasProcesses {
		t.Error("Expected 'show processes' command in minimal set")
	}
}

func TestFXOSCollector_getCommandSet_Standard(t *testing.T) {
	collector := NewFXOSCollector("192.168.1.1", "admin", "password", 30*time.Second)
	collector.SetCommandSet("standard")

	commands := collector.getCommandSet()

	if len(commands) == 0 {
		t.Error("Expected some commands for standard set, got none")
	}

	// Verify we have key forensic commands
	hasTechSupportFXOS := false
	hasTechSupportFTD := false
	hasAuthRunning := false
	hasMemoryTextHash := false

	for _, cmd := range commands {
		if cmd.Command == "show tech-support fprm detail" && cmd.CLI == "fxos" {
			hasTechSupportFXOS = true
		}
		if cmd.Command == "show tech-support detail" && cmd.CLI == "ftd" {
			hasTechSupportFTD = true
		}
		if cmd.Command == "show software authenticity running" {
			hasAuthRunning = true
		}
		if cmd.Command == "verify /sha-512 system:memory/text" {
			hasMemoryTextHash = true
		}
	}

	if !hasTechSupportFXOS {
		t.Error("Expected 'show tech-support fprm detail' for FXOS in standard set")
	}

	if !hasTechSupportFTD {
		t.Error("Expected 'show tech-support detail' for FTD in standard set")
	}

	if !hasAuthRunning {
		t.Error("Expected 'show software authenticity running' in standard set")
	}

	if !hasMemoryTextHash {
		t.Error("Expected 'verify /sha-512 system:memory/text' in standard set")
	}
}

func TestFXOSCollector_getCommandSet_Full(t *testing.T) {
	collector := NewFXOSCollector("192.168.1.1", "admin", "password", 30*time.Second)
	collector.SetCommandSet("full")

	commands := collector.getCommandSet()

	if len(commands) == 0 {
		t.Error("Expected some commands for full set, got none")
	}

	// Full should have more commands than standard
	collector.SetCommandSet("standard")
	standardCommands := collector.getCommandSet()

	if len(commands) <= len(standardCommands) {
		t.Errorf("Expected full set (%d commands) to have more than standard set (%d commands)",
			len(commands), len(standardCommands))
	}

	// Verify we have additional forensic commands
	hasEnvironment := false
	hasHardware := false
	hasDirRecursive := false

	for _, cmd := range commands {
		if cmd.Command == "show environment" {
			hasEnvironment = true
		}
		if cmd.Command == "show hardware" {
			hasHardware = true
		}
		if cmd.Command == "dir /recursive all-filesystems" {
			hasDirRecursive = true
		}
	}

	if !hasEnvironment {
		t.Error("Expected 'show environment' in full set")
	}

	if !hasHardware {
		t.Error("Expected 'show hardware' in full set")
	}

	if !hasDirRecursive {
		t.Error("Expected 'dir /recursive all-filesystems' in full set")
	}
}

func TestFXOSCollector_Timeouts(t *testing.T) {
	collector := NewFXOSCollector("192.168.1.1", "admin", "password", 30*time.Second)

	commands := collector.getCommandSet()

	// Verify all commands have reasonable timeouts
	for _, cmd := range commands {
		if cmd.Timeout <= 0 {
			t.Errorf("Command '%s' has invalid timeout: %v", cmd.Command, cmd.Timeout)
		}

		if cmd.Timeout > 600*time.Second {
			t.Errorf("Command '%s' has excessive timeout: %v", cmd.Command, cmd.Timeout)
		}

		// Tech support commands should have longer timeouts
		if (cmd.Command == "show tech-support fprm detail" ||
			cmd.Command == "show tech-support detail") &&
			cmd.Timeout < 60*time.Second {
			t.Errorf("Tech support command '%s' should have longer timeout, got: %v",
				cmd.Command, cmd.Timeout)
		}
	}
}

func TestFXOSCollector_CLIContexts(t *testing.T) {
	collector := NewFXOSCollector("192.168.1.1", "admin", "password", 30*time.Second)

	commands := collector.getCommandSet()

	hasFXOSCommands := false
	hasFTDCommands := false

	for _, cmd := range commands {
		if cmd.CLI == "fxos" {
			hasFXOSCommands = true
		}
		if cmd.CLI == "ftd" {
			hasFTDCommands = true
		}

		// Validate CLI context assignments
		switch {
		case cmd.Command == "show tech-support fprm detail":
			if cmd.CLI != "fxos" {
				t.Errorf("Command '%s' should use FXOS CLI, got '%s'", cmd.Command, cmd.CLI)
			}
		case cmd.Command == "show tech-support detail":
			if cmd.CLI != "ftd" {
				t.Errorf("Command '%s' should use FTD CLI, got '%s'", cmd.Command, cmd.CLI)
			}
		case cmd.Command == "verify /sha-512 system:memory/text":
			if cmd.CLI != "ftd" {
				t.Errorf("Command '%s' should use FTD CLI, got '%s'", cmd.Command, cmd.CLI)
			}
		case cmd.Command == "show software authenticity running" && cmd.CLI == "fxos":
			// This is correct for FXOS authenticity
		case cmd.Command == "show software authenticity running" && cmd.CLI == "ftd":
			// This is also valid if it exists in FTD
		}
	}

	if !hasFXOSCommands {
		t.Error("Expected some commands to use FXOS CLI context")
	}

	if !hasFTDCommands {
		t.Error("Expected some commands to use FTD CLI context")
	}
}
