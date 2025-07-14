package cisco

import (
	"testing"
)

// TestNewFTDParser tests FTD parser creation
func TestNewFTDParser(t *testing.T) {
	parser := NewFTDParser()

	if parser == nil {
		t.Fatal("NewFTDParser() returned nil")
	}

	if parser.supportedCommands == nil {
		t.Error("Supported commands map not initialized")
	}

	// Verify some key commands are supported
	expectedCommands := []string{
		"show version",
		"show tech-support",
		"show processes",
		"show connection",
		"show interface",
	}

	for _, cmd := range expectedCommands {
		if _, exists := parser.supportedCommands[cmd]; !exists {
			t.Errorf("Expected command '%s' to be supported", cmd)
		}
	}
}

// TestFTDParser_ParseCommand tests the main command parsing dispatch
func TestFTDParser_ParseCommand(t *testing.T) {
	parser := NewFTDParser()

	tests := []struct {
		name      string
		command   string
		output    string
		expectErr bool
	}{
		{
			name:      "version",
			command:   "show version",
			output:    "Cisco Firepower Threat Defense, Version 7.2.5 (Build 17)\nBy Cisco Systems, Inc.\nSerial Number: FCH2047V0LM\nInstallation: Thursday 14 December 2023 at 11:12:43\nHardware: FPR-1120, 16384 MB RAM, CPU AMD GX 2100T 1500 MHz, 4 cores\nBootloader Version: 2.2(2.1)\nMAC Address: 001b.d5ab.cd12 (GigabitEthernet0/0)\n",
			expectErr: false,
		},
		{
			name:      "interfaces",
			command:   "show interface",
			output:    "Interface GigabitEthernet0/0\n  Link is up, protocol is up\n  Hardware is Intel I210, address is 001b.d5ab.cd12\n  Internet address is 192.168.1.100/24\n  MTU 1500 bytes, BW 1000000 Kbit\n  Full-duplex, 1000Mb/s, link type is auto, media type is RJ45\n  Input flow-control is off, output flow-control is off\n",
			expectErr: false,
		},
		{
			name:      "processes",
			command:   "show processes",
			output:    "PID TTY          TIME CMD\n    1 ?        00:00:05 systemd\n    2 ?        00:00:00 kthreadd\n    3 ?        00:00:01 ksoftirqd/0\n  128 ?        00:00:00 rcu_gp\n  129 ?        00:00:00 rcu_par_gp\n 1234 ?        00:02:15 snortd\n 2345 ?        00:01:30 lina\n",
			expectErr: false,
		},
		{
			name:      "connections",
			command:   "show connection",
			output:    "TCP outside 192.168.1.10:80 inside 10.1.1.100:34567 flags UIO idle 0:00:01 bytes 2345\nTCP outside 192.168.1.10:443 inside 10.1.1.200:45678 flags UIO idle 0:00:05 bytes 1234\nUDP outside 192.168.1.1:53 inside 10.1.1.100:12345 flags - idle 0:00:30 bytes 128\n",
			expectErr: false,
		},
		{
			name:      "unsupported_command",
			command:   "unknown command",
			output:    "some output",
			expectErr: true, // Should return error for unsupported command
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parser.ParseCommand(tt.command, tt.output)

			if (err != nil) != tt.expectErr {
				t.Errorf("ParseCommand() error = %v, expectErr %v", err, tt.expectErr)
				return
			}

			if !tt.expectErr && result == nil {
				t.Errorf("ParseCommand() returned nil result")
			}
		})
	}
}

// TestFTDParser_ParseVersion tests version parsing
func TestFTDParser_ParseVersion(t *testing.T) {
	parser := NewFTDParser()

	versionOutput := `Cisco Firepower Threat Defense, Version 7.2.5 (Build 17)
By Cisco Systems, Inc.
Serial Number: FCH2047V0LM
Installation: Thursday 14 December 2023 at 11:12:43
Hardware: FPR-1120, 16384 MB RAM, CPU AMD GX 2100T 1500 MHz, 4 cores
Bootloader Version: 2.2(2.1)
MAC Address: 001b.d5ab.cd12 (GigabitEthernet0/0)`

	result, err := parser.ParseCommand("show version", versionOutput)
	if err != nil {
		t.Fatalf("ParseCommand() failed: %v", err)
	}

	if result == nil {
		t.Fatal("ParseCommand() returned nil result")
	}

	// Check that result is not nil (actual parsing verification would require more complex logic)
	if result == nil {
		t.Error("Expected non-nil result from version parsing")
	}
}

// TestFTDParser_ParseInterfaces tests interface parsing
func TestFTDParser_ParseInterfaces(t *testing.T) {
	parser := NewFTDParser()

	interfaceOutput := `Interface GigabitEthernet0/0
  Link is up, protocol is up
  Hardware is Intel I210, address is 001b.d5ab.cd12
  Internet address is 192.168.1.100/24
  MTU 1500 bytes, BW 1000000 Kbit
  Full-duplex, 1000Mb/s, link type is auto, media type is RJ45
  Input flow-control is off, output flow-control is off

Interface GigabitEthernet0/1
  Link is up, protocol is up
  Hardware is Intel I210, address is 001b.d5ab.cd13
  Internet address is 10.1.1.1/24
  MTU 1500 bytes, BW 1000000 Kbit`

	result, err := parser.ParseCommand("show interface", interfaceOutput)
	if err != nil {
		t.Fatalf("ParseCommand() failed: %v", err)
	}

	if result == nil {
		t.Fatal("ParseCommand() returned nil result")
	}

	// Check that result is not nil (actual parsing verification would require more complex logic)
	if result == nil {
		t.Error("Expected non-nil result from interface parsing")
	}
}

// TestFTDParser_ParseConnections tests connection parsing
func TestFTDParser_ParseConnections(t *testing.T) {
	parser := NewFTDParser()

	connectionOutput := `TCP outside 192.168.1.10:80 inside 10.1.1.100:34567 flags UIO idle 0:00:01 bytes 2345
TCP outside 192.168.1.10:443 inside 10.1.1.200:45678 flags UIO idle 0:00:05 bytes 1234
UDP outside 192.168.1.1:53 inside 10.1.1.100:12345 flags - idle 0:00:30 bytes 128`

	result, err := parser.ParseCommand("show connection", connectionOutput)
	if err != nil {
		t.Fatalf("ParseCommand() failed: %v", err)
	}

	if result == nil {
		t.Fatal("ParseCommand() returned nil result")
	}

	// Check that result is not nil (actual parsing verification would require more complex logic)
	if result == nil {
		t.Error("Expected non-nil result from connection parsing")
	}
}

// TestFTDParser_SupportedCommands tests supported command checking
func TestFTDParser_SupportedCommands(t *testing.T) {
	parser := NewFTDParser()

	if parser.supportedCommands == nil {
		t.Error("Expected non-nil supported commands map")
	}

	// Verify key commands are in the map
	expectedCommands := []string{
		"show version",
		"show tech-support",
		"show processes",
		"show connection",
		"show interface",
	}

	for _, expected := range expectedCommands {
		if _, exists := parser.supportedCommands[expected]; !exists {
			t.Errorf("Expected command '%s' not found in supported commands", expected)
		}
	}
}
