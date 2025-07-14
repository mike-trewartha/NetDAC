package cisco

import (
	"testing"
)

// TestNewNXOSParser tests NXOS parser creation
func TestNewNXOSParser(t *testing.T) {
	parser := NewNXOSParser()

	if parser == nil {
		t.Fatal("NewNXOSParser() returned nil")
	}

	// Test that parser has the SupportedCommands method
	commands := parser.SupportedCommands()
	if len(commands) == 0 {
		t.Error("Expected non-empty supported commands list")
	}
}

// TestNXOSParser_ParseCommand tests the main command parsing dispatch
func TestNXOSParser_ParseCommand(t *testing.T) {
	parser := NewNXOSParser()

	tests := []struct {
		name       string
		parserType string
		output     string
		expectErr  bool
	}{
		{
			name:       "version",
			parserType: "version",
			output:     "Cisco Nexus Operating System (NX-OS) Software\nTAC support: http://www.cisco.com/tac\nDocuments: http://www.cisco.com/go/nexus9000docs\nCopyright (c) 2002-2019, Cisco Systems, Inc. All rights reserved.\nThe copyrights to certain works contained herein are owned by\nother third parties and are used and distributed under license.\nSome parts of this software are covered under the GNU Public\nLicense. A copy of the license is available at\nhttp://www.gnu.org/licenses/gpl.html.\n\nNexus 9000v is a demo version of the Cisco Nexus Operating System\n\nSoftware\n  BIOS: version \n  NXOS: version 9.3(5) [build 9.3(5)] [feature set F3]\n  BIOS compile time:  \n  NXOS image file is: bootflash:///nxos.9.3.5.bin\n  NXOS compile time:  10/14/2019 12:00:00 [10/14/2019 17:13:50]\n\n\nHardware\n  cisco Nexus9000 C9300v Chassis\n  Intel(R) Xeon(R) Gold 6148 CPU @ 2.40GHz with 8154996 kB of memory.\n  Processor Board ID 9SM8CHX70H5\n",
			expectErr:  false,
		},
		{
			name:       "interfaces",
			parserType: "interfaces",
			output:     "Ethernet1/1 is up\n admin state is up, Dedicated Interface\n  Hardware: 1000/10000 Ethernet, address: 5254.001a.f1aa (bia 5254.001a.f1aa)\n  Description: to spine1\n  MTU 1500 bytes, BW 10000000 Kbit, DLY 10 usec\n  reliability 255/255, txload 1/255, rxload 1/255\n  Encapsulation ARPA, medium is broadcast\n  Port mode is access\n  full-duplex, 10 Gb/s, media type is 10G\n  Beacon is turned off\n  Auto-Negotiation is turned on, FEC mode is Auto\n  Input flow-control is off, output flow-control is off\n  Auto-mdix is turned off\n",
			expectErr:  false,
		},
		{
			name:       "unsupported_command",
			parserType: "unknown_command",
			output:     "some output",
			expectErr:  false, // Returns raw output map, no error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parser.ParseCommand(tt.parserType, tt.output)

			if (err != nil) != tt.expectErr {
				t.Errorf("ParseCommand() error = %v, expectErr %v", err, tt.expectErr)
				return
			}

			if result == nil {
				t.Errorf("ParseCommand() returned nil result")
			}
		})
	}
}

// TestNXOSParser_SupportedCommands tests supported command checking
func TestNXOSParser_SupportedCommands(t *testing.T) {
	parser := NewNXOSParser()

	commands := parser.SupportedCommands()
	if len(commands) == 0 {
		t.Error("Expected non-empty supported commands list")
	}

	// Verify key commands are in the list
	expectedCommands := []string{
		"show version",
		"show tech-support details",
		"show interfaces",
		"show processes",
	}

	commandSet := make(map[string]bool)
	for _, cmd := range commands {
		commandSet[cmd] = true
	}

	for _, expected := range expectedCommands {
		if !commandSet[expected] {
			t.Errorf("Expected command '%s' not found in supported commands", expected)
		}
	}
}
