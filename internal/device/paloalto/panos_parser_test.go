package paloalto

import (
	"testing"
)

// TestNewPANOSParser tests PANOS parser creation
func TestNewPANOSParser(t *testing.T) {
	parser := NewPANOSParser()

	if parser == nil {
		t.Fatal("NewPANOSParser() returned nil")
	}

	// Test that parser has the SupportedCommands method
	commands := parser.SupportedCommands()
	if len(commands) == 0 {
		t.Error("Expected non-empty supported commands list")
	}
}

// TestPANOSParser_ParseCommand tests the main command parsing dispatch
func TestPANOSParser_ParseCommand(t *testing.T) {
	parser := NewPANOSParser()

	tests := []struct {
		name       string
		parserType string
		output     string
		expectErr  bool
	}{
		{
			name:       "system_info",
			parserType: "system_info",
			output:     "hostname: PA-VM\nip-address: 192.168.1.100\nnetmask: 255.255.255.0\ndefault-gateway: 192.168.1.1\nis-dhcp: no\nipv6-address: unknown\nipv6-link-local-address: fe80::250:56ff:fe8f:18e5/64\nipv6-default-gateway: \nmac-address: 00:50:56:8f:18:e5\ntime: Wed Dec  6 14:30:45 PST 2023\nuptime: 15 days, 2:45:30\nfamily: vm\nmodel: PA-VM\nserial: 015351000012345\nsw-version: 10.2.0\nglobal-protect-client-package-version: 0.0.0\napp-version: 8543-6870\napp-release-date: 2023/11/21  15:30:45 PST\nav-version: 4104-4565\nav-release-date: 2023/11/20  01:02:03 PST\nthreat-version: 8543-6870\nthreat-release-date: 2023/11/21  15:30:45 PST\nwf-private-version: 0\nwf-private-release-date: unknown\nurl-db: paloaltonetworks\nwildfire-version: 0\nwildfire-release-date: \nwildfire-rt: Disabled\nglobal-protect-datafile-version: unknown\nglobal-protect-datafile-release-date: unknown\nglobal-protect-clientless-vpn-version: 0\nlogdb-version: 10.2.0\nplatform-family: vm\nvpn-disable-mode: off\nmulti-vsys: off\noperational-mode: normal\n",
			expectErr:  false,
		},
		{
			name:       "interfaces",
			parserType: "interfaces",
			output:     "ethernet1/1      up    up      1000/full/up  00:50:56:8f:18:e5\nethernet1/2      up    up      1000/full/up  00:50:56:8f:18:e6\nethernet1/3      down  down    auto/auto/down 00:50:56:8f:18:e7\nloopback         up    N/A     N/A           N/A\ntunnel           up    N/A     N/A           N/A\nvlan             up    N/A     N/A           N/A\n",
			expectErr:  false,
		},
		{
			name:       "sessions",
			parserType: "sessions",
			output:     "ID      Application    State   Type Flag  Src Zone    Dst Zone    Protocol    Src IP          Dst IP          Src Port  Dst Port  NAT Src IP      NAT Dst IP      NAT Src Port  NAT Dst Port\n12345   web-browsing   ACTIVE  FLOW 0     trust       untrust     6           192.168.1.10    203.0.113.1     45678     80        192.168.1.100   203.0.113.1     45678         80\n12346   ssl            ACTIVE  FLOW 0     trust       untrust     6           192.168.1.20    203.0.113.2     54321     443       192.168.1.100   203.0.113.2     54321         443\n",
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

// TestPANOSParser_SupportedCommands tests supported command checking
func TestPANOSParser_SupportedCommands(t *testing.T) {
	parser := NewPANOSParser()

	commands := parser.SupportedCommands()
	if len(commands) == 0 {
		t.Error("Expected non-empty supported commands list")
	}

	// Verify key commands are in the list
	expectedCommands := []string{
		"system_info",
		"interfaces",
		"all_sessions",
		"system_logs",
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
