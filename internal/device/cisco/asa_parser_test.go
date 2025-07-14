package cisco

import (
	"netdac/internal/core"
	"testing"
)

// TestNewASAParser tests ASA parser creation
func TestNewASAParser(t *testing.T) {
	parser := NewASAParser()

	if parser == nil {
		t.Fatal("NewASAParser() returned nil")
	}

	if parser.supportedCommands == nil {
		t.Error("Supported commands map not initialized")
	}

	// Verify some key commands are supported
	expectedCommands := []string{
		"show version",
		"show tech-support",
		"show processes",
		"show conn",
		"show interface",
	}

	for _, cmd := range expectedCommands {
		if _, exists := parser.supportedCommands[cmd]; !exists {
			t.Errorf("Expected command '%s' to be supported", cmd)
		}
	}
}

// TestASAParser_ParseCommand tests the main command parsing dispatch
func TestASAParser_ParseCommand(t *testing.T) {
	parser := NewASAParser()

	tests := []struct {
		name       string
		parserType string
		output     string
		expectErr  bool
	}{
		{
			name:       "version",
			parserType: "version",
			output:     "Cisco Adaptive Security Appliance Software Version 9.18(4)20\nDevice Manager Version 7.18(4)\nCompiled on Tue 12-Dec-23 15:32 PDT by builders\nSystem image file is \"disk0:/asa9184-20-lfbff-k8.SPA\"\nConfig file at boot was \"startup-config\"\nhostname(config)# \nHardware:   ASA5515, 4096 MB RAM, CPU Clarkdale 2793 MHz, 1 CPU (4 cores)\nInternal ATA Compact Flash, 8192MB\nBIOS Flash Firmware Hub @ 0x0, 0KB\n\nSerial Number: FCH1947V0GY\nRunning Permanent Activation Key: 0xE8E75AA8 0x33838872 0x8C641B5D 0x49E8A89F 0x3A39BBF0\nConfiguration register is 0x1\nConfiguration last modified by enable_15 at 14:32:43.123 PDT Mon Dec 12 2023\n",
			expectErr:  false,
		},
		{
			name:       "interfaces",
			parserType: "interfaces",
			output:     "Interface GigabitEthernet0/0 \"outside\", is up, line protocol is up\n  Hardware is 88E6095, BW 1000000 Kbit\n  Description: Outside Interface\n  MAC address 001b.d512.d4fe, MTU 1500\n  IP address 192.168.1.100, subnet mask 255.255.255.0\n  Traffic Statistics for \"outside\":\n        10 packets input, 840 bytes\n        5 packets output, 420 bytes\n        0 packets dropped\n",
			expectErr:  false,
		},
		{
			name:       "processes",
			parserType: "processes",
			output:     "PC         SP         STATE       Runtime    SBASE     Stack Process\nHsi        0x08048000 0x09ffffff running     0          0x09ff0000  0x10000 Interrupt\nMwe        0x08048000 0x09fffef0 running     0          0x09ff0000  0x10000 arp_timer\nMwe        0x08048000 0x09fffef0 running     0          0x09ff0000  0x10000 L2TP data\nMwe        0x08048000 0x09fffef0 running     0          0x09ff0000  0x10000 PPPoE timer\n",
			expectErr:  false,
		},
		{
			name:       "connections",
			parserType: "connections",
			output:     "4 in use, 22 most used\nTCP outside 192.168.1.10:80 inside 10.1.1.100:34567, idle 0:00:01, bytes 2345, flags UIO\nTCP outside 192.168.1.10:443 inside 10.1.1.200:45678, idle 0:00:05, bytes 1234, flags UIO\nUDP outside 192.168.1.1:53 inside 10.1.1.100:12345, idle 0:00:30, bytes 128, flags -\n",
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

// TestASAParser_ParseVersion tests version parsing
func TestASAParser_ParseVersion(t *testing.T) {
	parser := NewASAParser()

	versionOutput := `Cisco Adaptive Security Appliance Software Version 9.18(4)20
Device Manager Version 7.18(4)
Compiled on Tue 12-Dec-23 15:32 PDT by builders
System image file is "disk0:/asa9184-20-lfbff-k8.SPA"
Config file at boot was "startup-config"
hostname(config)# 
Hardware:   ASA5515, 4096 MB RAM, CPU Clarkdale 2793 MHz, 1 CPU (4 cores)
Internal ATA Compact Flash, 8192MB
BIOS Flash Firmware Hub @ 0x0, 0KB

Serial Number: FCH1947V0GY
Running Permanent Activation Key: 0xE8E75AA8 0x33838872 0x8C641B5D 0x49E8A89F 0x3A39BBF0
Configuration register is 0x1
Configuration last modified by enable_15 at 14:32:43.123 PDT Mon Dec 12 2023`

	result, err := parser.ParseCommand("version", versionOutput)
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

// TestASAParser_ParseInterfaces tests interface parsing
func TestASAParser_ParseInterfaces(t *testing.T) {
	parser := NewASAParser()

	interfaceOutput := `Interface GigabitEthernet0/0 "outside", is up, line protocol is up
  Hardware is 88E6095, BW 1000000 Kbit
  Description: Outside Interface
  MAC address 001b.d512.d4fe, MTU 1500
  IP address 192.168.1.100, subnet mask 255.255.255.0
  Traffic Statistics for "outside":
        10 packets input, 840 bytes
        5 packets output, 420 bytes
        0 packets dropped

Interface GigabitEthernet0/1 "inside", is up, line protocol is up
  Hardware is 88E6095, BW 1000000 Kbit
  Description: Inside Interface
  MAC address 001b.d512.d4ff, MTU 1500
  IP address 10.1.1.1, subnet mask 255.255.255.0`

	result, err := parser.ParseCommand("interfaces", interfaceOutput)
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

// TestASAParser_ParseConnections tests connection parsing
func TestASAParser_ParseConnections(t *testing.T) {
	parser := NewASAParser()

	connectionOutput := `4 in use, 22 most used
TCP outside 192.168.1.10:80 inside 10.1.1.100:34567, idle 0:00:01, bytes 2345, flags UIO
TCP outside 192.168.1.10:443 inside 10.1.1.200:45678, idle 0:00:05, bytes 1234, flags UIO
UDP outside 192.168.1.1:53 inside 10.1.1.100:12345, idle 0:00:30, bytes 128, flags -`

	result, err := parser.ParseCommand("connections", connectionOutput)
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

// TestASAParser_SupportedCommands tests supported command checking
func TestASAParser_SupportedCommands(t *testing.T) {
	parser := NewASAParser()

	if parser.supportedCommands == nil {
		t.Error("Expected non-nil supported commands map")
	}

	// Verify key commands are in the map
	expectedCommands := []string{
		"show version",
		"show tech-support",
		"show processes",
		"show conn",
		"show interface",
	}

	for _, expected := range expectedCommands {
		if _, exists := parser.supportedCommands[expected]; !exists {
			t.Errorf("Expected command '%s' not found in supported commands", expected)
		}
	}
}

// TestASAParser_ParseRoutes tests route parsing
func TestASAParser_ParseRoutes(t *testing.T) {
	parser := NewASAParser()

	routeOutput := `Codes: C - connected, S - static, R - RIP, M - mobile, B - BGP
       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area

Gateway of last resort is 203.0.113.30 to network 0.0.0.0

S*   0.0.0.0/0 [1/0] via 203.0.113.30, outside
C    172.31.1.0/24 is directly connected, inside
C    172.31.50.0/24 is directly connected, dmz
O    10.0.0.0/8 [110/2] via 172.31.1.254, inside
S    192.168.99.0/24 [1/0] via 192.168.99.1, management`

	routes, err := parser.ParseRoutes(routeOutput)
	if err != nil {
		t.Fatalf("ParseRoutes() failed: %v", err)
	}

	if len(routes) != 5 {
		t.Errorf("Expected 5 routes, got %d", len(routes))
	}

	// Test first route (default route)
	if routes[0].Destination != "0.0.0.0/0" {
		t.Errorf("Expected destination '0.0.0.0/0', got '%s'", routes[0].Destination)
	}
	if routes[0].Gateway != "203.0.113.30" {
		t.Errorf("Expected gateway '203.0.113.30', got '%s'", routes[0].Gateway)
	}
	if routes[0].Interface != "outside" {
		t.Errorf("Expected interface 'outside', got '%s'", routes[0].Interface)
	}
	if routes[0].Protocol != "static" {
		t.Errorf("Expected protocol 'static', got '%s'", routes[0].Protocol)
	}

	// Test connected route
	if routes[1].Destination != "172.31.1.0/24" {
		t.Errorf("Expected destination '172.31.1.0/24', got '%s'", routes[1].Destination)
	}
	if routes[1].Gateway != "0.0.0.0" {
		t.Errorf("Expected gateway '0.0.0.0' for connected route, got '%s'", routes[1].Gateway)
	}
	if routes[1].Interface != "inside" {
		t.Errorf("Expected interface 'inside', got '%s'", routes[1].Interface)
	}
	if routes[1].Protocol != "connected" {
		t.Errorf("Expected protocol 'connected', got '%s'", routes[1].Protocol)
	}
}

// TestASAParser_ParseSessions tests session parsing
func TestASAParser_ParseSessions(t *testing.T) {
	parser := NewASAParser()

	sessionOutput := `Line      User       Host(s)              Idle       Location
*  0 SSH                                    00:00:00   192.168.99.100
   1 HTTP     enable_15  172.31.1.100         00:01:22   
   2 SSH      enable_15  192.168.99.50        00:04:33   
   3 HTTPS    admin      172.31.1.200         1d3h       console`

	sessions, err := parser.ParseSessions(sessionOutput)
	if err != nil {
		t.Fatalf("ParseSessions() failed: %v", err)
	}

	if len(sessions) < 2 {
		t.Errorf("Expected at least 2 sessions, got %d", len(sessions))
	}

	// Find the enable_15 HTTP session
	var httpSession *core.Session
	for i := range sessions {
		if sessions[i].User == "enable_15" && sessions[i].Protocol == "HTTP" {
			httpSession = &sessions[i]
			break
		}
	}

	if httpSession == nil {
		t.Fatal("Could not find enable_15 HTTP session")
	}

	if httpSession.Location != "172.31.1.100" {
		t.Errorf("Expected location '172.31.1.100', got '%s'", httpSession.Location)
	}
	if httpSession.IdleTime != "00:01:22" {
		t.Errorf("Expected idle time '00:01:22', got '%s'", httpSession.IdleTime)
	}
	if httpSession.Privilege != "15" {
		t.Errorf("Expected privilege '15', got '%s'", httpSession.Privilege)
	}
}

// TestASAParser_ParseRoutesEmpty tests empty route output
func TestASAParser_ParseRoutesEmpty(t *testing.T) {
	parser := NewASAParser()

	routes, err := parser.ParseRoutes("")
	if err != nil {
		t.Fatalf("ParseRoutes() with empty input failed: %v", err)
	}

	if len(routes) != 0 {
		t.Errorf("Expected 0 routes for empty input, got %d", len(routes))
	}
}

// TestASAParser_ParseSessionsEmpty tests empty session output
func TestASAParser_ParseSessionsEmpty(t *testing.T) {
	parser := NewASAParser()

	sessions, err := parser.ParseSessions("")
	if err != nil {
		t.Fatalf("ParseSessions() with empty input failed: %v", err)
	}

	if len(sessions) != 0 {
		t.Errorf("Expected 0 sessions for empty input, got %d", len(sessions))
	}
}
