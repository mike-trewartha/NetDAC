package fortinet

import (
	"testing"
)

// TestFortiOSParser_ParseCommand tests the main command parsing dispatch
func TestFortiOSParser_ParseCommand(t *testing.T) {
	parser := NewFortiOSParser()

	tests := []struct {
		name       string
		parserType string
		output     string
		expectErr  bool
	}{
		{
			name:       "system_status",
			parserType: "system_status",
			output:     "Version: FortiOS v7.2.5 build1718 230628 (GA)\nBuild: 1718\nSerial Number: FG123456789\nHostname: Test-FG\n",
			expectErr:  false,
		},
		{
			name:       "interfaces",
			parserType: "interfaces",
			output:     "port1\tup\t192.168.1.1/24\twan\ninternal\tup\t10.1.1.1/24\tlan\n",
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

// TestFortiOSParser_ParseSystemStatus tests system status parsing
func TestFortiOSParser_ParseSystemStatus(t *testing.T) {
	parser := NewFortiOSParser()

	testOutput := `Version: FortiOS v7.2.5 build1718 230628 (GA)
Build: 1718
Serial Number: FG123456789
Hostname: Test-FG
Operation Mode: Transparent
Current HA Mode: Standalone, 
System Uptime: 5 days,  5 hours, 30 minutes
Memory: 3945 MB
CPU: 1 x Intel(R) Atom(TM) CPU  C3958 @ 2.00GHz (2000 MHz)`

	result, err := parser.ParseSystemStatus(testOutput)
	if err != nil {
		t.Fatalf("ParseSystemStatus() failed: %v", err)
	}

	if result == nil {
		t.Fatalf("ParseSystemStatus() returned nil")
	}

	// Verify parsed fields
	if result.Version != "FortiOS v7.2.5 build1718 230628 (GA)" {
		t.Errorf("Expected Version 'FortiOS v7.2.5 build1718 230628 (GA)', got '%s'", result.Version)
	}

	if result.Hostname != "Test-FG" {
		t.Errorf("Expected hostname 'Test-FG', got '%s'", result.Hostname)
	}

	if result.SerialNumber != "FG123456789" {
		t.Errorf("Expected serial 'FG123456789', got '%s'", result.SerialNumber)
	}
}

// TestFortiOSParser_ParseInterfaces tests interface parsing
func TestFortiOSParser_ParseInterfaces(t *testing.T) {
	parser := NewFortiOSParser()

	testOutput := `== [ port1 ]
        status: up
        ip: 192.168.1.1/24
        type: wan
== [ internal ]
        status: up
        ip: 10.1.1.1/24
        type: lan
== [ port2 ]
        status: down
        ip: -
        type: -`

	result, err := parser.ParseInterfaces(testOutput)
	if err != nil {
		t.Fatalf("ParseInterfaces() failed: %v", err)
	}

	if len(result) != 3 {
		t.Fatalf("Expected 3 interfaces, got %d", len(result))
	}

	// Test first interface
	if result[0].Name != "port1" {
		t.Errorf("Expected interface name 'port1', got '%s'", result[0].Name)
	}

	if result[0].Status != "up" {
		t.Errorf("Expected interface status 'up', got '%s'", result[0].Status)
	}

	if result[0].IPAddress != "192.168.1.1/24" {
		t.Errorf("Expected IP '192.168.1.1/24', got '%s'", result[0].IPAddress)
	}

	// Test down interface
	if result[2].Status != "down" {
		t.Errorf("Expected interface status 'down', got '%s'", result[2].Status)
	}
}

// TestFortiOSParser_ParseRoutes tests routing table parsing
func TestFortiOSParser_ParseRoutes(t *testing.T) {
	parser := NewFortiOSParser()

	testOutput := `Destination     Gateway         Interface       Distance  Priority  Uptime
0.0.0.0/0       192.168.1.254   port1          10        0         00:05:30
10.1.1.0/24     0.0.0.0         internal       0         0         00:05:30
172.16.1.0/24   0.0.0.0         dmz            0         0         00:05:30
192.168.50.0/24 10.1.1.100      internal       20        0         00:01:15`

	result, err := parser.ParseRoutes(testOutput)
	if err != nil {
		t.Fatalf("ParseRoutes() failed: %v", err)
	}

	if len(result) < 1 {
		t.Fatalf("Expected at least 1 route, got %d", len(result))
	}

	// Basic validation that routes were parsed
	found := false
	for _, route := range result {
		if route.Destination != "" {
			found = true
			break
		}
	}
	if !found {
		t.Error("No valid routes found in parsed output")
	}
}

// TestFortiOSParser_ParseSessions tests session parsing
func TestFortiOSParser_ParseSessions(t *testing.T) {
	parser := NewFortiOSParser()

	testOutput := `Session 1:
proto=tcp src=10.1.1.100:3389 dst=192.168.1.100:54321 state=ESTABLISHED
Session 2:
proto=udp src=10.1.1.50:53 dst=8.8.8.8:53 state=ESTABLISHED
Session 3:
proto=tcp src=172.16.1.200:80 dst=203.0.113.45:12345 state=ESTABLISHED`

	result, err := parser.ParseSessions(testOutput)
	if err != nil {
		t.Fatalf("ParseSessions() failed: %v", err)
	}

	if len(result) < 1 {
		t.Fatalf("Expected at least 1 session, got %d", len(result))
	}

	// Basic validation that sessions were parsed
	found := false
	for _, session := range result {
		if session.Protocol != "" {
			found = true
			break
		}
	}
	if !found {
		t.Error("No valid sessions found in parsed output")
	}
}

// TestFortiOSParser_ParseProcesses tests process parsing
func TestFortiOSParser_ParseProcesses(t *testing.T) {
	parser := NewFortiOSParser()

	testOutput := `PID   COMMAND         CPU%   MEM%
1     init            0.0    0.1
100   miglogd         0.1    0.2
200   ipsengine       5.2    3.2
300   fortigate       10.5   6.5`

	result, err := parser.ParseProcesses(testOutput)
	if err != nil {
		t.Fatalf("ParseProcesses() failed: %v", err)
	}

	if len(result) < 1 {
		t.Fatalf("Expected at least 1 process, got %d", len(result))
	}

	// Basic validation that processes were parsed
	found := false
	for _, process := range result {
		if process.PID != "" && process.Name != "" {
			found = true
			break
		}
	}
	if !found {
		t.Error("No valid processes found in parsed output")
	}
}

// TestFortiOSParser_ErrorHandling tests error handling for invalid input
func TestFortiOSParser_ErrorHandling(t *testing.T) {
	parser := NewFortiOSParser()

	tests := []struct {
		name       string
		parserType string
		output     string
		expectErr  bool
	}{
		{
			name:       "empty_system_status",
			parserType: "system_status",
			output:     "",
			expectErr:  false, // Should return empty DeviceInfo
		},
		{
			name:       "empty_interfaces",
			parserType: "interfaces",
			output:     "",
			expectErr:  false, // Should return empty slice
		},
		{
			name:       "unknown_command",
			parserType: "nonexistent",
			output:     "some output",
			expectErr:  false, // Returns raw output map
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parser.ParseCommand(tt.parserType, tt.output)

			if (err != nil) != tt.expectErr {
				t.Errorf("ParseCommand() error = %v, expectErr %v", err, tt.expectErr)
			}

			if result == nil {
				t.Errorf("ParseCommand() returned nil result")
			}
		})
	}
}

// BenchmarkFortiOSParser_ParseSystemStatus benchmarks system status parsing
func BenchmarkFortiOSParser_ParseSystemStatus(b *testing.B) {
	parser := NewFortiOSParser()
	output := `Version: FortiOS v7.2.5 build1718 230628 (GA)
Build: 1718
Serial Number: FG123456789
Hostname: Test-FG
Operation Mode: Transparent
Current HA Mode: Standalone
System Uptime: 5 days,  5 hours, 30 minutes`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := parser.ParseSystemStatus(output)
		if err != nil {
			b.Fatalf("ParseSystemStatus failed: %v", err)
		}
	}
}

// BenchmarkFortiOSParser_ParseInterfaces benchmarks interface parsing
func BenchmarkFortiOSParser_ParseInterfaces(b *testing.B) {
	parser := NewFortiOSParser()
	output := `== [ port1 ]
        status: up
        ip: 192.168.1.1/24
        type: wan
== [ internal ]
        status: up
        ip: 10.1.1.1/24
        type: lan`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := parser.ParseInterfaces(output)
		if err != nil {
			b.Fatalf("ParseInterfaces failed: %v", err)
		}
	}
}
