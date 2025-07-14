package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netdac/internal/core"
)

func TestNewJSONFormatter(t *testing.T) {
	tests := []struct {
		name        string
		prettyPrint bool
		includeRaw  bool
	}{
		{
			name:        "Default values",
			prettyPrint: false,
			includeRaw:  false,
		},
		{
			name:        "Pretty print enabled",
			prettyPrint: true,
			includeRaw:  false,
		},
		{
			name:        "Include raw enabled",
			prettyPrint: false,
			includeRaw:  true,
		},
		{
			name:        "Both enabled",
			prettyPrint: true,
			includeRaw:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			formatter := NewJSONFormatter(tt.prettyPrint, tt.includeRaw)

			if formatter.PrettyPrint != tt.prettyPrint {
				t.Errorf("Expected PrettyPrint %v, got %v", tt.prettyPrint, formatter.PrettyPrint)
			}

			if formatter.IncludeRaw != tt.includeRaw {
				t.Errorf("Expected IncludeRaw %v, got %v", tt.includeRaw, formatter.IncludeRaw)
			}
		})
	}
}

func TestJSONFormatter_Format(t *testing.T) {
	deviceState := createTestDeviceStateJSON()

	tests := []struct {
		name        string
		prettyPrint bool
		includeRaw  bool
		expectError bool
		checkFunc   func(string) bool
	}{
		{
			name:        "All data pretty print",
			prettyPrint: true,
			includeRaw:  false,
			expectError: false,
			checkFunc: func(output string) bool {
				return strings.Contains(output, "test-device") &&
					strings.Contains(output, "interfaces") &&
					strings.Contains(output, "routes") &&
					strings.Contains(output, "\n") // Pretty print should have newlines
			},
		},
		{
			name:        "All data compact",
			prettyPrint: false,
			includeRaw:  false,
			expectError: false,
			checkFunc: func(output string) bool {
				return strings.Contains(output, "test-device") &&
					!strings.Contains(output, "\n  ") // No indentation
			},
		},
		{
			name:        "Include raw commands",
			prettyPrint: true,
			includeRaw:  true,
			expectError: false,
			checkFunc: func(output string) bool {
				return strings.Contains(output, "test-device") &&
					strings.Contains(output, "raw_commands")
			},
		},
		{
			name:        "Exclude raw commands",
			prettyPrint: true,
			includeRaw:  false,
			expectError: false,
			checkFunc: func(output string) bool {
				return strings.Contains(output, "test-device") &&
					!strings.Contains(output, "raw_commands")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			formatter := NewJSONFormatter(tt.prettyPrint, tt.includeRaw)
			var buf bytes.Buffer

			err := formatter.Format(deviceState, &buf)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			output := buf.String()

			// Verify it's valid JSON
			var jsonData interface{}
			if err := json.Unmarshal([]byte(output), &jsonData); err != nil {
				t.Errorf("Output is not valid JSON: %v", err)
				t.Logf("Output: %s", output)
				return
			}

			if tt.checkFunc != nil && !tt.checkFunc(output) {
				t.Errorf("Output validation failed")
				t.Logf("Output: %s", output)
			}
		})
	}
}

func TestJSONFormatter_WriteToFile(t *testing.T) {
	deviceState := createTestDeviceStateJSON()
	formatter := NewJSONFormatter(true, false)

	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "netdac_json_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testFile := filepath.Join(tempDir, "test_output.json")

	// Test writing to file
	err = formatter.WriteToFile(deviceState, testFile)
	if err != nil {
		t.Fatalf("Failed to write to file: %v", err)
	}

	// Verify file exists and has valid JSON content
	content, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}

	if len(content) == 0 {
		t.Error("File is empty")
	}

	// Verify it's valid JSON
	var jsonData interface{}
	if err := json.Unmarshal(content, &jsonData); err != nil {
		t.Errorf("File content is not valid JSON: %v", err)
	}
}

func TestJSONFormatter_PrettyPrint(t *testing.T) {
	deviceState := createTestDeviceStateJSON()

	tests := []struct {
		name        string
		prettyPrint bool
		checkFunc   func(string) bool
	}{
		{
			name:        "Pretty print enabled",
			prettyPrint: true,
			checkFunc: func(output string) bool {
				return strings.Contains(output, "\n") && strings.Contains(output, "  ")
			},
		},
		{
			name:        "Pretty print disabled",
			prettyPrint: false,
			checkFunc: func(output string) bool {
				return !strings.Contains(output, "\n  ") // No indented newlines
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			formatter := NewJSONFormatter(tt.prettyPrint, false)
			var buf bytes.Buffer

			err := formatter.Format(deviceState, &buf)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			output := buf.String()
			if !tt.checkFunc(output) {
				t.Errorf("Pretty print validation failed")
				t.Logf("Output: %s", output)
			}
		})
	}
}

func TestJSONFormatter_RawCommands(t *testing.T) {
	deviceState := createTestDeviceStateJSON()
	// Add some raw commands for testing
	deviceState.RawCommands = []core.RawCommand{
		{
			Command:   "show version",
			Output:    "IOS Version output...",
			Timestamp: time.Now(),
			ExitCode:  0,
			Duration:  "1.2s",
		},
		{
			Command:   "show interfaces",
			Output:    "Interface details...",
			Timestamp: time.Now(),
			ExitCode:  0,
			Duration:  "0.8s",
		},
	}

	tests := []struct {
		name       string
		includeRaw bool
		checkFunc  func(string) bool
	}{
		{
			name:       "Include raw commands",
			includeRaw: true,
			checkFunc: func(output string) bool {
				return strings.Contains(output, "raw_commands") &&
					strings.Contains(output, "show version") &&
					strings.Contains(output, "IOS Version output")
			},
		},
		{
			name:       "Exclude raw commands",
			includeRaw: false,
			checkFunc: func(output string) bool {
				return !strings.Contains(output, "raw_commands")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			formatter := NewJSONFormatter(true, tt.includeRaw)
			var buf bytes.Buffer

			err := formatter.Format(deviceState, &buf)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			output := buf.String()
			if !tt.checkFunc(output) {
				t.Errorf("Raw commands validation failed")
				t.Logf("Output: %s", output)
			}
		})
	}
}

func TestJSONFormatter_EmptyData(t *testing.T) {
	// Test with empty device state
	emptyState := &core.DeviceState{
		DeviceInfo: core.DeviceInfo{
			Hostname: "empty-device",
		},
		Timestamp:   time.Now(),
		Interfaces:  []core.Interface{},
		Routes:      []core.Route{},
		Processes:   []core.Process{},
		Sessions:    []core.Session{},
		Connections: []core.Connection{},
		Metadata: core.CollectionMetadata{
			TotalCommands:      0,
			SuccessfulCommands: 0,
			FailedCommands:     0,
		},
	}

	formatter := NewJSONFormatter(true, false)
	var buf bytes.Buffer

	err := formatter.Format(emptyState, &buf)
	if err != nil {
		t.Errorf("Unexpected error with empty data: %v", err)
	}

	output := buf.String()

	// Should be valid JSON
	var data interface{}
	if err := json.Unmarshal([]byte(output), &data); err != nil {
		t.Errorf("Empty data output is not valid JSON: %v", err)
	}

	// Should contain the hostname
	if !strings.Contains(output, "empty-device") {
		t.Error("Expected hostname in empty device output")
	}
}

func TestJSONFormatter_JSONIndentation(t *testing.T) {
	deviceState := createTestDeviceStateJSON()
	formatter := NewJSONFormatter(true, false)

	var buf bytes.Buffer
	err := formatter.Format(deviceState, &buf)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	output := buf.String()
	lines := strings.Split(output, "\n")

	// Check that we have proper indentation
	foundIndentation := false
	for _, line := range lines {
		if strings.HasPrefix(line, "  ") && len(line) > 2 {
			foundIndentation = true
			break
		}
	}

	if !foundIndentation {
		t.Error("Expected to find proper JSON indentation in pretty print mode")
	}
}

func TestJSONFormatter_ValidJSON(t *testing.T) {
	deviceState := createTestDeviceStateJSON()

	// Test all combinations
	for _, prettyPrint := range []bool{true, false} {
		for _, includeRaw := range []bool{true, false} {
			t.Run(fmt.Sprintf("pretty_%v_raw_%v", prettyPrint, includeRaw), func(t *testing.T) {
				formatter := NewJSONFormatter(prettyPrint, includeRaw)
				var buf bytes.Buffer

				err := formatter.Format(deviceState, &buf)
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}

				output := buf.String()

				// Validate JSON
				var jsonData interface{}
				if err := json.Unmarshal([]byte(output), &jsonData); err != nil {
					t.Errorf("Invalid JSON (pretty=%v, raw=%v): %v", prettyPrint, includeRaw, err)
					t.Logf("Output: %s", output)
				}
			})
		}
	}
}

func TestJSONFormatter_SpecialCharacters(t *testing.T) {
	deviceState := createTestDeviceStateJSON()
	// Add some special characters that need to be escaped
	deviceState.DeviceInfo.Hostname = "test-device-with-\"quotes\"-and-\n-newlines"
	deviceState.Interfaces[0].Description = "Interface with special chars: \\ / \" \t \n"

	formatter := NewJSONFormatter(true, false)
	var buf bytes.Buffer

	err := formatter.Format(deviceState, &buf)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	output := buf.String()

	// Should be valid JSON despite special characters
	var jsonData interface{}
	if err := json.Unmarshal([]byte(output), &jsonData); err != nil {
		t.Errorf("JSON with special characters is not valid: %v", err)
		t.Logf("Output: %s", output)
	}
}

// Helper function to create test device state
func createTestDeviceStateJSON() *core.DeviceState {
	return &core.DeviceState{
		DeviceInfo: core.DeviceInfo{
			Hostname:     "test-device",
			IPAddress:    "192.168.1.1",
			Vendor:       "cisco",
			Model:        "ISR4321",
			Version:      "16.09.04",
			SerialNumber: "FDO12345678",
			Uptime:       "5 days, 2 hours",
		},
		Timestamp: time.Now(),
		Interfaces: []core.Interface{
			{
				Name:        "GigabitEthernet0/0/0",
				Status:      "up",
				AdminStatus: "up",
				IPAddress:   "192.168.1.1",
				SubnetMask:  "255.255.255.0",
				MACAddress:  "00:1a:2b:3c:4d:5e",
				MTU:         "1500",
				Speed:       "1000",
				Duplex:      "full",
				Description: "WAN Interface",
			},
			{
				Name:        "GigabitEthernet0/0/1",
				Status:      "down",
				AdminStatus: "down",
				IPAddress:   "",
				SubnetMask:  "",
				MACAddress:  "00:1a:2b:3c:4d:5f",
				MTU:         "1500",
				Speed:       "1000",
				Duplex:      "auto",
				Description: "Unused Interface",
			},
		},
		Routes: []core.Route{
			{
				Destination:   "0.0.0.0/0",
				Gateway:       "192.168.1.254",
				Interface:     "GigabitEthernet0/0/0",
				Metric:        "1",
				Protocol:      "static",
				AdminDistance: "1",
			},
			{
				Destination:   "192.168.1.0/24",
				Gateway:       "",
				Interface:     "GigabitEthernet0/0/0",
				Metric:        "0",
				Protocol:      "connected",
				AdminDistance: "0",
			},
		},
		Processes: []core.Process{
			{
				PID:         "1",
				Name:        "init",
				CPU:         "0.0",
				Memory:      "1024",
				Runtime:     "5d2h",
				State:       "running",
				Priority:    "20",
				CommandLine: "/sbin/init",
			},
			{
				PID:         "1234",
				Name:        "sshd",
				CPU:         "0.1",
				Memory:      "2048",
				Runtime:     "1h30m",
				State:       "running",
				Priority:    "20",
				CommandLine: "/usr/sbin/sshd -D",
			},
		},
		Sessions: []core.Session{
			{
				User:      "admin",
				Line:      "vty 0",
				Location:  "192.168.1.100",
				IdleTime:  "00:05:23",
				LoginTime: "09:30:15",
				Protocol:  "ssh",
			},
		},
		Connections: []core.Connection{
			{
				Protocol:      "TCP",
				LocalAddress:  "192.168.1.1",
				LocalPort:     "22",
				RemoteAddress: "192.168.1.100",
				RemotePort:    "54321",
				State:         "ESTABLISHED",
				PID:           "1234",
				Process:       "sshd",
			},
		},
		Metadata: core.CollectionMetadata{
			TotalCommands:      12,
			SuccessfulCommands: 11,
			FailedCommands:     1,
			CollectionDuration: "35.2s",
			Errors:             []string{"Command 'show invalid' failed"},
		},
		RawCommands: []core.RawCommand{
			{
				Command:   "show version",
				Output:    "Cisco IOS XE Software...",
				Timestamp: time.Now(),
				ExitCode:  0,
				Duration:  "1.5s",
			},
			{
				Command:   "show interfaces",
				Output:    "GigabitEthernet0/0/0 is up...",
				Timestamp: time.Now(),
				ExitCode:  0,
				Duration:  "0.9s",
			},
		},
	}
}

// Benchmark tests
func BenchmarkJSONFormatter_AllData(b *testing.B) {
	deviceState := createTestDeviceStateJSON()
	formatter := NewJSONFormatter(false, false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		formatter.Format(deviceState, &buf)
	}
}

func BenchmarkJSONFormatter_PrettyPrint(b *testing.B) {
	deviceState := createTestDeviceStateJSON()
	formatter := NewJSONFormatter(true, false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		formatter.Format(deviceState, &buf)
	}
}

func BenchmarkJSONFormatter_WithRaw(b *testing.B) {
	deviceState := createTestDeviceStateJSON()
	formatter := NewJSONFormatter(false, true)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		formatter.Format(deviceState, &buf)
	}
}
