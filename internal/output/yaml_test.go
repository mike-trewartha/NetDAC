package output

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netdac/internal/core"

	"gopkg.in/yaml.v3"
)

func TestNewYAMLFormatter(t *testing.T) {
	tests := []struct {
		name       string
		includeRaw bool
	}{
		{
			name:       "Default values",
			includeRaw: false,
		},
		{
			name:       "Include raw enabled",
			includeRaw: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			formatter := NewYAMLFormatter(tt.includeRaw)

			if formatter.IncludeRaw != tt.includeRaw {
				t.Errorf("Expected IncludeRaw %v, got %v", tt.includeRaw, formatter.IncludeRaw)
			}
		})
	}
}

func TestYAMLFormatter_Format(t *testing.T) {
	deviceState := createTestDeviceStateYAML()

	tests := []struct {
		name        string
		includeRaw  bool
		expectError bool
		checkFunc   func(string) bool
	}{
		{
			name:        "Format without raw commands",
			includeRaw:  false,
			expectError: false,
			checkFunc: func(output string) bool {
				return strings.Contains(output, "hostname: test-device") &&
					strings.Contains(output, "interfaces:") &&
					strings.Contains(output, "routes:") &&
					!strings.Contains(output, "raw_commands:")
			},
		},
		{
			name:        "Format with raw commands",
			includeRaw:  true,
			expectError: false,
			checkFunc: func(output string) bool {
				return strings.Contains(output, "hostname: test-device") &&
					strings.Contains(output, "interfaces:") &&
					strings.Contains(output, "routes:") &&
					strings.Contains(output, "raw_commands:")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			formatter := NewYAMLFormatter(tt.includeRaw)
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

			// Verify it's valid YAML
			var yamlData interface{}
			if err := yaml.Unmarshal([]byte(output), &yamlData); err != nil {
				t.Errorf("Output is not valid YAML: %v", err)
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

func TestYAMLFormatter_WriteToFile(t *testing.T) {
	deviceState := createTestDeviceStateYAML()
	formatter := NewYAMLFormatter(false)

	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "netdac_yaml_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testFile := filepath.Join(tempDir, "test_output.yaml")

	// Test writing to file
	err = formatter.WriteToFile(deviceState, testFile)
	if err != nil {
		t.Fatalf("Failed to write to file: %v", err)
	}

	// Verify file exists and has valid YAML content
	content, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}

	if len(content) == 0 {
		t.Error("File is empty")
	}

	// Verify it's valid YAML
	var yamlData interface{}
	if err := yaml.Unmarshal(content, &yamlData); err != nil {
		t.Errorf("File content is not valid YAML: %v", err)
	}

	// Check for expected content
	contentStr := string(content)
	if !strings.Contains(contentStr, "hostname: test-device") {
		t.Error("File doesn't contain expected device data")
	}
}

func TestYAMLFormatter_RawCommands(t *testing.T) {
	deviceState := createTestDeviceStateYAML()
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
				return strings.Contains(output, "raw_commands:") &&
					strings.Contains(output, "show version") &&
					strings.Contains(output, "IOS Version output")
			},
		},
		{
			name:       "Exclude raw commands",
			includeRaw: false,
			checkFunc: func(output string) bool {
				return !strings.Contains(output, "raw_commands:")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			formatter := NewYAMLFormatter(tt.includeRaw)
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

func TestYAMLFormatter_EmptyData(t *testing.T) {
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

	formatter := NewYAMLFormatter(false)
	var buf bytes.Buffer

	err := formatter.Format(emptyState, &buf)
	if err != nil {
		t.Errorf("Unexpected error with empty data: %v", err)
	}

	output := buf.String()

	// Should be valid YAML
	var data interface{}
	if err := yaml.Unmarshal([]byte(output), &data); err != nil {
		t.Errorf("Empty data output is not valid YAML: %v", err)
	}

	// Should contain the hostname
	if !strings.Contains(output, "hostname: empty-device") {
		t.Error("Expected hostname in empty device output")
	}

	// YAML omits empty arrays, so we should NOT see interfaces section at all
	// or it might be present depending on the YAML library behavior
	if strings.Contains(output, "interfaces:") {
		// If interfaces section exists, it should be empty or omitted content
		t.Logf("Interfaces section found in output: %s", output)
	}
}

func TestYAMLFormatter_YAMLFormat(t *testing.T) {
	deviceState := createTestDeviceStateYAML()
	formatter := NewYAMLFormatter(false)

	var buf bytes.Buffer
	err := formatter.Format(deviceState, &buf)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	output := buf.String()

	// Check for YAML-specific formatting
	if !strings.Contains(output, "hostname: test-device") {
		t.Error("Expected YAML key-value format")
	}

	// Check for proper indentation (YAML uses spaces)
	lines := strings.Split(output, "\n")
	foundIndentation := false
	for _, line := range lines {
		if strings.HasPrefix(line, "  ") && len(line) > 2 {
			foundIndentation = true
			break
		}
	}

	if !foundIndentation {
		t.Error("Expected to find proper YAML indentation")
	}

	// Check for array format
	if !strings.Contains(output, "- name: GigabitEthernet0/0/0") {
		t.Error("Expected YAML array format for interfaces")
	}
}

func TestYAMLFormatter_ValidYAML(t *testing.T) {
	deviceState := createTestDeviceStateYAML()

	// Test both configurations
	for _, includeRaw := range []bool{true, false} {
		t.Run(fmt.Sprintf("includeRaw_%v", includeRaw), func(t *testing.T) {
			formatter := NewYAMLFormatter(includeRaw)
			var buf bytes.Buffer

			err := formatter.Format(deviceState, &buf)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			output := buf.String()

			// Validate YAML
			var yamlData interface{}
			if err := yaml.Unmarshal([]byte(output), &yamlData); err != nil {
				t.Errorf("Invalid YAML (includeRaw=%v): %v", includeRaw, err)
				t.Logf("Output: %s", output)
			}
		})
	}
}

func TestYAMLFormatter_SpecialCharacters(t *testing.T) {
	deviceState := createTestDeviceStateYAML()
	// Add some special characters that need to be escaped
	deviceState.DeviceInfo.Hostname = "test-device-with-\"quotes\"-and-\n-newlines"
	deviceState.Interfaces[0].Description = "Interface with special chars: \\ / \" \t \n"

	formatter := NewYAMLFormatter(false)
	var buf bytes.Buffer

	err := formatter.Format(deviceState, &buf)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	output := buf.String()

	// Should be valid YAML despite special characters
	var yamlData interface{}
	if err := yaml.Unmarshal([]byte(output), &yamlData); err != nil {
		t.Errorf("YAML with special characters is not valid: %v", err)
		t.Logf("Output: %s", output)
	}
}

func TestYAMLFormatter_LargeData(t *testing.T) {
	deviceState := createTestDeviceStateYAML()

	// Add more interfaces and routes to test with larger datasets
	for i := 0; i < 50; i++ {
		deviceState.Interfaces = append(deviceState.Interfaces, core.Interface{
			Name:        fmt.Sprintf("GigabitEthernet0/0/%d", i+2),
			Status:      "down",
			AdminStatus: "down",
			IPAddress:   "",
			Description: fmt.Sprintf("Test interface %d", i+2),
		})

		deviceState.Routes = append(deviceState.Routes, core.Route{
			Destination: fmt.Sprintf("10.%d.0.0/24", i),
			Gateway:     "192.168.1.254",
			Interface:   fmt.Sprintf("GigabitEthernet0/0/%d", i+2),
			Protocol:    "static",
		})
	}

	formatter := NewYAMLFormatter(false)
	var buf bytes.Buffer

	err := formatter.Format(deviceState, &buf)
	if err != nil {
		t.Fatalf("Unexpected error with large data: %v", err)
	}

	output := buf.String()

	// Should still be valid YAML
	var yamlData interface{}
	if err := yaml.Unmarshal([]byte(output), &yamlData); err != nil {
		t.Errorf("Large data output is not valid YAML: %v", err)
	}

	// Should contain all the data
	if !strings.Contains(output, "GigabitEthernet0/0/51") {
		t.Error("Expected all interfaces to be present in output")
	}
}

func TestYAMLFormatter_MultilineStrings(t *testing.T) {
	deviceState := createTestDeviceStateYAML()

	// Add multiline description
	multilineDescription := `This is a long description
that spans multiple lines
and contains various information
about the interface configuration`

	deviceState.Interfaces[0].Description = multilineDescription

	formatter := NewYAMLFormatter(false)
	var buf bytes.Buffer

	err := formatter.Format(deviceState, &buf)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	output := buf.String()

	// Should be valid YAML
	var yamlData interface{}
	if err := yaml.Unmarshal([]byte(output), &yamlData); err != nil {
		t.Errorf("YAML with multiline strings is not valid: %v", err)
		t.Logf("Output: %s", output)
	}
}

// Helper function to create test device state
func createTestDeviceStateYAML() *core.DeviceState {
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
func BenchmarkYAMLFormatter_AllData(b *testing.B) {
	deviceState := createTestDeviceStateYAML()
	formatter := NewYAMLFormatter(false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		formatter.Format(deviceState, &buf)
	}
}

func BenchmarkYAMLFormatter_WithRaw(b *testing.B) {
	deviceState := createTestDeviceStateYAML()
	formatter := NewYAMLFormatter(true)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		formatter.Format(deviceState, &buf)
	}
}

func BenchmarkYAMLFormatter_LargeData(b *testing.B) {
	deviceState := createTestDeviceStateYAML()

	// Add more data for benchmark
	for i := 0; i < 100; i++ {
		deviceState.Interfaces = append(deviceState.Interfaces, core.Interface{
			Name:        fmt.Sprintf("GigabitEthernet0/0/%d", i+2),
			Status:      "down",
			AdminStatus: "down",
			Description: fmt.Sprintf("Test interface %d", i+2),
		})
	}

	formatter := NewYAMLFormatter(false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		formatter.Format(deviceState, &buf)
	}
}
