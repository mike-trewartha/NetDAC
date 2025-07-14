package output

import (
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netdac/internal/core"
)

func TestNewCSVFormatter(t *testing.T) {
	tests := []struct {
		name           string
		includeHeaders bool
		separator      rune
		dataType       string
		expectedSep    rune
		expectedType   string
	}{
		{
			name:           "Default values",
			includeHeaders: true,
			separator:      0,
			dataType:       "",
			expectedSep:    ',',
			expectedType:   "all",
		},
		{
			name:           "Custom separator",
			includeHeaders: false,
			separator:      ';',
			dataType:       "interfaces",
			expectedSep:    ';',
			expectedType:   "interfaces",
		},
		{
			name:           "Tab separator",
			includeHeaders: true,
			separator:      '\t',
			dataType:       "routes",
			expectedSep:    '\t',
			expectedType:   "routes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			formatter := NewCSVFormatter(tt.includeHeaders, tt.separator, tt.dataType)

			if formatter.IncludeHeaders != tt.includeHeaders {
				t.Errorf("Expected IncludeHeaders %v, got %v", tt.includeHeaders, formatter.IncludeHeaders)
			}

			if formatter.Separator != tt.expectedSep {
				t.Errorf("Expected separator %c, got %c", tt.expectedSep, formatter.Separator)
			}

			if formatter.DataType != tt.expectedType {
				t.Errorf("Expected DataType %s, got %s", tt.expectedType, formatter.DataType)
			}
		})
	}
}

func TestCSVFormatter_Format(t *testing.T) {
	deviceState := createTestDeviceState()

	tests := []struct {
		name        string
		dataType    string
		expectError bool
		checkFunc   func(string) bool
	}{
		{
			name:        "Interfaces format",
			dataType:    "interfaces",
			expectError: false,
			checkFunc: func(output string) bool {
				return strings.Contains(output, "GigabitEthernet0/0/0") &&
					strings.Contains(output, "up") &&
					strings.Contains(output, "192.168.1.1")
			},
		},
		{
			name:        "Routes format",
			dataType:    "routes",
			expectError: false,
			checkFunc: func(output string) bool {
				return strings.Contains(output, "0.0.0.0/0") &&
					strings.Contains(output, "192.168.1.254") &&
					strings.Contains(output, "static")
			},
		},
		{
			name:        "Processes format",
			dataType:    "processes",
			expectError: false,
			checkFunc: func(output string) bool {
				return strings.Contains(output, "init") &&
					strings.Contains(output, "running")
			},
		},
		{
			name:        "Sessions format",
			dataType:    "sessions",
			expectError: false,
			checkFunc: func(output string) bool {
				return strings.Contains(output, "admin") &&
					strings.Contains(output, "vty 0") &&
					strings.Contains(output, "ssh")
			},
		},
		{
			name:        "Connections format",
			dataType:    "connections",
			expectError: false,
			checkFunc: func(output string) bool {
				return strings.Contains(output, "TCP") &&
					strings.Contains(output, "ESTABLISHED") &&
					strings.Contains(output, "22")
			},
		},
		{
			name:        "Summary format",
			dataType:    "summary",
			expectError: false,
			checkFunc: func(output string) bool {
				return strings.Contains(output, "test-device") &&
					strings.Contains(output, "cisco") &&
					strings.Contains(output, "Total Interfaces")
			},
		},
		{
			name:        "All format",
			dataType:    "all",
			expectError: false,
			checkFunc: func(output string) bool {
				return strings.Contains(output, "=== DEVICE SUMMARY ===") &&
					strings.Contains(output, "=== INTERFACES ===") &&
					strings.Contains(output, "=== ROUTES ===")
			},
		},
		{
			name:        "Unsupported format",
			dataType:    "invalid",
			expectError: true,
			checkFunc:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			formatter := NewCSVFormatter(true, ',', tt.dataType)
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
			if tt.checkFunc != nil && !tt.checkFunc(output) {
				t.Errorf("Output validation failed for %s format", tt.dataType)
				t.Logf("Output: %s", output)
			}
		})
	}
}

func TestCSVFormatter_WriteToFile(t *testing.T) {
	deviceState := createTestDeviceState()
	formatter := NewCSVFormatter(true, ',', "summary")

	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "netdac_csv_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testFile := filepath.Join(tempDir, "test_output.csv")

	// Test writing to file
	err = formatter.WriteToFile(deviceState, testFile)
	if err != nil {
		t.Fatalf("Failed to write to file: %v", err)
	}

	// Verify file exists and has content
	content, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}

	if len(content) == 0 {
		t.Error("File is empty")
	}

	contentStr := string(content)
	if !strings.Contains(contentStr, "test-device") {
		t.Error("File doesn't contain expected device data")
	}
}

func TestCSVFormatter_Headers(t *testing.T) {
	deviceState := createTestDeviceState()

	tests := []struct {
		name           string
		includeHeaders bool
		dataType       string
		expectedHeader string
	}{
		{
			name:           "Interfaces with headers",
			includeHeaders: true,
			dataType:       "interfaces",
			expectedHeader: "Name,Status,AdminStatus",
		},
		{
			name:           "Routes with headers",
			includeHeaders: true,
			dataType:       "routes",
			expectedHeader: "Destination,Gateway,Interface",
		},
		{
			name:           "No headers",
			includeHeaders: false,
			dataType:       "interfaces",
			expectedHeader: "GigabitEthernet0/0/0", // Should start with data, not headers
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			formatter := NewCSVFormatter(tt.includeHeaders, ',', tt.dataType)
			var buf bytes.Buffer

			err := formatter.Format(deviceState, &buf)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			output := buf.String()
			lines := strings.Split(output, "\n")

			if len(lines) == 0 {
				t.Fatal("No output generated")
			}

			firstLine := lines[0]
			if !strings.Contains(firstLine, tt.expectedHeader) {
				t.Errorf("Expected first line to contain '%s', got '%s'", tt.expectedHeader, firstLine)
			}
		})
	}
}

func TestCSVFormatter_CustomSeparator(t *testing.T) {
	deviceState := createTestDeviceState()

	tests := []struct {
		name      string
		separator rune
	}{
		{
			name:      "Semicolon separator",
			separator: ';',
		},
		{
			name:      "Tab separator",
			separator: '\t',
		},
		{
			name:      "Pipe separator",
			separator: '|',
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			formatter := NewCSVFormatter(true, tt.separator, "interfaces")
			var buf bytes.Buffer

			err := formatter.Format(deviceState, &buf)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			output := buf.String()

			// Parse CSV with custom separator
			reader := csv.NewReader(strings.NewReader(output))
			reader.Comma = tt.separator

			records, err := reader.ReadAll()
			if err != nil {
				t.Errorf("Failed to parse CSV with separator '%c': %v", tt.separator, err)
			}

			if len(records) < 2 { // At least header + 1 data row
				t.Errorf("Expected at least 2 records, got %d", len(records))
			}
		})
	}
}

func TestCSVFormatter_GetSupportedDataTypes(t *testing.T) {
	formatter := NewCSVFormatter(true, ',', "all")

	supportedTypes := formatter.GetSupportedDataTypes()

	expectedTypes := []string{"all", "summary", "interfaces", "routes", "processes", "sessions", "connections"}

	if len(supportedTypes) != len(expectedTypes) {
		t.Errorf("Expected %d supported types, got %d", len(expectedTypes), len(supportedTypes))
	}

	for _, expectedType := range expectedTypes {
		found := false
		for _, supportedType := range supportedTypes {
			if supportedType == expectedType {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected type '%s' not found in supported types", expectedType)
		}
	}
}

func TestCSVFormatter_EmptyData(t *testing.T) {
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

	tests := []string{"interfaces", "routes", "processes", "sessions", "connections"}

	for _, dataType := range tests {
		t.Run("Empty_"+dataType, func(t *testing.T) {
			formatter := NewCSVFormatter(true, ',', dataType)
			var buf bytes.Buffer

			err := formatter.Format(emptyState, &buf)
			if err != nil {
				t.Errorf("Unexpected error with empty %s data: %v", dataType, err)
			}

			output := buf.String()
			lines := strings.Split(strings.TrimSpace(output), "\n")

			// Should have header line only
			if len(lines) != 1 {
				t.Errorf("Expected 1 line (header only) for empty %s, got %d", dataType, len(lines))
			}
		})
	}
}

func TestCSVFormatter_StructToStringSlice(t *testing.T) {
	formatter := NewCSVFormatter(true, ',', "all")

	// Test the unexported method by using a simple struct
	testInterface := core.Interface{
		Name:        "test",
		Status:      "up",
		AdminStatus: "up",
		IPAddress:   "192.168.1.1",
	}

	// This tests the concept; in real code the method is unexported
	// We can verify through the public interface that it works correctly
	var buf bytes.Buffer
	deviceState := &core.DeviceState{
		Interfaces: []core.Interface{testInterface},
	}

	err := formatter.Format(deviceState, &buf)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "test") {
		t.Error("Expected struct fields to be converted to strings")
	}
}

// Helper function to create test device state
func createTestDeviceState() *core.DeviceState {
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
			TotalCommands:      10,
			SuccessfulCommands: 9,
			FailedCommands:     1,
			CollectionDuration: "30.5s",
			Errors:             []string{"Command 'show invalid' failed"},
		},
	}
}

// Benchmark tests
func BenchmarkCSVFormatter_Interfaces(b *testing.B) {
	deviceState := createTestDeviceState()
	formatter := NewCSVFormatter(true, ',', "interfaces")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		formatter.Format(deviceState, &buf)
	}
}

func BenchmarkCSVFormatter_All(b *testing.B) {
	deviceState := createTestDeviceState()
	formatter := NewCSVFormatter(true, ',', "all")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		formatter.Format(deviceState, &buf)
	}
}
