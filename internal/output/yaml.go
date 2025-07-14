package output

import (
	"fmt"
	"io"
	"os"

	"netdac/internal/core"

	"gopkg.in/yaml.v3"
)

// YAMLFormatter implements output formatting for YAML
type YAMLFormatter struct {
	IncludeRaw bool
}

// NewYAMLFormatter creates a new YAML formatter
func NewYAMLFormatter(includeRaw bool) *YAMLFormatter {
	return &YAMLFormatter{
		IncludeRaw: includeRaw,
	}
}

// Format formats the device state as YAML
func (f *YAMLFormatter) Format(deviceState *core.DeviceState, writer io.Writer) error {
	// Create a copy of the device state for formatting
	output := *deviceState

	// Remove raw commands if not requested
	if !f.IncludeRaw {
		output.RawCommands = nil
	}

	encoder := yaml.NewEncoder(writer)
	encoder.SetIndent(2)

	err := encoder.Encode(output)
	if err != nil {
		return fmt.Errorf("failed to encode YAML: %v", err)
	}

	return encoder.Close()
}

// WriteToFile writes YAML output to a file
func (f *YAMLFormatter) WriteToFile(deviceState *core.DeviceState, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer file.Close()

	return f.Format(deviceState, file)
}

// FormatSummary creates a summary view of the device state in YAML
func (f *YAMLFormatter) FormatSummary(deviceState *core.DeviceState) ([]byte, error) {
	summary := map[string]interface{}{
		"device_info": deviceState.DeviceInfo,
		"timestamp":   deviceState.Timestamp,
		"summary": map[string]interface{}{
			"total_interfaces": len(deviceState.Interfaces),
			"total_routes":     len(deviceState.Routes),
			"total_processes":  len(deviceState.Processes),
			"total_sessions":   len(deviceState.Sessions),
			"collection_info":  deviceState.Metadata,
		},
	}

	return yaml.Marshal(summary)
}

// ValidateYAML validates that the output is valid YAML
func (f *YAMLFormatter) ValidateYAML(data []byte) error {
	var temp interface{}
	return yaml.Unmarshal(data, &temp)
}

// FormatError formats an error message as YAML
func (f *YAMLFormatter) FormatError(err error, timestamp string) []byte {
	errorObj := map[string]interface{}{
		"error":     true,
		"message":   err.Error(),
		"timestamp": timestamp,
	}

	data, _ := yaml.Marshal(errorObj)
	return data
}
