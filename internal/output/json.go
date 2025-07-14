package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"netdac/internal/core"
)

// JSONFormatter implements output formatting for JSON
type JSONFormatter struct {
	PrettyPrint bool
	IncludeRaw  bool
}

// NewJSONFormatter creates a new JSON formatter
func NewJSONFormatter(prettyPrint, includeRaw bool) *JSONFormatter {
	return &JSONFormatter{
		PrettyPrint: prettyPrint,
		IncludeRaw:  includeRaw,
	}
}

// Format formats the device state as JSON
func (f *JSONFormatter) Format(deviceState *core.DeviceState, writer io.Writer) error {
	// Create a copy of the device state for formatting
	output := *deviceState

	// Remove raw commands if not requested
	if !f.IncludeRaw {
		output.RawCommands = nil
	}

	var data []byte
	var err error

	if f.PrettyPrint {
		data, err = json.MarshalIndent(output, "", "  ")
	} else {
		data, err = json.Marshal(output)
	}

	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}

	_, err = writer.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write JSON output: %v", err)
	}

	return nil
}

// WriteToFile writes JSON output to a file
func (f *JSONFormatter) WriteToFile(deviceState *core.DeviceState, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer file.Close()

	return f.Format(deviceState, file)
}

// FormatSummary creates a summary view of the device state in JSON
func (f *JSONFormatter) FormatSummary(deviceState *core.DeviceState) ([]byte, error) {
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

	if f.PrettyPrint {
		return json.MarshalIndent(summary, "", "  ")
	}

	return json.Marshal(summary)
}

// ValidateJSON validates that the output is valid JSON
func (f *JSONFormatter) ValidateJSON(data []byte) error {
	var temp interface{}
	return json.Unmarshal(data, &temp)
}

// FormatError formats an error message as JSON
func (f *JSONFormatter) FormatError(err error, timestamp string) []byte {
	errorObj := map[string]interface{}{
		"error":     true,
		"message":   err.Error(),
		"timestamp": timestamp,
	}

	data, _ := json.Marshal(errorObj)
	return data
}
