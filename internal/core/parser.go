package core

import (
	"fmt"
	"strings"
	"time"
)

// ParserRegistry manages all available command parsers
type ParserRegistry struct {
	parsers map[string]CommandParser
}

// NewParserRegistry creates a new parser registry
func NewParserRegistry() *ParserRegistry {
	return &ParserRegistry{
		parsers: make(map[string]CommandParser),
	}
}

// RegisterParser registers a new command parser
func (pr *ParserRegistry) RegisterParser(name string, parser CommandParser) {
	pr.parsers[name] = parser
}

// GetParser retrieves a parser by name
func (pr *ParserRegistry) GetParser(name string) (CommandParser, error) {
	parser, exists := pr.parsers[name]
	if !exists {
		return nil, fmt.Errorf("parser '%s' not found", name)
	}
	return parser, nil
}

// ListParsers returns all available parser names
func (pr *ParserRegistry) ListParsers() []string {
	var names []string
	for name := range pr.parsers {
		names = append(names, name)
	}
	return names
}

// BaseParser provides common functionality for all parsers
type BaseParser struct {
	Name        string
	Description string
	Vendor      string
}

// ParseResult contains the result of parsing a command output
type ParseResult struct {
	Command   string      `json:"command"`
	DataType  string      `json:"data_type"`
	Data      interface{} `json:"data"`
	Success   bool        `json:"success"`
	Error     string      `json:"error,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
	Duration  string      `json:"duration,omitempty"`
}

// ParseContext provides context information for parsing
type ParseContext struct {
	DeviceInfo DeviceInfo
	Command    string
	Output     string
	Timestamp  time.Time
	Vendor     string
	Model      string
}

// ParserUtils provides utility functions for parsers
type ParserUtils struct{}

// NewParserUtils creates a new parser utilities instance
func NewParserUtils() *ParserUtils {
	return &ParserUtils{}
}

// ExtractLines splits output into lines and removes empty lines
func (pu *ParserUtils) ExtractLines(output string) []string {
	lines := strings.Split(output, "\n")
	var result []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// ExtractTableData extracts tabular data from command output
func (pu *ParserUtils) ExtractTableData(output string, headerIndicators []string) ([]map[string]string, error) {
	lines := pu.ExtractLines(output)
	if len(lines) == 0 {
		return nil, fmt.Errorf("no data to parse")
	}

	// Find header line
	headerIndex := -1
	for i, line := range lines {
		for _, indicator := range headerIndicators {
			if strings.Contains(strings.ToLower(line), strings.ToLower(indicator)) {
				headerIndex = i
				break
			}
		}
		if headerIndex != -1 {
			break
		}
	}

	if headerIndex == -1 {
		return nil, fmt.Errorf("could not find table header")
	}

	// Parse header to get column positions
	headerLine := lines[headerIndex]
	columns := pu.parseTableColumns(headerLine)
	if len(columns) == 0 {
		return nil, fmt.Errorf("could not parse table columns")
	}

	// Parse data rows
	var result []map[string]string
	for i := headerIndex + 1; i < len(lines); i++ {
		line := lines[i]
		if strings.TrimSpace(line) == "" {
			continue
		}

		rowData := pu.parseTableRow(line, columns)
		if len(rowData) > 0 {
			result = append(result, rowData)
		}
	}

	return result, nil
}

// parseTableColumns identifies column names and positions from header line
func (pu *ParserUtils) parseTableColumns(headerLine string) []TableColumn {
	var columns []TableColumn
	words := strings.Fields(headerLine)

	currentPos := 0
	for i, word := range words {
		startPos := strings.Index(headerLine[currentPos:], word) + currentPos
		endPos := startPos + len(word)

		// Determine column width (extend to next column or end of line)
		width := len(word)
		if i < len(words)-1 {
			nextWord := words[i+1]
			nextPos := strings.Index(headerLine[endPos:], nextWord)
			if nextPos > 0 {
				width = nextPos + endPos - startPos
			}
		} else {
			width = len(headerLine) - startPos
		}

		columns = append(columns, TableColumn{
			Name:     strings.ToLower(word),
			StartPos: startPos,
			Width:    width,
		})

		currentPos = endPos
	}

	return columns
}

// parseTableRow extracts data from a table row based on column definitions
func (pu *ParserUtils) parseTableRow(line string, columns []TableColumn) map[string]string {
	result := make(map[string]string)

	for _, col := range columns {
		if col.StartPos < len(line) {
			endPos := col.StartPos + col.Width
			if endPos > len(line) {
				endPos = len(line)
			}

			value := strings.TrimSpace(line[col.StartPos:endPos])
			if value != "" {
				result[col.Name] = value
			}
		}
	}

	return result
}

// TableColumn represents a column in a table
type TableColumn struct {
	Name     string
	StartPos int
	Width    int
}

// ExtractKeyValuePairs extracts key-value pairs from output
func (pu *ParserUtils) ExtractKeyValuePairs(output string, separator string) map[string]string {
	result := make(map[string]string)
	lines := pu.ExtractLines(output)

	for _, line := range lines {
		if strings.Contains(line, separator) {
			parts := strings.SplitN(line, separator, 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				result[key] = value
			}
		}
	}

	return result
}

// MatchPattern checks if a line matches a specific pattern
func (pu *ParserUtils) MatchPattern(line string, patterns []string) bool {
	line = strings.ToLower(strings.TrimSpace(line))
	for _, pattern := range patterns {
		if strings.Contains(line, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// ExtractIPAddresses extracts IP addresses from a string
func (pu *ParserUtils) ExtractIPAddresses(text string) []string {
	// Simple regex pattern for IPv4 addresses
	// This is a basic implementation - could be enhanced with proper regex
	words := strings.Fields(text)
	var ips []string

	for _, word := range words {
		if pu.isValidIPv4(word) {
			ips = append(ips, word)
		}
	}

	return ips
}

// isValidIPv4 checks if a string is a valid IPv4 address
func (pu *ParserUtils) isValidIPv4(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}

	for _, part := range parts {
		if len(part) == 0 || len(part) > 3 {
			return false
		}

		// Check if all characters are digits
		for _, char := range part {
			if char < '0' || char > '9' {
				return false
			}
		}

		// Convert to int and check range (0-255)
		num := 0
		for _, char := range part {
			num = num*10 + int(char-'0')
		}

		if num > 255 {
			return false
		}
	}

	return true
}

// CleanOutput removes common artifacts from command output
func (pu *ParserUtils) CleanOutput(output string) string {
	// Remove common prompts and artifacts
	lines := strings.Split(output, "\n")
	var cleanLines []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip empty lines
		if trimmed == "" {
			continue
		}

		// Skip common CLI prompts and artifacts
		if pu.isPromptLine(trimmed) {
			continue
		}

		cleanLines = append(cleanLines, line)
	}

	return strings.Join(cleanLines, "\n")
}

// isPromptLine checks if a line appears to be a CLI prompt
func (pu *ParserUtils) isPromptLine(line string) bool {
	promptIndicators := []string{
		"#", ">", "$", ")",
		"--More--", "--more--",
		"Press any key", "press any key",
		"Continue?", "continue?",
	}

	for _, indicator := range promptIndicators {
		if strings.HasSuffix(line, indicator) {
			return true
		}
	}

	return false
}

// NormalizeWhitespace normalizes whitespace in text
func (pu *ParserUtils) NormalizeWhitespace(text string) string {
	// Replace multiple whitespace characters with single space
	words := strings.Fields(text)
	return strings.Join(words, " ")
}
