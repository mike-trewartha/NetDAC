package output

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"netdac/internal/core"
)

// CSVFormatter implements output formatting for CSV
type CSVFormatter struct {
	IncludeHeaders bool
	Separator      rune
	DataType       string // "interfaces", "routes", "processes", "sessions", "all"
}

// NewCSVFormatter creates a new CSV formatter
func NewCSVFormatter(includeHeaders bool, separator rune, dataType string) *CSVFormatter {
	if separator == 0 {
		separator = ','
	}
	if dataType == "" {
		dataType = "all"
	}

	return &CSVFormatter{
		IncludeHeaders: includeHeaders,
		Separator:      separator,
		DataType:       dataType,
	}
}

// Format formats the device state as CSV
func (f *CSVFormatter) Format(deviceState *core.DeviceState, writer io.Writer) error {
	csvWriter := csv.NewWriter(writer)
	csvWriter.Comma = f.Separator
	defer csvWriter.Flush()

	switch strings.ToLower(f.DataType) {
	case "interfaces":
		return f.formatInterfaces(deviceState.Interfaces, csvWriter)
	case "routes":
		return f.formatRoutes(deviceState.Routes, csvWriter)
	case "processes":
		return f.formatProcesses(deviceState.Processes, csvWriter)
	case "sessions":
		return f.formatSessions(deviceState.Sessions, csvWriter)
	case "connections":
		return f.formatConnections(deviceState.Connections, csvWriter)
	case "summary":
		return f.formatSummary(deviceState, csvWriter)
	case "all":
		return f.formatAll(deviceState, csvWriter)
	default:
		return fmt.Errorf("unsupported CSV data type: %s", f.DataType)
	}
}

// WriteToFile writes CSV output to a file
func (f *CSVFormatter) WriteToFile(deviceState *core.DeviceState, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer file.Close()

	return f.Format(deviceState, file)
}

// formatInterfaces formats interface data as CSV
func (f *CSVFormatter) formatInterfaces(interfaces []core.Interface, writer *csv.Writer) error {
	if f.IncludeHeaders {
		headers := []string{
			"Name", "Status", "AdminStatus", "IPAddress", "SubnetMask", "MACAddress",
			"MTU", "Speed", "Duplex", "RxBytes", "TxBytes", "RxPackets", "TxPackets",
			"RxErrors", "TxErrors", "Description", "VLAN",
		}
		if err := writer.Write(headers); err != nil {
			return err
		}
	}

	for _, iface := range interfaces {
		record := []string{
			iface.Name, iface.Status, iface.AdminStatus, iface.IPAddress,
			iface.SubnetMask, iface.MACAddress, iface.MTU, iface.Speed,
			iface.Duplex, iface.RxBytes, iface.TxBytes, iface.RxPackets,
			iface.TxPackets, iface.RxErrors, iface.TxErrors, iface.Description,
			iface.VLAN,
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

// formatRoutes formats route data as CSV
func (f *CSVFormatter) formatRoutes(routes []core.Route, writer *csv.Writer) error {
	if f.IncludeHeaders {
		headers := []string{
			"Destination", "Gateway", "Interface", "Metric", "Protocol",
			"AdminDistance", "Age", "NextHop",
		}
		if err := writer.Write(headers); err != nil {
			return err
		}
	}

	for _, route := range routes {
		record := []string{
			route.Destination, route.Gateway, route.Interface, route.Metric,
			route.Protocol, route.AdminDistance, route.Age, route.NextHop,
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

// formatProcesses formats process data as CSV
func (f *CSVFormatter) formatProcesses(processes []core.Process, writer *csv.Writer) error {
	if f.IncludeHeaders {
		headers := []string{
			"PID", "Name", "CPU", "Memory", "Runtime", "State",
			"Priority", "ParentPID", "CommandLine",
		}
		if err := writer.Write(headers); err != nil {
			return err
		}
	}

	for _, process := range processes {
		record := []string{
			process.PID, process.Name, process.CPU, process.Memory,
			process.Runtime, process.State, process.Priority,
			process.ParentPID, process.CommandLine,
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

// formatSessions formats session data as CSV
func (f *CSVFormatter) formatSessions(sessions []core.Session, writer *csv.Writer) error {
	if f.IncludeHeaders {
		headers := []string{
			"User", "Line", "Location", "IdleTime", "LoginTime",
			"Protocol", "Privilege", "SourceIP",
		}
		if err := writer.Write(headers); err != nil {
			return err
		}
	}

	for _, session := range sessions {
		record := []string{
			session.User, session.Line, session.Location, session.IdleTime,
			session.LoginTime, session.Protocol, session.Privilege, session.SourceIP,
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

// formatConnections formats connection data as CSV
func (f *CSVFormatter) formatConnections(connections []core.Connection, writer *csv.Writer) error {
	if f.IncludeHeaders {
		headers := []string{
			"Protocol", "LocalAddress", "LocalPort", "RemoteAddress",
			"RemotePort", "State", "PID", "Process", "EstablishedTime",
		}
		if err := writer.Write(headers); err != nil {
			return err
		}
	}

	for _, conn := range connections {
		record := []string{
			conn.Protocol, conn.LocalAddress, conn.LocalPort, conn.RemoteAddress,
			conn.RemotePort, conn.State, conn.PID, conn.Process, conn.EstablishedTime,
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

// formatSummary formats summary data as CSV
func (f *CSVFormatter) formatSummary(deviceState *core.DeviceState, writer *csv.Writer) error {
	if f.IncludeHeaders {
		headers := []string{
			"Metric", "Value",
		}
		if err := writer.Write(headers); err != nil {
			return err
		}
	}

	// Device information
	deviceInfo := [][]string{
		{"Hostname", deviceState.DeviceInfo.Hostname},
		{"IP Address", deviceState.DeviceInfo.IPAddress},
		{"Vendor", deviceState.DeviceInfo.Vendor},
		{"Model", deviceState.DeviceInfo.Model},
		{"Version", deviceState.DeviceInfo.Version},
		{"Serial Number", deviceState.DeviceInfo.SerialNumber},
		{"Uptime", deviceState.DeviceInfo.Uptime},
		{"Collection Time", deviceState.Timestamp.Format(time.RFC3339)},
	}

	for _, record := range deviceInfo {
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	// Counts
	counts := [][]string{
		{"Total Interfaces", strconv.Itoa(len(deviceState.Interfaces))},
		{"Total Routes", strconv.Itoa(len(deviceState.Routes))},
		{"Total Processes", strconv.Itoa(len(deviceState.Processes))},
		{"Total Sessions", strconv.Itoa(len(deviceState.Sessions))},
		{"Total Connections", strconv.Itoa(len(deviceState.Connections))},
		{"Commands Executed", strconv.Itoa(deviceState.Metadata.TotalCommands)},
		{"Successful Commands", strconv.Itoa(deviceState.Metadata.SuccessfulCommands)},
		{"Failed Commands", strconv.Itoa(deviceState.Metadata.FailedCommands)},
		{"Collection Duration", deviceState.Metadata.CollectionDuration},
	}

	for _, record := range counts {
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

// formatAll formats all data types in separate sections
func (f *CSVFormatter) formatAll(deviceState *core.DeviceState, writer *csv.Writer) error {
	// Write summary section
	if err := writer.Write([]string{"=== DEVICE SUMMARY ==="}); err != nil {
		return err
	}
	if err := f.formatSummary(deviceState, writer); err != nil {
		return err
	}

	// Write interfaces section
	if len(deviceState.Interfaces) > 0 {
		if err := writer.Write([]string{""}); err != nil {
			return err
		}
		if err := writer.Write([]string{"=== INTERFACES ==="}); err != nil {
			return err
		}
		if err := f.formatInterfaces(deviceState.Interfaces, writer); err != nil {
			return err
		}
	}

	// Write routes section
	if len(deviceState.Routes) > 0 {
		if err := writer.Write([]string{""}); err != nil {
			return err
		}
		if err := writer.Write([]string{"=== ROUTES ==="}); err != nil {
			return err
		}
		if err := f.formatRoutes(deviceState.Routes, writer); err != nil {
			return err
		}
	}

	// Write processes section
	if len(deviceState.Processes) > 0 {
		if err := writer.Write([]string{""}); err != nil {
			return err
		}
		if err := writer.Write([]string{"=== PROCESSES ==="}); err != nil {
			return err
		}
		if err := f.formatProcesses(deviceState.Processes, writer); err != nil {
			return err
		}
	}

	// Write sessions section
	if len(deviceState.Sessions) > 0 {
		if err := writer.Write([]string{""}); err != nil {
			return err
		}
		if err := writer.Write([]string{"=== SESSIONS ==="}); err != nil {
			return err
		}
		if err := f.formatSessions(deviceState.Sessions, writer); err != nil {
			return err
		}
	}

	// Write connections section
	if len(deviceState.Connections) > 0 {
		if err := writer.Write([]string{""}); err != nil {
			return err
		}
		if err := writer.Write([]string{"=== CONNECTIONS ==="}); err != nil {
			return err
		}
		if err := f.formatConnections(deviceState.Connections, writer); err != nil {
			return err
		}
	}

	return nil
}

// GetSupportedDataTypes returns the supported data types for CSV output
func (f *CSVFormatter) GetSupportedDataTypes() []string {
	return []string{
		"all", "summary", "interfaces", "routes", "processes",
		"sessions", "connections",
	}
}

// structToStringSlice converts a struct to a slice of strings for CSV output
func (f *CSVFormatter) structToStringSlice(v interface{}) []string {
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}

	var result []string
	for i := 0; i < rv.NumField(); i++ {
		field := rv.Field(i)
		result = append(result, fmt.Sprintf("%v", field.Interface()))
	}

	return result
}
