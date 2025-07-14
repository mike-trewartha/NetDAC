package juniper

import (
	"testing"
)

func TestJunOSParser_Creation(t *testing.T) {
	parser := NewJunOSParser()

	if parser == nil {
		t.Error("Expected parser to be created")
	}

	if parser.supportedCommands == nil {
		t.Error("Expected supportedCommands map to be initialized")
	}

	if len(parser.supportedCommands) == 0 {
		t.Error("Expected parser to have registered commands")
	}
}

func TestJunOSParser_SupportedCommands(t *testing.T) {
	parser := NewJunOSParser()
	commands := parser.SupportedCommands()

	if len(commands) == 0 {
		t.Error("Expected parser to support some commands")
	}

	// Check for key commands
	expectedCommands := []string{
		"show version",
		"show system hostname",
		"show chassis hardware",
		"show system processes",
		"show interfaces terse",
		"show route summary",
		"show system users",
		"show security policies",
	}

	commandMap := make(map[string]bool)
	for _, cmd := range commands {
		commandMap[cmd] = true
	}

	for _, expected := range expectedCommands {
		if !commandMap[expected] {
			t.Errorf("Expected command '%s' to be supported", expected)
		}
	}
}

func TestJunOSParser_GetCommandType(t *testing.T) {
	parser := NewJunOSParser()

	testCases := []struct {
		command      string
		expectedType string
	}{
		{"show version", "version"},
		{"show system hostname", "hostname"},
		{"show chassis hardware", "hardware"},
		{"show system processes", "processes"},
		{"show interfaces terse", "interfaces"},
		{"show route summary", "routing"},
		{"show system users", "users"},
		{"show security policies", "security"},
		{"show security zones", "security"},
		{"show system storage", "storage"},
		{"show system memory", "memory"},
		{"show log messages", "logs"},
		{"show configuration", "configuration"},
		{"unknown command", "raw"},
	}

	for _, tc := range testCases {
		result := parser.GetCommandType(tc.command)
		if result != tc.expectedType {
			t.Errorf("Command '%s': expected type '%s', got '%s'",
				tc.command, tc.expectedType, result)
		}
	}
}

func TestJunOSParser_NormalizeCommand(t *testing.T) {
	parser := NewJunOSParser()

	testCases := []struct {
		input    string
		expected string
	}{
		{"show version", "show version"},
		{"SHOW VERSION", "show version"},
		{"  show version  ", "show version"},
		{"show log messages | last 100", "show log messages"},
		{"show log chassisd | head -50", "show log chassisd"},
		{"show log dcd | tail -20", "show log dcd"},
		{"show log rpd | grep error", "show log rpd"},
		{"file list /var/log/", "file list"},
		{"last | head -20", "last"},
	}

	for _, tc := range testCases {
		result := parser.normalizeCommand(tc.input)
		if result != tc.expected {
			t.Errorf("Input '%s': expected '%s', got '%s'",
				tc.input, tc.expected, result)
		}
	}
}

func TestJunOSParser_ParseCommand_Version(t *testing.T) {
	parser := NewJunOSParser()

	versionOutput := `Hostname: mx480-test
Model: mx480
Junos: 20.2R3.8
JUNOS OS Kernel 64-bit  [20200909.075910_builder_stable_12]
JUNOS OS libs [20200909.075910_builder_stable_12]
Uptime: 4 days, 20 hours, 10 minutes, 0 seconds`

	result, err := parser.ParseCommand("show version", versionOutput)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Error("Expected result to be a map")
	}

	if resultMap["raw"] != versionOutput {
		t.Error("Expected raw output to be preserved")
	}

	// Check if OS version was extracted
	if osVersion, exists := resultMap["os_version"]; exists {
		osVersionStr, ok := osVersion.(string)
		if !ok || osVersionStr == "" {
			t.Error("Expected os_version to be a non-empty string")
		}
	}
}

func TestJunOSParser_ParseCommand_Hostname(t *testing.T) {
	parser := NewJunOSParser()

	hostnameOutput := "mx480-lab-router"

	result, err := parser.ParseCommand("show system hostname", hostnameOutput)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Error("Expected result to be a map")
	}

	hostname, exists := resultMap["hostname"]
	if !exists {
		t.Error("Expected hostname field in result")
	}

	if hostname != "mx480-lab-router" {
		t.Errorf("Expected hostname 'mx480-lab-router', got '%v'", hostname)
	}
}

func TestJunOSParser_ParseCommand_ChassisHardware(t *testing.T) {
	parser := NewJunOSParser()

	chassisOutput := `Hardware inventory:
Item             Version  Part number  Serial number     Description
Chassis                                ABC123456         MX480 Base Chassis
Midplane         REV 06   750-025780   ACC234567         MX480 Backplane
FPC 0            REV 08   750-028467   DEF345678         MPC Type 2 3D
CPU              REV 07   750-026468   GHI456789         RMPC PMB`

	result, err := parser.ParseCommand("show chassis hardware", chassisOutput)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Error("Expected result to be a map")
	}

	hardwareItems, exists := resultMap["hardware_items"]
	if !exists {
		t.Error("Expected hardware_items field in result")
	}

	items, ok := hardwareItems.([]map[string]interface{})
	if !ok {
		t.Error("Expected hardware_items to be a slice of maps")
	}

	if len(items) == 0 {
		t.Error("Expected at least one hardware item")
	}

	// Check first item (should be Chassis)
	firstItem := items[0]
	if firstItem["item"] != "Chassis" {
		t.Errorf("Expected first item to be 'Chassis', got '%v'", firstItem["item"])
	}

	if firstItem["serial"] != "ABC123456" {
		t.Errorf("Expected serial 'ABC123456', got '%v'", firstItem["serial"])
	}
}

func TestJunOSParser_ParseCommand_Processes(t *testing.T) {
	parser := NewJunOSParser()

	processOutput := `  PID USERNAME PRI NICE   SIZE    RES STATE   TIME   CPU COMMAND
    1 root      20    0  3328K  1508K select   0:01  0.00% /sbin/init
  123 root      20    0  4456K  2108K select   0:00  0.00% /usr/sbin/cron
  456 admin     20    0  8192K  4096K run      0:02  1.50% /usr/bin/cli
  789 root      20    0 12288K  8192K sleep    0:05  2.30% /usr/sbin/rpd`

	result, err := parser.ParseCommand("show system processes", processOutput)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Error("Expected result to be a map")
	}

	processes, exists := resultMap["processes"]
	if !exists {
		t.Error("Expected processes field in result")
	}

	procList, ok := processes.([]map[string]interface{})
	if !ok {
		t.Error("Expected processes to be a slice of maps")
	}

	if len(procList) == 0 {
		t.Error("Expected at least one process")
	}

	// Check first process
	firstProc := procList[0]
	if firstProc["pid"] != "1" {
		t.Errorf("Expected PID '1', got '%v'", firstProc["pid"])
	}

	if firstProc["username"] != "root" {
		t.Errorf("Expected username 'root', got '%v'", firstProc["username"])
	}
}

func TestJunOSParser_ParseCommand_InterfacesTerse(t *testing.T) {
	parser := NewJunOSParser()

	interfaceOutput := `Interface               Admin Link Proto    Local                 Remote
ge-0/0/0                up    up   inet     192.168.1.1/24
ge-0/0/1                up    down
ge-0/0/2                down  down
lo0                     up    up   inet     127.0.0.1/32
                                   inet6    ::1/128`

	result, err := parser.ParseCommand("show interfaces terse", interfaceOutput)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Error("Expected result to be a map")
	}

	interfaces, exists := resultMap["interfaces"]
	if !exists {
		t.Error("Expected interfaces field in result")
	}

	ifaceList, ok := interfaces.([]map[string]interface{})
	if !ok {
		t.Error("Expected interfaces to be a slice of maps")
	}

	if len(ifaceList) == 0 {
		t.Error("Expected at least one interface")
	}

	// Check first interface
	firstIface := ifaceList[0]
	if firstIface["interface"] != "ge-0/0/0" {
		t.Errorf("Expected interface 'ge-0/0/0', got '%v'", firstIface["interface"])
	}

	if firstIface["admin_state"] != "up" {
		t.Errorf("Expected admin_state 'up', got '%v'", firstIface["admin_state"])
	}

	if firstIface["link_state"] != "up" {
		t.Errorf("Expected link_state 'up', got '%v'", firstIface["link_state"])
	}
}

func TestJunOSParser_ParseCommand_Users(t *testing.T) {
	parser := NewJunOSParser()

	usersOutput := `admin     cli      0   10:30AM  console
operator  cli      1    9:45AM  192.168.1.100
readonly  cli      -    2:15PM  192.168.1.101`

	result, err := parser.ParseCommand("show system users", usersOutput)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Error("Expected result to be a map")
	}

	users, exists := resultMap["users"]
	if !exists {
		t.Error("Expected users field in result")
	}

	userList, ok := users.([]map[string]interface{})
	if !ok {
		t.Error("Expected users to be a slice of maps")
	}

	if len(userList) == 0 {
		t.Error("Expected at least one user")
	}

	// Check first user
	firstUser := userList[0]
	if firstUser["user"] != "admin" {
		t.Errorf("Expected user 'admin', got '%v'", firstUser["user"])
	}

	if firstUser["class"] != "cli" {
		t.Errorf("Expected class 'cli', got '%v'", firstUser["class"])
	}
}

func TestJunOSParser_ParseCommand_LogMessages(t *testing.T) {
	parser := NewJunOSParser()

	logOutput := `Jan 15 10:30:15 hostname kernel: Interface ge-0/0/0 is up
Jan 15 10:31:20 hostname rpd[1234]: BGP neighbor 192.168.1.1 is up
Jan 15 10:32:25 hostname kernel: Link up: ge-0/0/1
Jan 15 10:33:30 hostname cli[5678]: User admin logged in`

	result, err := parser.ParseCommand("show log messages", logOutput)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Error("Expected result to be a map")
	}

	logMessages, exists := resultMap["log_messages"]
	if !exists {
		t.Error("Expected log_messages field in result")
	}

	msgList, ok := logMessages.([]map[string]interface{})
	if !ok {
		t.Error("Expected log_messages to be a slice of maps")
	}

	if len(msgList) == 0 {
		t.Error("Expected at least one log message")
	}

	// Check first message
	firstMsg := msgList[0]
	if _, exists := firstMsg["timestamp"]; !exists {
		t.Error("Expected timestamp field in log message")
	}

	if _, exists := firstMsg["message"]; !exists {
		t.Error("Expected message field in log message")
	}
}

func TestJunOSParser_ParseCommand_Storage(t *testing.T) {
	parser := NewJunOSParser()

	storageOutput := `Filesystem     Size  Used Avail Use% Mounted on
/dev/da0s1a    248M   89M  139M  39% /
devfs          1.0K  1.0K    0B 100% /dev
/dev/da0s1e    248M   12M  216M   5% /config
/dev/da0s1f    3.6G  1.8G  1.5G  55% /var
tmpfs          512M   24M  488M   5% /tmp`

	result, err := parser.ParseCommand("show system storage", storageOutput)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Error("Expected result to be a map")
	}

	filesystems, exists := resultMap["filesystems"]
	if !exists {
		t.Error("Expected filesystems field in result")
	}

	fsList, ok := filesystems.([]map[string]interface{})
	if !ok {
		t.Error("Expected filesystems to be a slice of maps")
	}

	if len(fsList) == 0 {
		t.Error("Expected at least one filesystem")
	}

	// Check first filesystem
	firstFS := fsList[0]
	if firstFS["filesystem"] != "/dev/da0s1a" {
		t.Errorf("Expected filesystem '/dev/da0s1a', got '%v'", firstFS["filesystem"])
	}

	if firstFS["mounted"] != "/" {
		t.Errorf("Expected mounted '/', got '%v'", firstFS["mounted"])
	}
}

func TestJunOSParser_ParseCommand_UnknownCommand(t *testing.T) {
	parser := NewJunOSParser()

	unknownOutput := "Some unknown command output"

	result, err := parser.ParseCommand("unknown command", unknownOutput)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Error("Expected result to be a map")
	}

	if resultMap["command"] != "unknown command" {
		t.Error("Expected command field to be preserved")
	}

	if resultMap["output"] != unknownOutput {
		t.Error("Expected output field to be preserved")
	}

	if resultMap["raw"] != true {
		t.Error("Expected raw field to be true")
	}
}
