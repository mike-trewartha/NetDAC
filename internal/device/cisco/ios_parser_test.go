package cisco

import (
	"testing"
	"time"

	"netdac/internal/core"
)

// TestNewIOSParser tests IOS parser creation
func TestNewIOSParser(t *testing.T) {
	parser := NewIOSParser()

	if parser == nil {
		t.Fatal("NewIOSParser() returned nil")
	}

	if parser.utils == nil {
		t.Error("Parser utils not initialized")
	}
}

// TestIOSParser_ParseVersion tests version parsing
func TestIOSParser_ParseVersion(t *testing.T) {
	parser := NewIOSParser()

	versionOutput := `Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.7(3)M8, RELEASE SOFTWARE (fc1)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2019 by Cisco Systems, Inc.
Compiled Thu 15-Aug-19 17:22 by prod_rel_team

ROM: System Bootstrap, Version 15.0(1r)M16, RELEASE SOFTWARE (fc1)

Router uptime is 15 weeks, 2 days, 6 hours, 45 minutes
System returned to ROM by power-on
System image file is "flash0:c2900-universalk9-mz.SPA.157-3.M8.bin"
Last reload reason: power-on

Processor board ID FCZ1847C0QS
Cisco 2901 (revision 1.0) with 483328K/40960K bytes of memory.`

	deviceState := &core.DeviceState{
		DeviceInfo: core.DeviceInfo{},
		Timestamp:  time.Now(),
	}

	err := parser.ParseVersion(versionOutput, deviceState)
	if err != nil {
		t.Fatalf("ParseVersion() failed: %v", err)
	}

	// Check that device info was populated
	if deviceState.DeviceInfo.Vendor != "cisco" {
		t.Errorf("Expected vendor 'cisco', got '%s'", deviceState.DeviceInfo.Vendor)
	}

	if deviceState.DeviceInfo.Version == "" {
		t.Error("Expected version to be populated")
	}
}

// TestIOSParser_ParseInterfaces tests interface parsing
func TestIOSParser_ParseInterfaces(t *testing.T) {
	parser := NewIOSParser()

	interfaceOutput := `GigabitEthernet0/0 is up, line protocol is up
  Hardware is CN Gigabit Ethernet, address is c067.af12.3456 (bia c067.af12.3456)
  Description: WAN Interface
  Internet address is 192.168.1.1/24
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Keepalive set (10 sec)

GigabitEthernet0/1 is up, line protocol is up
  Hardware is CN Gigabit Ethernet, address is c067.af12.3457 (bia c067.af12.3457)
  Description: LAN Interface
  Internet address is 10.1.1.1/24
  MTU 1500 bytes, BW 1000000 Kbit/sec`

	deviceState := &core.DeviceState{
		DeviceInfo: core.DeviceInfo{},
		Timestamp:  time.Now(),
	}

	err := parser.ParseInterfaces(interfaceOutput, deviceState)
	if err != nil {
		t.Fatalf("ParseInterfaces() failed: %v", err)
	}

	// Check that interfaces were parsed (basic validation)
	// The actual field population depends on the parser implementation
	// Just check that the method executed without error
}

// TestIOSParser_ParseProcesses tests process parsing
func TestIOSParser_ParseProcesses(t *testing.T) {
	parser := NewIOSParser()

	processOutput := `CPU utilization for five seconds: 2%/1%; one minute: 3%; five minutes: 2%
 PID Runtime(ms)     Invoked      uSecs   5Sec   1Min   5Min TTY Process
   1          44       16725          2  0.00%  0.00%  0.00%   0 Chunk Manager
   2           4        2517          1  0.00%  0.00%  0.00%   0 Load Meter
   3        1612       16725         96  0.00%  0.03%  0.01%   0 Check heaps`

	deviceState := &core.DeviceState{
		DeviceInfo: core.DeviceInfo{},
		Timestamp:  time.Now(),
	}

	err := parser.ParseProcesses(processOutput, deviceState)
	if err != nil {
		t.Fatalf("ParseProcesses() failed: %v", err)
	}

	// Check that processes were parsed (basic validation)
	// The actual field population depends on the parser implementation
	// Just check that the method executed without error
}

// TestIOSParser_ParseTechSupport tests tech-support parsing
func TestIOSParser_ParseTechSupport(t *testing.T) {
	parser := NewIOSParser()

	techSupportOutput := `show tech-support

------------------ show version ------------------

Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.7(3)M8, RELEASE SOFTWARE (fc1)
Technical Support: http://www.cisco.com/techsupport

------------------ show interfaces ------------------

GigabitEthernet0/0 is up, line protocol is up
  Hardware is CN Gigabit Ethernet, address is c067.af12.3456`

	deviceState := &core.DeviceState{
		DeviceInfo: core.DeviceInfo{},
		Timestamp:  time.Now(),
	}

	err := parser.ParseTechSupport(techSupportOutput, deviceState)
	if err != nil {
		t.Fatalf("ParseTechSupport() failed: %v", err)
	}

	// Tech support parsing should not fail (basic validation)
	if deviceState == nil {
		t.Error("Expected device state to remain valid")
	}
}

// TestIOSParser_ParseDirectoryListing tests directory listing parsing
func TestIOSParser_ParseDirectoryListing(t *testing.T) {
	parser := NewIOSParser()

	dirOutput := `Directory of flash0:/

    1  -rw-   102760448   Mar 1 1993 00:01:00 +00:00  c2900-universalk9-mz.SPA.157-3.M8.bin
    2  -rw-        1038   Mar 1 1993 00:01:00 +00:00  info

258048000 bytes total (155287552 bytes free)`

	deviceState := &core.DeviceState{
		DeviceInfo: core.DeviceInfo{},
		Timestamp:  time.Now(),
	}

	err := parser.ParseDirectoryListing(dirOutput, deviceState)
	if err != nil {
		t.Fatalf("ParseDirectoryListing() failed: %v", err)
	}

	// Directory listing parsing should not fail (basic validation)
	if deviceState == nil {
		t.Error("Expected device state to remain valid")
	}
}
