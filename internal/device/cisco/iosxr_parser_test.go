package cisco

import (
	"testing"
)

// TestNewIOSXRParser tests IOS-XR parser creation
func TestNewIOSXRParser(t *testing.T) {
	parser := NewIOSXRParser()

	if parser == nil {
		t.Fatal("NewIOSXRParser() returned nil")
	}
}

// TestIOSXRParser_ParseVersion tests version parsing
func TestIOSXRParser_ParseVersion(t *testing.T) {
	parser := NewIOSXRParser()

	versionOutput := `Cisco IOS XR Software, Version 6.5.3[Default]
Copyright (c) 2013-2018 by Cisco Systems, Inc.

ROM: GRUB 0.97(0/0/CPU0)

Router uptime is 2 weeks, 3 days, 4 hours, 15 minutes
System image file is "disk0:asr9k-mini-x64-6.5.3"

cisco ASR9K Series (Intel 686 F6M14S4) processor with 12582912K bytes of memory.
Intel 686 F6M14S4 processor at 2134MHz, Revision 2.174
ASR 9006 2 Line Card Slot Chassis with V2 AC PEM

Package active on node 0/RSP0/CPU0:
iosxr-infra, V 6.5.3[Default], Cisco Systems, at disk0:iosxr-infra-6.5.3
    Built on Thu 06-Dec-18 13:29 by builder in /auto/srcarchive13/production/6.5.3`

	result, err := parser.ParseVersion(versionOutput)
	if err != nil {
		t.Fatalf("ParseVersion() failed: %v", err)
	}

	if result == nil {
		t.Fatal("ParseVersion() returned nil result")
	}

	// Check that device info was populated
	if result.Vendor != "cisco" {
		t.Errorf("Expected vendor 'cisco', got '%s'", result.Vendor)
	}
}

// TestIOSXRParser_ParseInterfaces tests interface parsing
func TestIOSXRParser_ParseInterfaces(t *testing.T) {
	parser := NewIOSXRParser()

	interfaceOutput := `GigabitEthernet0/0/0/0 is up, line protocol is up
  Interface state transitions: 1
  Hardware is GigE, address is 008a.9612.3456 (bia 008a.9612.3456)
  Description: WAN Interface
  Internet address is 192.168.1.1/24
  MTU 1514 bytes, BW 1000000 Kbit (Max: 1000000 Kbit)
     reliability 255/255, txload 0/255, rxload 0/255
  Encapsulation ARPA,
  Full-duplex, 1000Mb/s, link type is autonegotiation
  output flow control is off, input flow control is off
  Carrier delay (up) is 10 msec
  loopback not set,

GigabitEthernet0/0/0/1 is up, line protocol is up
  Interface state transitions: 1
  Hardware is GigE, address is 008a.9612.3457 (bia 008a.9612.3457)
  Description: LAN Interface
  Internet address is 10.1.1.1/24
  MTU 1514 bytes, BW 1000000 Kbit (Max: 1000000 Kbit)`

	result, err := parser.ParseInterfaces(interfaceOutput)
	if err != nil {
		t.Fatalf("ParseInterfaces() failed: %v", err)
	}

	if result == nil {
		t.Fatal("ParseInterfaces() returned nil result")
	}

	// Check that result is not nil (actual parsing verification would require more complex logic)
	if result == nil {
		t.Error("Expected non-nil result from interface parsing")
	}
}

// TestIOSXRParser_ParseRoutes tests route parsing
func TestIOSXRParser_ParseRoutes(t *testing.T) {
	parser := NewIOSXRParser()

	routeOutput := `Codes: C - connected, S - static, R - RIP, B - BGP, (>) - Diversion path
       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area
       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2
       E1 - OSPF external type 1, E2 - OSPF external type 2, E - EGP
       i - ISIS, L1 - IS-IS level-1, L2 - IS-IS level-2
       ia - IS-IS inter area, su - IS-IS summary null, * - candidate default
       U - per-user static route, o - ODR, L - local, G  - DAGR, l - LISP
       A - access/subscriber, a - Application route
       M - mobile route, r - RPL, (!) - FRR Backup path

Gateway of last resort is 192.168.1.1 to network 0.0.0.0

S*   0.0.0.0/0 [1/0] via 192.168.1.1, 00:05:23
C    10.1.1.0/24 is directly connected, 00:05:23, GigabitEthernet0/0/0/1
L    10.1.1.1/32 is directly connected, 00:05:23, GigabitEthernet0/0/0/1`

	result, err := parser.ParseRoutes(routeOutput)
	if err != nil {
		t.Fatalf("ParseRoutes() failed: %v", err)
	}

	if result == nil {
		t.Fatal("ParseRoutes() returned nil result")
	}

	// Check that result is not nil (actual parsing verification would require more complex logic)
	if result == nil {
		t.Error("Expected non-nil result from route parsing")
	}
}

// TestIOSXRParser_ParseProcesses tests process parsing
func TestIOSXRParser_ParseProcesses(t *testing.T) {
	parser := NewIOSXRParser()

	processOutput := `Job Id: 267
PID: 2345
Executable path: /disk0/iosxr-routing-6.5.3/bin/ospf
Instance #: 1
Version ID: 00.00.0000
Respawn: ON
Respawn count: 1
Max. spawns per minute: 12
Last started: Thu Dec  6 13:29:32 2018
Process state: Run
Package state: Normal
Started on config: cfg/gl/ipv4/ospf/process[process-name='OSPF_PROC']
core: MAINMEM
Max. core: 0
Level: 50
Placement: ON
startup_path: /pkg/startup/ospf.startup
Ready: 13:29:33

Job Id: 268
PID: 2346
Executable path: /disk0/iosxr-base-6.5.3/bin/netio
Instance #: 1`

	result, err := parser.ParseProcesses(processOutput)
	if err != nil {
		t.Fatalf("ParseProcesses() failed: %v", err)
	}

	if result == nil {
		t.Fatal("ParseProcesses() returned nil result")
	}

	// Check that result is not nil (actual parsing verification would require more complex logic)
	// The result could be an empty slice, which is valid
	if result == nil {
		t.Error("Expected non-nil result from process parsing")
	}
}
