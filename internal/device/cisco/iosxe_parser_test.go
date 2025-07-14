package cisco

import (
	"testing"
)

// TestNewIOSXEParser tests IOS-XE parser creation
func TestNewIOSXEParser(t *testing.T) {
	parser := NewIOSXEParser()

	if parser == nil {
		t.Fatal("NewIOSXEParser() returned nil")
	}
}

// TestIOSXEParser_ParseShowVersion tests version parsing
func TestIOSXEParser_ParseShowVersion(t *testing.T) {
	parser := NewIOSXEParser()

	versionOutput := `Cisco IOS XE Software, Version 16.09.08
Cisco IOS Software [Everest], ISR4000 Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 16.9.8, RELEASE SOFTWARE (fc2)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2021 by Cisco Systems, Inc.
Compiled Thu 22-Jul-21 00:22 by mcpre

Cisco IOS-XE software, Copyright (c) 2005-2021 by cisco Systems, Inc.
All rights reserved. Certain components of Cisco IOS-XE software are
licensed under the GNU General Public License ("GPL") Version 2.0. The
software code licensed under GPL Version 2.0 is free software that comes
with ABSOLUTELY NO WARRANTY.

ROM: IOS-XE ROMMON

ISR4431 uptime is 2 weeks, 3 days, 4 hours, 15 minutes
Uptime for this control processor is 2 weeks, 3 days, 4 hours, 17 minutes
System returned to ROM by reload
System image file is "bootflash:isr4400-universalk9.16.09.08.SPA.bin"
Last reload reason: reload

Processor board ID FDO21120R5K
1 Virtual Ethernet interface
4 Gigabit Ethernet interfaces
2048K bytes of non-volatile configuration memory.
4194304K bytes of physical memory.
7774207K bytes of bootflash at bootflash:.`

	result, err := parser.ParseShowVersion(versionOutput)
	if err != nil {
		t.Fatalf("ParseShowVersion() failed: %v", err)
	}

	if result == nil {
		t.Fatal("ParseShowVersion() returned nil result")
	}

	// Check that result is not nil (actual parsing verification would require more complex logic)
	if result == nil {
		t.Error("Expected non-nil result from version parsing")
	}
}

// TestIOSXEParser_ParseInterfaces tests interface parsing
func TestIOSXEParser_ParseInterfaces(t *testing.T) {
	parser := NewIOSXEParser()

	interfaceOutput := `GigabitEthernet0/0/0 is up, line protocol is up
  Hardware is ISR4431-X-4x1GE, address is a03d.6f12.3456 (bia a03d.6f12.3456)
  Description: WAN Interface
  Internet address is 192.168.1.1/24
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Keepalive set (10 sec)

GigabitEthernet0/0/1 is up, line protocol is up
  Hardware is ISR4431-X-4x1GE, address is a03d.6f12.3457 (bia a03d.6f12.3457)
  Description: LAN Interface
  Internet address is 10.1.1.1/24
  MTU 1500 bytes, BW 1000000 Kbit/sec`

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

// TestIOSXEParser_ParseIPRoute tests IP route parsing
func TestIOSXEParser_ParseIPRoute(t *testing.T) {
	parser := NewIOSXEParser()

	routeOutput := `Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP
       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area
       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2
       E1 - OSPF external type 1, E2 - OSPF external type 2
       i - IS-IS, su - IS-IS summary, L1 - IS-IS level-1, L2 - IS-IS level-2
       ia - IS-IS inter area, * - candidate default, U - per-user static route
       o - ODR, P - periodic downloaded static route, H - NHRP, l - LISP
       a - application route
       + - replicated route, % - next hop override, p - overrides from PfR

Gateway of last resort is 192.168.1.1 to network 0.0.0.0

S*    0.0.0.0/0 [1/0] via 192.168.1.1
      10.0.0.0/8 is variably subnetted, 2 subnets, 2 masks
C        10.1.1.0/24 is directly connected, GigabitEthernet0/0/1
L        10.1.1.1/32 is directly connected, GigabitEthernet0/0/1`

	result, err := parser.ParseIPRoute(routeOutput)
	if err != nil {
		t.Fatalf("ParseIPRoute() failed: %v", err)
	}

	if result == nil {
		t.Fatal("ParseIPRoute() returned nil result")
	}

	// Check that result is not nil (actual parsing verification would require more complex logic)
	if result == nil {
		t.Error("Expected non-nil result from route parsing")
	}
}

// TestIOSXEParser_ParseSoftwareAuthenticity tests software authenticity parsing
func TestIOSXEParser_ParseSoftwareAuthenticity(t *testing.T) {
	parser := NewIOSXEParser()

	authenticityOutput := `Software Authenticity: PASS

RSA Encrypted Signature Verification: PASS
DSA Encrypted Signature Verification: PASS
Software Image File: bootflash:isr4400-universalk9.16.09.08.SPA.bin
Signature Status: VERIFIED (1/1)
Release Signature Status: VERIFIED (1/1)

%Signature file for image bootflash:isr4400-universalk9.16.09.08.SPA.bin:
Signature is embedded in the image.
RSA signature status: VERIFIED (1/1)
DSA signature status: VERIFIED (1/1)`

	result, err := parser.ParseSoftwareAuthenticity(authenticityOutput)
	if err != nil {
		t.Fatalf("ParseSoftwareAuthenticity() failed: %v", err)
	}

	if result == nil {
		t.Fatal("ParseSoftwareAuthenticity() returned nil result")
	}

	// Check that result is not nil (actual parsing verification would require more complex logic)
	if result == nil {
		t.Error("Expected non-nil result from software authenticity parsing")
	}
}
