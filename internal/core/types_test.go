package core

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDeviceState_JSON(t *testing.T) {
	// Create a sample device state
	deviceState := &DeviceState{
		DeviceInfo: DeviceInfo{
			Hostname:     "test-device",
			IPAddress:    "192.168.1.1",
			Vendor:       "cisco",
			Model:        "ISR4321",
			Version:      "16.09.04",
			SerialNumber: "FDO12345678",
			Uptime:       "5 days, 2 hours",
		},
		Timestamp: time.Now(),
		Interfaces: []Interface{
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
		Routes: []Route{
			{
				Destination:   "0.0.0.0/0",
				Gateway:       "192.168.1.254",
				Interface:     "GigabitEthernet0/0/0",
				Metric:        "1",
				Protocol:      "static",
				AdminDistance: "1",
			},
		},
		Processes: []Process{
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
		Sessions: []Session{
			{
				User:      "admin",
				Line:      "vty 0",
				Location:  "192.168.1.100",
				IdleTime:  "00:05:23",
				LoginTime: "09:30:15",
				Protocol:  "ssh",
			},
		},
		Connections: []Connection{
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
		Metadata: CollectionMetadata{
			TotalCommands:      10,
			SuccessfulCommands: 9,
			FailedCommands:     1,
			CollectionDuration: "30.5s",
			Errors:             []string{"Command 'show invalid' failed"},
		},
	}

	// Test JSON marshaling
	jsonData, err := json.Marshal(deviceState)
	if err != nil {
		t.Fatalf("Failed to marshal DeviceState to JSON: %v", err)
	}

	// Test JSON unmarshaling
	var unmarshaledState DeviceState
	err = json.Unmarshal(jsonData, &unmarshaledState)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON to DeviceState: %v", err)
	}

	// Verify key fields
	if unmarshaledState.DeviceInfo.Hostname != deviceState.DeviceInfo.Hostname {
		t.Errorf("Expected hostname %s, got %s", deviceState.DeviceInfo.Hostname, unmarshaledState.DeviceInfo.Hostname)
	}

	if len(unmarshaledState.Interfaces) != len(deviceState.Interfaces) {
		t.Errorf("Expected %d interfaces, got %d", len(deviceState.Interfaces), len(unmarshaledState.Interfaces))
	}

	if len(unmarshaledState.Routes) != len(deviceState.Routes) {
		t.Errorf("Expected %d routes, got %d", len(deviceState.Routes), len(unmarshaledState.Routes))
	}
}

func TestInterface_Validation(t *testing.T) {
	tests := []struct {
		name      string
		iface     Interface
		expectErr bool
	}{
		{
			name: "Valid interface",
			iface: Interface{
				Name:        "GigabitEthernet0/0/0",
				Status:      "up",
				AdminStatus: "up",
				IPAddress:   "192.168.1.1",
				MACAddress:  "00:1a:2b:3c:4d:5e",
			},
			expectErr: false,
		},
		{
			name: "Empty interface name",
			iface: Interface{
				Name:        "",
				Status:      "up",
				AdminStatus: "up",
			},
			expectErr: false, // We don't currently validate this, but could add validation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON marshaling of individual interface
			jsonData, err := json.Marshal(tt.iface)
			if err != nil {
				t.Errorf("Failed to marshal interface: %v", err)
			}

			var unmarshaledIface Interface
			err = json.Unmarshal(jsonData, &unmarshaledIface)
			if err != nil {
				t.Errorf("Failed to unmarshal interface: %v", err)
			}

			if unmarshaledIface.Name != tt.iface.Name {
				t.Errorf("Expected name %s, got %s", tt.iface.Name, unmarshaledIface.Name)
			}
		})
	}
}

func TestRoute_Validation(t *testing.T) {
	route := Route{
		Destination:   "192.168.1.0/24",
		Gateway:       "192.168.1.254",
		Interface:     "eth0",
		Metric:        "100",
		Protocol:      "ospf",
		AdminDistance: "110",
	}

	jsonData, err := json.Marshal(route)
	if err != nil {
		t.Fatalf("Failed to marshal route: %v", err)
	}

	var unmarshaledRoute Route
	err = json.Unmarshal(jsonData, &unmarshaledRoute)
	if err != nil {
		t.Fatalf("Failed to unmarshal route: %v", err)
	}

	if unmarshaledRoute.Destination != route.Destination {
		t.Errorf("Expected destination %s, got %s", route.Destination, unmarshaledRoute.Destination)
	}

	if unmarshaledRoute.Protocol != route.Protocol {
		t.Errorf("Expected protocol %s, got %s", route.Protocol, unmarshaledRoute.Protocol)
	}
}

func TestSecurityInfo_ACLs(t *testing.T) {
	securityInfo := SecurityInfo{
		AccessLists: []AccessList{
			{
				Name:      "test-acl",
				Type:      "extended",
				Direction: "in",
				Interface: "GigabitEthernet0/0/0",
				Rules: []ACLRule{
					{
						Sequence:    "10",
						Action:      "permit",
						Protocol:    "tcp",
						Source:      "192.168.1.0/24",
						Destination: "any",
						Port:        "eq 80",
					},
					{
						Sequence:    "20",
						Action:      "deny",
						Protocol:    "ip",
						Source:      "any",
						Destination: "any",
					},
				},
			},
		},
	}

	jsonData, err := json.Marshal(securityInfo)
	if err != nil {
		t.Fatalf("Failed to marshal security info: %v", err)
	}

	var unmarshaledSecurity SecurityInfo
	err = json.Unmarshal(jsonData, &unmarshaledSecurity)
	if err != nil {
		t.Fatalf("Failed to unmarshal security info: %v", err)
	}

	if len(unmarshaledSecurity.AccessLists) != 1 {
		t.Errorf("Expected 1 access list, got %d", len(unmarshaledSecurity.AccessLists))
	}

	acl := unmarshaledSecurity.AccessLists[0]
	if len(acl.Rules) != 2 {
		t.Errorf("Expected 2 ACL rules, got %d", len(acl.Rules))
	}

	if acl.Rules[0].Action != "permit" {
		t.Errorf("Expected action 'permit', got '%s'", acl.Rules[0].Action)
	}

	if acl.Rules[1].Action != "deny" {
		t.Errorf("Expected action 'deny', got '%s'", acl.Rules[1].Action)
	}
}

func TestRawCommand_Structure(t *testing.T) {
	rawCmd := RawCommand{
		Command:     "show version",
		Output:      "Cisco IOS Software, Version 16.09.04",
		ErrorOutput: "",
		Timestamp:   time.Now(),
		Duration:    "2.0s",
	}

	jsonData, err := json.Marshal(rawCmd)
	if err != nil {
		t.Fatalf("Failed to marshal raw command: %v", err)
	}

	var unmarshaledCmd RawCommand
	err = json.Unmarshal(jsonData, &unmarshaledCmd)
	if err != nil {
		t.Fatalf("Failed to unmarshal raw command: %v", err)
	}

	if unmarshaledCmd.Command != rawCmd.Command {
		t.Errorf("Expected command %s, got %s", rawCmd.Command, unmarshaledCmd.Command)
	}

	if unmarshaledCmd.Output != rawCmd.Output {
		t.Errorf("Expected output %s, got %s", rawCmd.Output, unmarshaledCmd.Output)
	}
}

func TestCollectionMetadata_Statistics(t *testing.T) {
	metadata := CollectionMetadata{
		TotalCommands:      15,
		SuccessfulCommands: 13,
		FailedCommands:     2,
		CollectionDuration: "45.2s",
		Errors:             []string{"Command timeout", "Connection lost"},
	}

	// Test success rate calculation
	successRate := float64(metadata.SuccessfulCommands) / float64(metadata.TotalCommands) * 100
	expectedRate := 86.67 // 13/15 * 100

	if successRate < expectedRate-0.1 || successRate > expectedRate+0.1 {
		t.Errorf("Expected success rate ~%.2f%%, got %.2f%%", expectedRate, successRate)
	}

	// Test JSON serialization
	jsonData, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Failed to marshal metadata: %v", err)
	}

	var unmarshaledMetadata CollectionMetadata
	err = json.Unmarshal(jsonData, &unmarshaledMetadata)
	if err != nil {
		t.Fatalf("Failed to unmarshal metadata: %v", err)
	}

	if len(unmarshaledMetadata.Errors) != len(metadata.Errors) {
		t.Errorf("Expected %d errors, got %d", len(metadata.Errors), len(unmarshaledMetadata.Errors))
	}
}
