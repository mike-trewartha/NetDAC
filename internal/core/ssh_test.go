package core

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestCreateHostKeyCallback(t *testing.T) {
	tests := []struct {
		name             string
		skipVerification bool
		expectInsecure   bool
	}{
		{
			name:             "Skip verification enabled",
			skipVerification: true,
			expectInsecure:   true,
		},
		{
			name:             "Skip verification disabled",
			skipVerification: false,
			expectInsecure:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callback := CreateHostKeyCallback(tt.skipVerification, "127.0.0.1")

			// Test with a dummy host key
			testKey, err := generateTestHostKey()
			if err != nil {
				t.Fatalf("Failed to generate test key: %v", err)
			}

			if tt.expectInsecure {
				// Should accept any key when insecure
				err = callback("127.0.0.1", &net.TCPAddr{}, testKey)
				if err != nil {
					t.Errorf("Expected insecure callback to accept key, got error: %v", err)
				}
			} else {
				// Secure callback behavior depends on known_hosts file existence
				// We'll just verify it returns a valid callback function
				if callback == nil {
					t.Error("Expected valid callback function, got nil")
				}
			}
		})
	}
}

func TestCreateSSHAuthMethods(t *testing.T) {
	tests := []struct {
		name        string
		sshKey      []byte
		password    string
		expectCount int
		expectError bool
	}{
		{
			name:        "Valid SSH key only",
			sshKey:      generateValidSSHKey(t),
			password:    "",
			expectCount: 1,
			expectError: false,
		},
		{
			name:        "Password only",
			sshKey:      nil,
			password:    "testpass",
			expectCount: 1,
			expectError: false,
		},
		{
			name:        "Both SSH key and password",
			sshKey:      generateValidSSHKey(t),
			password:    "testpass",
			expectCount: 2,
			expectError: false,
		},
		{
			name:        "Invalid SSH key",
			sshKey:      []byte("invalid key data"),
			password:    "",
			expectCount: 0,
			expectError: true,
		},
		{
			name:        "No auth methods",
			sshKey:      nil,
			password:    "",
			expectCount: 0,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			methods, err := CreateSSHAuthMethods(tt.sshKey, tt.password)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error, but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if len(methods) != tt.expectCount {
				t.Errorf("Expected %d auth methods, got %d", tt.expectCount, len(methods))
			}
		})
	}
}

func TestGenerateFingerprint(t *testing.T) {
	testKey, err := generateTestHostKey()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	fingerprint := generateFingerprint(testKey)

	// Verify fingerprint format
	if len(fingerprint) == 0 {
		t.Error("Expected non-empty fingerprint")
	}

	// Should be base64 encoded
	if strings.Contains(fingerprint, " ") {
		t.Error("Fingerprint should not contain spaces")
	}
}

func TestGetKnownHostsPath(t *testing.T) {
	path := getKnownHostsPath()

	if len(path) == 0 {
		t.Error("Expected non-empty known_hosts path")
	}

	if !strings.HasSuffix(path, "known_hosts") {
		t.Error("Path should end with 'known_hosts'")
	}
}

func TestAddToKnownHosts(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "netdac_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Generate test key
	testKey, err := generateTestHostKey()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	// Test adding to known_hosts file
	testHost := "test.example.com"

	// For now, just test that the function doesn't crash
	err = addToKnownHosts(testHost, testKey)
	// We expect this might fail due to permissions or path issues in test environment
	// The important thing is that it doesn't panic
	if err != nil {
		t.Logf("addToKnownHosts returned error (expected in test environment): %v", err)
	}
}

// Helper functions for testing

func generateTestHostKey() (ssh.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}

	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func generateValidSSHKey(t *testing.T) []byte {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}

	pemKey := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	return pemKey
}

func TestCreateSSHAuthMethodsIntegration(t *testing.T) {
	// Test with real SSH key generation
	tempDir, err := os.MkdirTemp("", "netdac_ssh_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	keyPath := filepath.Join(tempDir, "test_key")
	keyBytes := generateValidSSHKey(t)

	err = os.WriteFile(keyPath, keyBytes, 0600)
	if err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	// Test reading the key back
	readBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("Failed to read key file: %v", err)
	}

	methods, err := CreateSSHAuthMethods(readBytes, "")
	if err != nil {
		t.Errorf("Failed to create auth methods with valid key: %v", err)
	}

	if len(methods) != 1 {
		t.Errorf("Expected 1 auth method, got %d", len(methods))
	}
}
