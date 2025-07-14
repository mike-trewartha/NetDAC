package core

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// CreateHostKeyCallback creates an appropriate SSH host key callback based on verification settings
func CreateHostKeyCallback(skipVerification bool, target string) ssh.HostKeyCallback {
	if skipVerification {
		return ssh.InsecureIgnoreHostKey()
	}

	// Try to use known_hosts file for verification
	knownHostsPath := getKnownHostsPath()
	if _, err := os.Stat(knownHostsPath); err == nil {
		callback, err := knownhosts.New(knownHostsPath)
		if err == nil {
			return callback
		}
	}

	// Fall back to interactive verification with fingerprint display
	return createInteractiveHostKeyCallback(target)
}

// getKnownHostsPath returns the path to the SSH known_hosts file
func getKnownHostsPath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(homeDir, ".ssh", "known_hosts")
}

// createInteractiveHostKeyCallback creates a callback that prompts for host key verification
func createInteractiveHostKeyCallback(target string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fingerprint := generateFingerprint(key)
		keyType := key.Type()

		fmt.Printf("\nWarning: The authenticity of host '%s (%s)' can't be established.\n", hostname, remote.String())
		fmt.Printf("%s key fingerprint is SHA256:%s\n", keyType, fingerprint)
		fmt.Print("Are you sure you want to continue connecting (yes/no)? ")

		var response string
		fmt.Scanln(&response)
		response = strings.ToLower(strings.TrimSpace(response))

		if response == "yes" || response == "y" {
			// Optionally add to known_hosts file
			if err := addToKnownHosts(hostname, key); err != nil {
				fmt.Printf("Warning: Failed to add host key to known_hosts: %v\n", err)
			}
			return nil
		}

		return fmt.Errorf("host key verification failed: user rejected connection")
	}
}

// generateFingerprint generates a SHA256 fingerprint for the host key
func generateFingerprint(key ssh.PublicKey) string {
	hash := sha256.Sum256(key.Marshal())
	return base64.StdEncoding.EncodeToString(hash[:])
}

// addToKnownHosts adds a host key to the known_hosts file
func addToKnownHosts(hostname string, key ssh.PublicKey) error {
	knownHostsPath := getKnownHostsPath()

	// Create .ssh directory if it doesn't exist
	sshDir := filepath.Dir(knownHostsPath)
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return err
	}

	// Open known_hosts file for appending
	file, err := os.OpenFile(knownHostsPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	// Format: hostname key_type key_data
	line := fmt.Sprintf("%s %s %s\n", hostname, key.Type(), base64.StdEncoding.EncodeToString(key.Marshal()))
	_, err = file.WriteString(line)
	return err
}

// CreateSSHAuthMethods creates SSH authentication methods from key and/or password
func CreateSSHAuthMethods(sshKey []byte, password string) ([]ssh.AuthMethod, error) {
	var authMethods []ssh.AuthMethod

	// Add SSH key authentication if provided
	if len(sshKey) > 0 {
		signer, err := ssh.ParsePrivateKey(sshKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse SSH private key: %v", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	// Add password authentication if provided
	if password != "" {
		authMethods = append(authMethods, ssh.Password(password))
	}

	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no authentication methods provided")
	}

	return authMethods, nil
}
