package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"netdac/internal/logger"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

var (
	// Global flags
	target       string
	username     string
	password     string
	sshKey       string
	vendor       string
	outputFormat string
	outputFile   string
	verbose      bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "netdac",
	Short: "Network Device Artifact Collector - Forensically Sound Data Collection",
	Long: `NetDAC (Network Device Artifact Collector) is a CLI tool for rapid, forensically 
sound collection of volatile state information from various network devices.

This tool helps incident responders by:
• Multi-Vendor Support: Connect to different network device types (Cisco IOS/NX-OS, FortiGate, Palo Alto PAN-OS)
• Automated Data Collection: Execute pre-defined sets of commands to capture volatile data
• Output Normalization: Parse vendor-specific command output into unified, structured format
• Forensic Compliance: Follow official vendor forensic procedures where available`,
	Version: "1.0.0",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// Global persistent flags
	rootCmd.PersistentFlags().StringVarP(&target, "target", "t", "", "Target device IP address or hostname (required)")
	rootCmd.PersistentFlags().StringVarP(&username, "username", "u", "", "Username for device authentication (required)")
	rootCmd.PersistentFlags().StringVarP(&password, "password", "p", "", "Password for device authentication (optional - will prompt if not provided)")
	rootCmd.PersistentFlags().StringVarP(&sshKey, "ssh-key", "k", "", "Path to SSH private key file for authentication")
	rootCmd.PersistentFlags().StringVarP(&vendor, "vendor", "v", "", "Device vendor (cisco-ios, cisco-ios-xe, cisco-ios-xr, cisco-nxos, cisco-ftd, cisco-asa, cisco-fxos, cisco-fpr4100-9300, cisco-wlc-iosxe, fortinet, paloalto, juniper)")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output-format", "f", "json", "Output format (json, yaml, csv)")
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "Output file path (default: stdout)")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "Enable verbose output")

	// Add subcommands
	rootCmd.AddCommand(collectCmd)

	// Configure completion command to not inherit required flags
	rootCmd.CompletionOptions.DisableDefaultCmd = false
}

func main() {
	// Initialize logger based on verbose flag
	logLevel := logger.LevelInfo
	if verbose {
		logLevel = logger.LevelDebug
	}
	logger.Init(logLevel, verbose)

	Execute()
}

// promptForPassword securely prompts the user for a password
func promptForPassword() (string, error) {
	fmt.Print("Enter password: ")

	// Check if stdin is a terminal
	if !term.IsTerminal(int(syscall.Stdin)) {
		// If not a terminal (e.g., piped input), read normally
		var password string
		_, err := fmt.Scanln(&password)
		return password, err
	}

	// Get the file descriptor for stdin
	fd := int(syscall.Stdin)

	// Read password without echo
	bytePassword, err := term.ReadPassword(fd)
	fmt.Println() // Print a newline after password input

	if err != nil {
		return "", fmt.Errorf("failed to read password: %v", err)
	}

	return string(bytePassword), nil
}

// loadSSHPrivateKey loads an SSH private key from a file
func loadSSHPrivateKey(keyPath string) (ssh.Signer, error) {
	// Expand tilde to home directory
	if strings.HasPrefix(keyPath, "~/") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %v", err)
		}
		keyPath = filepath.Join(homeDir, keyPath[2:])
	}

	// Read the private key file
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read SSH key file %s: %v", keyPath, err)
	}

	// Parse the private key
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		// Try parsing as encrypted key
		block, _ := pem.Decode(keyBytes)
		if block == nil {
			return nil, fmt.Errorf("failed to parse PEM block from SSH key")
		}

		// Check if key is encrypted
		if x509.IsEncryptedPEMBlock(block) {
			// Prompt for passphrase
			fmt.Print("Enter passphrase for SSH key: ")
			passphrase, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				return nil, fmt.Errorf("failed to read passphrase: %v", err)
			}

			// Decrypt the key
			decryptedKey, err := x509.DecryptPEMBlock(block, passphrase)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt SSH key: %v", err)
			}

			// Parse the decrypted key
			signer, err = ssh.ParsePrivateKey(pem.EncodeToMemory(&pem.Block{
				Type:  block.Type,
				Bytes: decryptedKey,
			}))
			if err != nil {
				return nil, fmt.Errorf("failed to parse decrypted SSH key: %v", err)
			}
		} else {
			return nil, fmt.Errorf("failed to parse SSH key: %v", err)
		}
	}

	return signer, nil
}

// getDefaultSSHKeyPaths returns common SSH key file paths
func getDefaultSSHKeyPaths() []string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return []string{}
	}

	sshDir := filepath.Join(homeDir, ".ssh")
	return []string{
		filepath.Join(sshDir, "id_rsa"),
		filepath.Join(sshDir, "id_ecdsa"),
		filepath.Join(sshDir, "id_ed25519"),
		filepath.Join(sshDir, "id_dsa"),
	}
}

// findDefaultSSHKey attempts to find a default SSH key
func findDefaultSSHKey() (string, error) {
	keyPaths := getDefaultSSHKeyPaths()

	for _, keyPath := range keyPaths {
		if _, err := os.Stat(keyPath); err == nil {
			return keyPath, nil
		}
	}

	return "", fmt.Errorf("no default SSH key found in ~/.ssh/")
}
