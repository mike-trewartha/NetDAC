package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"netdac/internal/core"
	"netdac/internal/device/cisco"
	"netdac/internal/device/fortinet"
	"netdac/internal/device/juniper"
	"netdac/internal/device/paloalto"
	"netdac/internal/logger"
	"netdac/internal/output"

	"github.com/spf13/cobra"
)

var (
	// Collect command specific flags
	commandSet    string
	timeout       int
	retryAttempts int
	skipSSLVerify bool
)

// collectCmd represents the collect command
var collectCmd = &cobra.Command{
	Use:   "collect",
	Short: "Collect volatile state information from a network device",
	Long: `The collect command connects to a network device and executes a predefined
set of commands to capture volatile state information such as:
• Active network connections
• Routing tables  
• Process lists
• Current configurations
• Session tables
• Memory and CPU usage
• Interface statistics

The collected data is then parsed and normalized into a structured format.`,
	Example: `  # Collect from a Cisco IOS device
  netdac collect -t 192.168.1.1 -u admin -p password -v cisco-ios

  # Collect with custom command set and output to file
  netdac collect -t 10.0.0.1 -u user -v cisco-nxos --command-set full -o device_state.json

  # Collect from FortiGate with verbose output
  netdac collect -t firewall.example.com -u admin -v fortinet --verbose`,
	Run: runCollect,
}

func init() {
	// Command-specific flags
	collectCmd.Flags().StringVar(&commandSet, "command-set", "standard", "Command set to execute (minimal, standard, full)")
	collectCmd.Flags().IntVar(&timeout, "timeout", 30, "SSH connection timeout in seconds")
	collectCmd.Flags().IntVar(&retryAttempts, "retry", 3, "Number of retry attempts for failed commands")
	collectCmd.Flags().BoolVar(&skipSSLVerify, "skip-ssl-verify", false, "Skip SSL certificate and SSH host key verification")

	// Mark required flags for collect command only
	collectCmd.MarkFlagRequired("target")
	collectCmd.MarkFlagRequired("username")
	collectCmd.MarkFlagRequired("vendor")
}

func runCollect(cmd *cobra.Command, args []string) {
	// Validate required parameters
	if target == "" {
		logger.Fatal("required flag 'target' not set")
	}
	if username == "" {
		logger.Fatal("required flag 'username' not set")
	}
	if vendor == "" {
		logger.Fatal("required flag 'vendor' not set")
	}

	if verbose {
		logger.Info("Starting NetDAC collection",
			"target", target,
			"vendor", vendor,
			"output_format", outputFormat,
			"command_set", commandSet,
		)
	}

	// Handle authentication - SSH key takes precedence over password
	var authMethod string
	var sshKeyBytes []byte
	if sshKey != "" {
		authMethod = "ssh-key"
		if verbose {
			logger.Debug("Using SSH key authentication", "key_path", sshKey)
		}
		// Load SSH key bytes
		var err error
		sshKeyBytes, err = loadSSHKeyBytes(sshKey)
		if err != nil {
			logger.Fatal("Failed to load SSH key", "error", err)
		}
	} else if password != "" {
		authMethod = "password"
		if verbose {
			logger.Debug("Using password authentication")
		}
	} else {
		// Prompt for password if no SSH key provided
		var err error
		password, err = promptForPassword()
		if err != nil {
			logger.Fatal("Failed to read password", "error", err)
		}
		if password == "" {
			logger.Fatal("Password is required when SSH key is not provided")
		}
		authMethod = "password"
	}

	// Validate vendor
	if !isValidVendor(vendor) {
		logger.Fatal("Unsupported vendor",
			"vendor", vendor,
			"supported_vendors", strings.Join(getSupportedVendors(), ", "),
		)
	}

	// Validate output format
	if !isValidOutputFormat(outputFormat) {
		logger.Fatal("Unsupported output format",
			"format", outputFormat,
			"supported_formats", "json, yaml, csv",
		)
	}

	// Log connection attempt
	logger.Info("Connecting to device",
		"target", target,
		"vendor", vendor,
		"username", username,
		"auth_method", authMethod,
	)

	// Create and connect to device
	deviceCollector, err := createDeviceCollector(vendor, sshKeyBytes)
	if err != nil {
		logger.Fatal("Failed to create device collector", "error", err)
	}

	// Connect to device
	err = deviceCollector.Connect()
	if err != nil {
		logger.Fatal("Failed to connect to device", "error", err)
	}
	defer deviceCollector.Disconnect()

	// Validate connection
	err = deviceCollector.ValidateConnection()
	if err != nil {
		logger.Fatal("Connection validation failed", "error", err)
	}

	if verbose {
		logger.Info("Successfully connected and validated connection", "target", target)
	}

	// Execute collection
	logger.Info("Executing command set", "command_set", commandSet)
	deviceState, err := deviceCollector.Collect()
	if err != nil {
		logger.Fatal("Collection failed", "error", err)
	}

	if verbose {
		logger.Info("Collection completed",
			"successful_commands", deviceState.Metadata.SuccessfulCommands,
			"failed_commands", deviceState.Metadata.FailedCommands,
		)
		if len(deviceState.Metadata.Errors) > 0 {
			logger.Warn("Errors encountered during collection",
				"error_count", len(deviceState.Metadata.Errors),
				"errors", deviceState.Metadata.Errors,
			)
		}
	}

	// Format and output results
	err = outputResults(deviceState)
	if err != nil {
		logger.Fatal("Failed to output results", "error", err)
	}

	if verbose {
		logger.Info("Collection completed successfully")
	}
}

// isValidVendor checks if the specified vendor is supported
func isValidVendor(vendor string) bool {
	supportedVendors := getSupportedVendors()
	for _, v := range supportedVendors {
		if strings.EqualFold(vendor, v) {
			return true
		}
	}
	return false
}

// getSupportedVendors returns the list of supported vendors
func getSupportedVendors() []string {
	return []string{"cisco-ios", "cisco-ios-xe", "cisco-ios-xr", "cisco-nxos", "cisco-ftd", "cisco-asa", "cisco-fxos", "cisco-fpr4100-9300", "cisco-wlc-iosxe", "fortinet", "paloalto", "juniper"}
}

// isValidOutputFormat checks if the specified output format is supported
func isValidOutputFormat(format string) bool {
	supportedFormats := []string{"json", "yaml", "csv"}
	for _, f := range supportedFormats {
		if strings.EqualFold(format, f) {
			return true
		}
	}
	return false
}

// createDeviceCollector creates the appropriate device collector based on vendor
func createDeviceCollector(vendor string, sshKeyBytes []byte) (core.DeviceCollector, error) {
	connectionTimeout := time.Duration(timeout) * time.Second

	switch strings.ToLower(vendor) {
	case "cisco-ios":
		collector := cisco.NewIOSCollector(target, username, password, connectionTimeout)
		collector.CommandSet = commandSet
		collector.SetSkipHostKeyVerification(skipSSLVerify)
		if len(sshKeyBytes) > 0 {
			collector.SetSSHKey(sshKeyBytes)
		}
		return collector, nil
	case "cisco-ios-xe":
		collector := cisco.NewIOSXECollector(target, username, password, connectionTimeout)
		collector.CommandSet = commandSet
		collector.SetSkipHostKeyVerification(skipSSLVerify)
		if len(sshKeyBytes) > 0 {
			collector.SetSSHKey(sshKeyBytes)
		}
		return collector, nil
	case "cisco-ios-xr":
		collector := cisco.NewIOSXRCollector(target, username, password, connectionTimeout)
		collector.CommandSet = commandSet
		if len(sshKeyBytes) > 0 {
			collector.SetSSHKey(sshKeyBytes)
		}
		return collector, nil
	case "cisco-nxos":
		collector := cisco.NewNXOSCollector(target, username, password, connectionTimeout)
		collector.CommandSet = commandSet
		if len(sshKeyBytes) > 0 {
			collector.SetSSHKey(sshKeyBytes)
		}
		return collector, nil
	case "cisco-ftd":
		collector := cisco.NewFTDCollector(target, username, password, connectionTimeout)
		collector.CommandSet = commandSet
		return collector, nil
	case "cisco-asa":
		collector := cisco.NewASACollector(target, username, password, connectionTimeout)
		collector.CommandSet = commandSet
		return collector, nil
	case "cisco-fxos":
		collector := cisco.NewFXOSCollector(target, username, password, connectionTimeout)
		collector.SetCommandSet(commandSet)
		return collector, nil
	case "cisco-fpr4100-9300":
		collector := cisco.NewFPR4100_9300Collector(target, username, password, connectionTimeout)
		err := collector.SetCommandSet(commandSet)
		if err != nil {
			return nil, fmt.Errorf("failed to set command set: %v", err)
		}
		return collector, nil
	case "cisco-wlc-iosxe":
		collector := cisco.NewWLCIOSXECollector(target, username, password, connectionTimeout)
		err := collector.SetCommandSet(commandSet)
		if err != nil {
			return nil, fmt.Errorf("failed to set command set: %v", err)
		}
		return collector, nil
	case "fortinet":
		collector := fortinet.NewFortiOSCollector(target, username, password, connectionTimeout)
		collector.CommandSet = commandSet
		return collector, nil
	case "paloalto":
		collector := paloalto.NewPANOSCollector(target, username, password, connectionTimeout)
		collector.CommandSet = commandSet
		return collector, nil
	case "juniper":
		collector := juniper.NewJunOSCollector(target, username, password, connectionTimeout)
		collector.CommandSet = commandSet
		collector.SetSkipHostKeyVerification(skipSSLVerify)
		if len(sshKeyBytes) > 0 {
			collector.SetSSHKey(sshKeyBytes)
		}
		return collector, nil
	default:
		return nil, fmt.Errorf("unsupported vendor: %s", vendor)
	}
}

// outputResults formats and outputs the collected device state
func outputResults(deviceState *core.DeviceState) error {
	var err error

	switch strings.ToLower(outputFormat) {
	case "json":
		formatter := output.NewJSONFormatter(true, verbose) // pretty print = true, include raw = verbose
		if outputFile != "" {
			err = formatter.WriteToFile(deviceState, outputFile)
		} else {
			err = formatter.Format(deviceState, os.Stdout)
		}
	case "yaml":
		formatter := output.NewYAMLFormatter(verbose) // include raw = verbose
		if outputFile != "" {
			err = formatter.WriteToFile(deviceState, outputFile)
		} else {
			err = formatter.Format(deviceState, os.Stdout)
		}
	case "csv":
		formatter := output.NewCSVFormatter(true, ',', "all") // headers = true, comma separator, all data
		if outputFile != "" {
			err = formatter.WriteToFile(deviceState, outputFile)
		} else {
			err = formatter.Format(deviceState, os.Stdout)
		}
	default:
		return fmt.Errorf("unsupported output format: %s", outputFormat)
	}

	return err
}

// loadSSHKeyBytes loads SSH private key bytes from file
func loadSSHKeyBytes(keyPath string) ([]byte, error) {
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

	return keyBytes, nil
}
