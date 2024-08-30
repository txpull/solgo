package simulator

import (
	"fmt"
	"net"

	"github.com/unpackdev/solgo/utils"
)

const (
	// MaxAnvilSimulatedClients defines the maximum number of clients that can be simulated.
	MaxAnvilSimulatedClients = 100
)

// AnvilProviderOptions defines the configuration options for an Anvil simulator provider.
// These options specify how the Anvil nodes should be set up and run, including network
// settings, client counts, executable paths, and forking options.
type AnvilProviderOptions struct {
	Network             utils.Network   `json:"network"`
	NetworkID           utils.NetworkID `json:"network_id"`
	ClientCount         int32           `json:"client_count"`
	MaxClientCount      int32           `json:"max_client_count"`
	IPAddr              net.IP          `json:"ip_addr"`
	StartPort           int             `json:"start_port"`
	EndPort             int             `json:"end_port"`
	PidPath             string          `json:"pid_path"`
	AnvilExecutablePath string          `json:"anvil_binary_path"`
	Fork                bool            `json:"fork"`
	ForkEndpoint        string          `json:"fork_endpoint"`
	AutoImpersonate     bool            `json:"auto_impersonate"`
}

// Validate checks the validity of the AnvilProviderOptions. It ensures that all necessary
// configurations are set correctly and within acceptable ranges. This includes checking
// client counts, path existence, network settings, and port configurations.
// Returns an error if any validation check fails.
func (a *AnvilProviderOptions) Validate() error {
	if a.MaxClientCount > MaxAnvilSimulatedClients {
		return fmt.Errorf("max simulated clients must be less then %d", MaxAnvilSimulatedClients)
	}

	if a.ClientCount > a.MaxClientCount {
		return fmt.Errorf("simulated clients must be less than or equal to max simulated clients")
	}

	if a.PidPath == "" {
		return fmt.Errorf("pid path must be provided")
	} else {
		if !utils.PathExists(a.PidPath) {
			return fmt.Errorf("pid path does not exist: %s", a.PidPath)
		}
	}

	if a.AnvilExecutablePath == "" {
		return fmt.Errorf("anvil executable path must be provided")
	} else {
		if !utils.PathExists(a.AnvilExecutablePath) {
			return fmt.Errorf("anvil executable path does not exist: %s", a.AnvilExecutablePath)
		}
	}

	if a.Fork {
		if a.ClientCount > 1 {
			return fmt.Errorf("initial forking is only supported with a single client. Remaining will be spawned as needed")
		}

		if a.ForkEndpoint == "" {
			return fmt.Errorf("fork endpoint must be provided")
		}
	}

	if a.IPAddr.String() == "" {
		return fmt.Errorf("ip address must be provided")
	}

	if a.StartPort < 2000 || a.StartPort > 65535 {
		return fmt.Errorf("start port must be between 2000 and 65535")
	}

	if a.EndPort < a.StartPort+1 || a.EndPort > 65535 {
		return fmt.Errorf("end port must be between %d and 65535", a.StartPort+1)
	}

	return nil
}
