package simulator

import (
	"math/big"
	"net"

	"github.com/unpackdev/solgo/utils"
)

// StartOptions defines the configuration options for starting a simulation node.
// It includes settings for forking, networking, block number, and account impersonation.
type StartOptions struct {
	Fork            bool        `json:"fork"`             // Indicates whether to fork from an existing blockchain.
	ForkEndpoint    string      `json:"endpoint"`         // Endpoint URL for forking the blockchain.
	Addr            net.TCPAddr `json:"port"`             // TCP address for the node to listen on.
	BlockNumber     *big.Int    `json:"block_number"`     // Specific block number to start the simulation from.
	AutoImpersonate bool        `json:"auto_impersonate"` // Enables automatic impersonation of accounts.
}

// StopOptions defines the configuration options for stopping a simulation node.
// It includes a forceful stop option and specifies the node to stop by its port.
type StopOptions struct {
	Force bool `json:"force"` // Forcefully stops the node, potentially without cleanup.
	Port  int  `json:"port"`  // Specifies the port of the node to be stopped.
}

// Options encapsulates the general configuration settings for the simulator.
// It includes settings for the keystore, supported networks, faucet options, and default password.
type Options struct {
	Endpoint                    string          `json:"endpoint"`                       // Endpoint URL for interacting with the blockchain.
	KeystorePath                string          `json:"keystore_path"`                  // Filesystem path to the keystore directory.
	SupportedNetworks           []utils.Network `json:"supported_networks"`             // List of supported blockchain networks.
	FaucetsEnabled              bool            `json:"faucets_enabled"`                // Flag to enable or disable faucet functionality.
	FaucetsAutoReplenishEnabled bool            `json:"faucets_auto_replenish_enabled"` // Flag to enable or disable automatic replenishment of faucet accounts.
	FaucetAccountCount          int             `json:"auto_faucet_count"`              // Number of faucet accounts to create.
	FaucetAccountDefaultBalance *big.Int        `json:"auto_faucet_balance"`            // Default balance for each faucet account.
	DefaultPassword             string          `json:"default_password"`               // Default password for accounts managed by the simulator.
}
