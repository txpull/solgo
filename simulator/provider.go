package simulator

import (
	"context"
	"math/big"

	"github.com/unpackdev/solgo/clients"
	"github.com/unpackdev/solgo/utils"
)

// Provider defines an interface for simulation providers in the simulator package.
// It includes a set of methods for managing and interacting with simulated blockchain nodes,
// clients, and related resources. Each method in the interface serves a specific purpose in
// the lifecycle and operation of a simulation environment.
type Provider interface {
	// Name returns the name of the simulation provider.
	Name() string

	// Network returns the blockchain network associated with the provider.
	Network() utils.Network

	// NetworkID returns the network ID associated with the provider.
	NetworkID() utils.NetworkID

	// Type returns the type of the simulation provider.
	Type() utils.SimulatorType

	// GetCmdArguments returns the command line arguments for the simulation provider.
	GetCmdArguments(node *Node) []string

	// Load initializes the provider and loads necessary resources.
	Load(context.Context) error

	// Unload releases resources and performs cleanup for the provider.
	Unload(context.Context) error

	// SetupFaucetAccounts sets up faucet accounts for a given simulation node.
	SetupFaucetAccounts(context.Context, *Node) error

	// Start initiates a new simulation node with the specified options.
	Start(ctx context.Context, opts StartOptions) (*Node, error)

	// Stop terminates a simulation node based on provided options.
	Stop(context.Context, StopOptions) error

	// Status retrieves the status of all simulation nodes managed by the provider.
	Status(context.Context) ([]*NodeStatus, error)

	// GetNodes returns a map of all currently active simulation nodes.
	GetNodes() map[uint64]*Node

	// GetNodeByBlockNumber retrieves a simulation node by its block number.
	GetNodeByBlockNumber(*big.Int) (*Node, bool)

	// GetNodeByPort finds a simulation node based on its port number.
	GetNodeByPort(int) (*Node, bool)

	// GetClientByGroupAndType retrieves a client based on the simulation type and group identifier.
	GetClientByGroupAndType(utils.SimulatorType, string) (*clients.Client, bool)

	// GetClientPool returns the client pool associated with the provider.
	GetClientPool() *clients.ClientPool
}
