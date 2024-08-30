package simulator

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/unpackdev/solgo/accounts"
	"github.com/unpackdev/solgo/bindings"
	"github.com/unpackdev/solgo/clients"
	"github.com/unpackdev/solgo/utils"
	"go.uber.org/zap"
)

// AnvilProvider is a component of the simulator that manages blockchain simulation nodes.
// It holds a reference to the simulation context, various options for the provider, and
// manages a collection of active nodes and a client pool.
type AnvilProvider struct {
	ctx            context.Context       // The context for managing the lifecycle of the provider.
	opts           *AnvilProviderOptions // Configuration options for the Anvil provider.
	nodes          map[uint64]*Node      // Collection of active simulation nodes.
	mu             sync.Mutex            // Mutex for managing concurrent access to the provider.
	pool           *clients.ClientPool   // Client pool for managing simulated clients.
	simulator      *Simulator            // Reference to the parent Simulator.
	bindingManager *bindings.Manager     // Binding manager for managing contract bindings.
}

// NewAnvilProvider initializes a new instance of AnvilProvider with the given context,
// simulator reference, and options. It validates the provided options and sets up
// the initial state for the provider.
func NewAnvilProvider(ctx context.Context, simulator *Simulator, opts *AnvilProviderOptions) (Provider, error) {
	if opts == nil {
		return nil, fmt.Errorf("in order to create a new anvil provider, you must provide options")
	}

	if simulator == nil {
		return nil, fmt.Errorf("in order to create a new anvil provider, you must provide a simulator")
	}

	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("failed to validate anvil provider options: %s", err)
	}

	provider := &AnvilProvider{
		ctx:       ctx,
		opts:      opts,
		pool:      simulator.GetClientPool(),
		simulator: simulator,
		nodes:     make(map[uint64]*Node),
		mu:        sync.Mutex{},
	}

	return provider, nil
}

// GetBindingManager returns the binding manager associated with the AnvilProvider.
func (a *AnvilProvider) GetBindingManager() *bindings.Manager {
	return a.bindingManager
}

// SetBindingManager sets the binding manager associated with the AnvilProvider.
func (a *AnvilProvider) SetBindingManager(bindingManager *bindings.Manager) {
	a.bindingManager = bindingManager
}

// Name returns a human-readable name for the AnvilProvider.
func (a *AnvilProvider) Name() string {
	return "Foundry Anvil Node Simulator"
}

// Network returns the network type associated with the AnvilProvider.
func (a *AnvilProvider) Network() utils.Network {
	return utils.AnvilNetwork
}

// Type returns the simulator type for the AnvilProvider.
func (a *AnvilProvider) Type() utils.SimulatorType {
	return utils.AnvilSimulator
}

// NetworkID returns the network ID associated with the AnvilProvider.
func (a *AnvilProvider) NetworkID() utils.NetworkID {
	return a.opts.NetworkID
}

// GetCmdArguments builds the command-line arguments for starting the node...
// @TODO: Fetch arguments based on provider, not just for Anvil.
func (a *AnvilProvider) GetCmdArguments(node *Node) []string {
	args := []string{
		"--auto-impersonate",
		"--accounts", "0",
		"--host", node.Addr.IP.String(),
		"--port", fmt.Sprintf("%d", node.Addr.Port),
	}

	ipcPath := filepath.Join(node.IpcPath, fmt.Sprintf("anvil.%d.ipc", node.Addr.Port))
	args = append(args, "--ipc", ipcPath)

	if node.Fork {
		args = append(args, "--fork-url", node.ForkEndpoint)
		args = append(args, "--chain-id", fmt.Sprintf("%d", node.GetProvider().NetworkID()))
	}

	if node.BlockNumber != nil {
		args = append(args, "--fork-block-number", node.BlockNumber.String())
	}

	return args
}

// Load initializes and loads the Anvil simulation nodes. It ensures that existing nodes
// are properly managed and new nodes are created as needed. It is crucial for avoiding
// zombie processes and ensuring a clean simulation environment.
func (a *AnvilProvider) Load(ctx context.Context) error {

	// Lets go through process of shutting down any existing zombie nodes...
	if err := a.ResolveZombieNodes(ctx); err != nil {
		return fmt.Errorf("failed to resolve zombie nodes: %w", err)
	}

	// Now we are going to load remaining of the nodes that are not running yet.
	if remainingClientsCount := a.NeedClients(); remainingClientsCount > 0 {
		for i := 0; i < remainingClientsCount; i++ {
			port := a.GetNextPort()
			if port == 0 {
				return fmt.Errorf("no available ports to start anvil nodes")
			}

			startOpts := StartOptions{
				Fork:         a.opts.Fork,
				ForkEndpoint: a.opts.ForkEndpoint,
				Addr: net.TCPAddr{
					IP:   a.opts.IPAddr,
					Port: port,
				},
			}

			node, err := a.Start(ctx, startOpts)
			if err != nil {
				return fmt.Errorf("failed to spawn anvil node: %w", err)
			}

			// Lets now load faucet accounts for the newly spawned node
			if a.simulator.opts.FaucetsEnabled {
				if a.simulator.opts.FaucetsAutoReplenishEnabled {
					if err := a.SetupFaucetAccounts(ctx, node); err != nil {
						return fmt.Errorf("failed to load faucet accounts: %w", err)
					}
				}
			}
		}
	}

	return nil
}

// Unload stops and cleans up all Anvil simulation nodes managed by the provider.
func (a *AnvilProvider) Unload(ctx context.Context) error {
	for _, node := range a.nodes {
		if err := node.Stop(ctx, false); err != nil {
			return fmt.Errorf("failed to stop anvil node: %s", err)
		}
	}

	return nil
}

// Start initializes and starts a new simulation node with the given options.
func (a *AnvilProvider) Start(ctx context.Context, opts StartOptions) (*Node, error) {
	if node, ok := a.nodes[uint64(opts.Addr.Port)]; ok {
		return node, nil
	}

	node := &Node{
		provider:        a,
		simulator:       a.simulator,
		ID:              uuid.New(),
		Addr:            opts.Addr,
		IpcPath:         a.opts.PidPath,
		PidPath:         a.opts.PidPath,
		AutoImpersonate: a.opts.AutoImpersonate,
		ExecutablePath:  a.opts.AnvilExecutablePath,
		Fork:            a.opts.Fork,
		ForkEndpoint:    a.opts.ForkEndpoint,
		BlockNumber:     opts.BlockNumber,
	}

	// Ability to override the fork defaults if needed
	if opts.Fork {
		node.Fork = opts.Fork
		node.ForkEndpoint = opts.ForkEndpoint
	}

	// Ability to override the auto impersonate defaults if needed
	if opts.AutoImpersonate {
		node.AutoImpersonate = opts.AutoImpersonate
	}

	if err := node.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start anvil node: %w", err)
	}

	zap.L().Info(
		"Anvil node successfully started",
		zap.String("id", node.GetID().String()),
		zap.String("addr", node.Addr.String()),
		zap.String("network", node.GetProvider().Network().String()),
		zap.Any("network_id", node.GetProvider().NetworkID()),
		zap.Uint64("block_number", node.BlockNumber.Uint64()),
	)

	// Lets register the node with the client pool
	err := a.pool.RegisterClient(
		ctx,
		uint64(a.NetworkID()),
		utils.AnvilSimulator.String(),
		node.GetID().String(),
		node.GetNodeAddr(),
		1, // We are going to have only one concurrent client per node
	)

	if err != nil {
		return nil, fmt.Errorf(
			"failed to register client with client pool: %s",
			err.Error(),
		)
	}

	a.mu.Lock()
	if _, ok := a.nodes[opts.BlockNumber.Uint64()]; !ok {
		a.nodes[opts.BlockNumber.Uint64()] = node
	}
	a.mu.Unlock()

	return node, nil
}

// Stop terminates a simulation node based on the provided StopOptions.
func (a *AnvilProvider) Stop(ctx context.Context, opts StopOptions) error {
	if node, found := a.GetNodeByPort(opts.Port); found {
		if err := node.Stop(ctx, opts.Force); err != nil {
			return fmt.Errorf("failed to stop anvil node: %s", err)
		}
	}
	return nil
}

// Status retrieves the status of all simulation nodes managed by the provider.
func (a *AnvilProvider) Status(ctx context.Context) ([]*NodeStatus, error) {
	var statuses []*NodeStatus

	zap.L().Debug(
		"Checking up on Anvil nodes status...",
		zap.String("network", a.Network().String()),
		zap.Any("network_id", a.NetworkID()),
	)

	for _, node := range a.nodes {
		if status, err := node.Status(ctx); err != nil {
			return nil, err
		} else {
			statuses = append(statuses, status)
		}
	}

	return statuses, nil
}

// SetupFaucetAccounts prepares faucet accounts for a given simulation node in the AnvilProvider.
//
// This function is responsible for initializing and setting up faucet accounts that are essential for simulating
// blockchain transactions. It is typically used in testing environments where simulated accounts with pre-filled
// balances are required.
func (a *AnvilProvider) SetupFaucetAccounts(ctx context.Context, node *Node) error {
	zap.L().Info(
		"Loading faucet accounts...",
		zap.String("id", node.GetID().String()),
		zap.String("addr", node.Addr.String()),
		zap.String("network", node.GetProvider().Network().String()),
		zap.Any("network_id", node.GetProvider().NetworkID()),
		zap.Uint64("block_number", node.BlockNumber.Uint64()),
	)

	wg := sync.WaitGroup{}

	for _, address := range a.simulator.faucets.List(a.Network()) {
		wg.Add(1)

		client := a.pool.GetClient(utils.AnvilSimulator.String(), node.GetID().String())
		address.SetClient(client)

		go func(address *accounts.Account) {

			defer wg.Done()
			if err := address.SetAccountBalance(ctx, a.simulator.opts.FaucetAccountDefaultBalance); err != nil {
				zap.L().Error(
					fmt.Sprintf("failure to set account balance: %s", err.Error()),
					zap.String("account", address.GetAddress().String()),
					zap.String("id", node.GetID().String()),
					zap.String("addr", node.Addr.String()),
					zap.String("network", node.GetProvider().Network().String()),
					zap.Any("network_id", node.GetProvider().NetworkID()),
					zap.Uint64("block_number", node.BlockNumber.Uint64()),
				)
			}

			for i := 0; i < 2; i++ {
				balance, err := address.Balance(ctx, nil)
				if err != nil {
					zap.L().Error(
						fmt.Sprintf("failure to get account balance: %s", err.Error()),
						zap.String("account", address.GetAddress().String()),
						zap.String("id", node.GetID().String()),
						zap.String("addr", node.Addr.String()),
						zap.String("network", node.GetProvider().Network().String()),
						zap.Any("network_id", node.GetProvider().NetworkID()),
						zap.Uint64("block_number", node.BlockNumber.Uint64()),
					)
					time.Sleep(500 * time.Millisecond)
					continue
				}

				if balance.Cmp(a.simulator.opts.FaucetAccountDefaultBalance) != 0 {
					zap.L().Debug(
						"Account balance successfully set",
						zap.String("account", address.GetAddress().String()),
						zap.String("id", node.GetID().String()),
						zap.String("addr", node.Addr.String()),
						zap.String("network", node.GetProvider().Network().String()),
						zap.Any("network_id", node.GetProvider().NetworkID()),
						zap.Uint64("block_number", node.BlockNumber.Uint64()),
						zap.String("balance", balance.String()),
					)
					time.Sleep(500 * time.Millisecond)
					continue
				}

				break
			}
		}(address)
	}

	wg.Wait()

	return nil
}

// GetNodes returns a map of all currently active simulation nodes managed by the AnvilProvider.
func (a *AnvilProvider) GetNodes() map[uint64]*Node {
	return a.nodes
}

// GetNodeByBlockNumber retrieves a simulation node corresponding to a specific block number.
// Returns the node and a boolean indicating whether such a node was found.
func (a *AnvilProvider) GetNodeByBlockNumber(blockNumber *big.Int) (*Node, bool) {
	if blockNumber == nil {
		return nil, false
	}

	node, ok := a.nodes[blockNumber.Uint64()]
	return node, ok
}

// GetNodeByPort searches for a simulation node by its port number.
// Returns the node and a boolean indicating whether a node with the given port was found.
func (a *AnvilProvider) GetNodeByPort(port int) (*Node, bool) {
	for _, node := range a.nodes {
		if node.Addr.Port == port {
			return node, true
		}
	}
	return nil, false
}

// GetClientByGroupAndType retrieves a client from the client pool based on the given simulator type and group.
// Returns the client and a boolean indicating whether the client was found.
func (a *AnvilProvider) GetClientByGroupAndType(simulatorType utils.SimulatorType, group string) (*clients.Client, bool) {
	if client := a.pool.GetClientByGroupAndType(simulatorType.String(), group); client != nil {
		return client, true
	}

	return nil, false
}

// GetClientPool returns the client pool associated with the AnvilProvider.
func (a *AnvilProvider) GetClientPool() *clients.ClientPool {
	return a.pool
}

// NeedClients calculates the number of additional clients needed to reach the desired client count.
// Returns the number of additional clients required.
func (a *AnvilProvider) NeedClients() int {
	return int(a.opts.ClientCount) - len(a.nodes)
}

// PortAvailable checks if a specific port is available both in the simulation nodes
// and on the OS level. Returns true if the port is available, false otherwise.
func (a *AnvilProvider) PortAvailable(port int) bool {
	// First, check if the port is in use by any simulation node.
	if _, ok := a.GetNodeByPort(port); ok {
		return false
	}

	// Now, check if the port is available on the OS.
	address := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		// If there is an error opening the listener, the port is not available.
		return false
	}

	// Don't forget to close the listener if the port is available.
	listener.Close()

	return true
}

// GetNextPort identifies the next available port within the specified port range in the provider options.
// Returns the next available port number or 0 if no ports are available.
func (a *AnvilProvider) GetNextPort() int {
	for i := a.opts.StartPort; i <= a.opts.EndPort; i++ {
		if a.PortAvailable(i) {
			return i
		}
	}
	return 0
}

func (a *AnvilProvider) ResolveZombieNodes(ctx context.Context) error {
	pidPath := a.opts.PidPath
	files, err := os.ReadDir(pidPath)
	if err != nil {
		return fmt.Errorf("failed to read simulator processes directory: %w", err)
	}

	for _, file := range files {
		if filepath.Ext(file.Name()) != ".json" {
			continue
		}

		filePath := filepath.Join(pidPath, file.Name())
		fileBytes, err := os.ReadFile(filePath)
		if err != nil {
			zap.L().Error("Failed to read zombie simulator node file", zap.String("path", filePath), zap.Error(err))
			continue
		}

		var node *Node

		if err := json.Unmarshal(fileBytes, &node); err != nil {
			zap.L().Error("Failed to unmarshal zombie simulator node file", zap.String("path", filePath), zap.Error(err))
			continue
		}

		if process, err := os.FindProcess(node.PID); err == nil {
			if err := process.Signal(syscall.SIGTERM); err == nil {
				zap.L().Info(
					"Successfully terminated zombie simulator node",
					zap.String("path", filePath),
					zap.Any("pid", node.PID),
					zap.Any("network", utils.AnvilNetwork),
				)
			}
		}

		pidFileName := fmt.Sprintf("anvil.%d.pid.json", node.Addr.Port)
		if err := os.Remove(filepath.Join(node.PidPath, pidFileName)); err != nil {
			zap.L().Error("Failed to remove zombie simulator node file", zap.String("path", filePath), zap.Error(err))
		}

		pidFileName = fmt.Sprintf("anvil.%d.ipc", node.Addr.Port)
		if err := os.Remove(filepath.Join(node.PidPath, pidFileName)); err != nil {
			zap.L().Error("Failed to remove zombie simulator node file", zap.String("path", filePath), zap.Error(err))
		}
	}

	return nil
}
