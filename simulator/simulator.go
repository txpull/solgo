package simulator

import (
	"context"
	"fmt"
	"math/big"
	"net"
	"sync"
	"sync/atomic"

	"github.com/unpackdev/solgo/bindings"
	"github.com/unpackdev/solgo/clients"
	"github.com/unpackdev/solgo/utils"
	"go.uber.org/zap"
)

// Simulator is the core struct for the simulator package. It manages the lifecycle
// and operations of blockchain simulations, including the management of providers
// and faucets. The Simulator allows for flexible interaction with various simulated
// blockchain environments and accounts.
type Simulator struct {
	ctx        context.Context                  // Context for managing lifecycle and control flow.
	opts       *Options                         // Configuration options for the Simulator.
	clientPool *clients.ClientPool              // Ethereum client pool
	providers  map[utils.SimulatorType]Provider // Registered providers for different simulation types.
	mu         sync.Mutex                       // Mutex to protect concurrent access to the providers map and other shared resources.
	faucets    *Faucet                          // Faucet for managing simulated accounts.
	started    atomic.Bool                      // Flag to indicate if the Simulator has been started.
}

// NewSimulator initializes a new Simulator with the given context and options.
// It sets up a new Faucet for account management and prepares the Simulator for operation.
// Returns an error if options are not provided or if the Faucet fails to initialize.
func NewSimulator(ctx context.Context, clientPool *clients.ClientPool, opts *Options) (*Simulator, error) {
	if opts == nil {
		return nil, fmt.Errorf("in order to create a new simulator, you must provide options")
	}

	var pool *clients.ClientPool
	if clientPool == nil {
		emptyPool, err := clients.NewClientPool(ctx, &clients.Options{Nodes: []clients.Node{}})
		if err != nil {
			return nil, fmt.Errorf("failed to create simulator client pool: %s", err)
		}
		pool = emptyPool
	} else {
		pool = clientPool
	}

	faucets, err := NewFaucet(ctx, pool, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create new faucet: %s", err)
	}

	if opts.FaucetsEnabled {
		if opts.FaucetAccountCount <= 0 {
			return nil, fmt.Errorf("auto faucet count must be greater than 0")
		}

		for _, network := range opts.SupportedNetworks {
			if faucetCount := len(faucets.List(network)); faucetCount < opts.FaucetAccountCount {
				missingFaucetCount := opts.FaucetAccountCount - faucetCount

				zap.L().Info(
					"Generating new faucet accounts. Please be patient...",
					zap.Int("current_count", faucetCount),
					zap.Int("required_count", opts.FaucetAccountCount),
					zap.Int("missing_count", missingFaucetCount),
					zap.String("network", string(network)),
				)

				for i := 0; i < missingFaucetCount; i++ {
					zap.L().Info(
						"Generating new faucet account...",
						zap.Int("current_count", i),
						zap.Int("required_count", opts.FaucetAccountCount),
						zap.String("network", string(network)),
					)

					if _, err := faucets.Create(network, opts.DefaultPassword, true, utils.SimulatorAccountType.String()); err != nil {
						return nil, fmt.Errorf("failed to generate faucet account for network: %s err: %s", network, err)
					}
				}
			}
		}
	}

	return &Simulator{
		ctx:        ctx,
		opts:       opts,
		providers:  make(map[utils.SimulatorType]Provider),
		faucets:    faucets,
		clientPool: pool,
		started:    atomic.Bool{},
	}, nil
}

// GetFaucet returns the Faucet associated with the Simulator.
// The Faucet is used for creating and managing simulated blockchain accounts.
func (s *Simulator) GetFaucet() *Faucet {
	return s.faucets
}

// GetClientPool returns the Ethereum client pool associated with the Simulator.
// The client pool is used for managing Ethereum clients for various simulated environments.
func (s *Simulator) GetClientPool() *clients.ClientPool {
	return s.clientPool
}

func (c *Simulator) GetBindingManager(simType utils.SimulatorType) (*bindings.Manager, error) {
	return bindings.NewManager(c.ctx, c.GetProvider(simType).GetClientPool())
}

// RegisterProvider registers a new provider for a specific simulation type.
// If a provider for the given name already exists, it returns false.
// Otherwise, it adds the provider and returns true.
func (s *Simulator) RegisterProvider(name utils.SimulatorType, provider Provider) (bool, error) {
	if _, ok := s.providers[name]; ok {
		return false, fmt.Errorf("provider %s already exists", name)
	}

	s.providers[name] = provider

	if anvilProvider, ok := ToAnvilProvider(provider); ok {
		manager, err := s.GetBindingManager(name)
		if err != nil {
			return false, err
		}

		anvilProvider.SetBindingManager(manager)
		return true, nil
	}

	return true, nil
}

// GetProvider retrieves a registered provider by its simulation type.
// Returns nil if no provider is registered under the given name.
func (s *Simulator) GetProvider(name utils.SimulatorType) Provider {
	s.mu.Lock()
	defer s.mu.Unlock()

	if provider, ok := s.providers[name]; ok {
		return provider
	}

	return nil
}

// GetProviders returns a map of all registered providers by their simulation types.
func (s *Simulator) GetProviders() map[utils.SimulatorType]Provider {
	return s.providers
}

// ProviderExists checks if a provider with the given simulation type is registered.
// Returns true if the provider exists, false otherwise.
func (s *Simulator) ProviderExists(name utils.SimulatorType) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.providers[name]; ok {
		return true
	}

	return false
}

// Start initiates the simulation providers within the Simulator. It can start
// all registered providers or a subset specified in the 'simulators' variadic argument.
// If the 'simulators' argument is provided, only the providers matching the specified
// SimulatorTypes are started. If no 'simulators' argument is provided, all registered
// providers are started.
//
// This method iterates through each registered provider and calls its Load method,
// passing the provided context. The Load method of each provider is expected to
// initiate any necessary operations to start the simulation client.
func (s *Simulator) Start(ctx context.Context, simulators ...utils.SimulatorType) error {
	for _, provider := range s.providers {
		if len(simulators) > 0 {
			for _, simulator := range simulators {
				if provider.Type() == simulator {
					if err := provider.Load(ctx); err != nil {
						return fmt.Errorf("failed to start provider: %s", err)
					}
				}
			}
		} else {
			if err := provider.Load(ctx); err != nil {
				return fmt.Errorf("failed to start provider: %s", err)
			}
		}
	}

	s.started.Store(true)

	zap.L().Info("Simulator started successfully")

	return nil
}

// IsStarted returns a boolean indicating if the Simulator has been started.
func (s *Simulator) IsStarted() bool {
	return s.started.Load()
}

// Stop terminates the simulation providers within the Simulator. Similar to Start,
// it can stop all registered providers or a subset specified in the 'simulators'
// variadic argument. If the 'simulators' argument is provided, only the providers
// matching the specified SimulatorTypes are stopped. If no 'simulators' argument
// is provided, all registered providers are stopped.
//
// This method iterates through each registered provider and calls its Unload method,
// passing the provided context. The Unload method of each provider is expected to
// perform any necessary operations to stop the simulation client.
func (s *Simulator) Stop(ctx context.Context, simulators ...utils.SimulatorType) error {
	if !s.IsStarted() {
		return fmt.Errorf("simulator has not been started")
	}

	for _, provider := range s.providers {
		if len(simulators) > 0 {
			for _, simulator := range simulators {
				if provider.Type() == simulator {
					if err := provider.Unload(ctx); err != nil {
						return err
					}
				}
			}
		} else {
			if err := provider.Unload(ctx); err != nil {
				return err
			}
		}
	}

	zap.L().Info("Simulator stopped successfully")

	return nil
}

// Status retrieves the status of the simulation providers within the Simulator.
// Similar to Start and Stop, it can retrieve the status of all registered providers
// or a subset specified in the 'simulators' variadic argument. If the 'simulators'
// argument is provided, only the providers matching the specified SimulatorTypes
// are queried. If no 'simulators' argument is provided, all registered providers
// are queried.
//
// This method iterates through each registered provider and calls its Status method,
// passing the provided context. The Status method of each provider is expected to
// return the current status of the simulation client.
func (s *Simulator) Status(ctx context.Context, simulators ...utils.SimulatorType) (*NodeStatusResponse, error) {
	toReturn := &NodeStatusResponse{
		Nodes: make(map[utils.SimulatorType][]*NodeStatus),
	}

	for _, provider := range s.providers {
		if len(simulators) > 0 {
			for _, simulator := range simulators {
				if provider.Type() == simulator {
					statusSlice, err := provider.Status(ctx)
					if err != nil {
						return nil, err
					}
					for _, status := range statusSlice {
						toReturn.Nodes[provider.Type()] = append(toReturn.Nodes[provider.Type()], status)
					}
				}
			}
		} else {
			statusSlice, err := provider.Status(ctx)
			if err != nil {
				return nil, err
			}
			for _, status := range statusSlice {
				toReturn.Nodes[provider.Type()] = append(toReturn.Nodes[provider.Type()], status)
			}
		}
	}

	return toReturn, nil
}

// GetClient retrieves a blockchain client for a specific provider and block number.
// It first checks if the provider exists. If not, it returns an error.
// For an existing provider, it attempts to find a node that matches the given block number.
// If such a node doesn't exist, it tries to spawn a new node:
// - It first gets the next available port. If no ports are available, an error is returned.
// - It then starts a new node with the specified start options.
// - If faucets are enabled, it sets up faucet accounts for the new node.
// - Finally, it attempts to retrieve a client for the new node. If not found, an error is reported.
// If a matching node is found, it attempts to retrieve the corresponding client.
// If the client doesn't exist, it returns an error.
// If the provider is recognized but not fully implemented, an appropriate error is returned.
// Returns a pointer to the blockchain client and an error if any issues occur during the process.
func (s *Simulator) GetClient(ctx context.Context, provider utils.SimulatorType, blockNumber *big.Int) (*clients.Client, *Node, error) {
	if !s.ProviderExists(provider) {
		return nil, nil, fmt.Errorf("provider %s does not exist", provider)
	}

	if !s.IsStarted() {
		return nil, nil, fmt.Errorf("simulator has not been started")
	}

	if providerCtx, ok := s.GetProvider(provider).(*AnvilProvider); ok {
		if node, ok := providerCtx.GetNodeByBlockNumber(blockNumber); !ok {
			zap.L().Debug(
				"Node for block number does not exist. Attempting to spawn new node...",
				zap.Any("block_number", blockNumber),
				zap.String("provider", provider.String()),
				zap.String("network", providerCtx.Network().String()),
			)

			port := providerCtx.GetNextPort()
			if port == 0 {
				return nil, nil, fmt.Errorf("no available ports to start anvil nodes")
			}

			startOpts := StartOptions{
				Fork:         providerCtx.opts.Fork,
				ForkEndpoint: providerCtx.opts.ForkEndpoint,
				Addr: net.TCPAddr{
					IP:   providerCtx.opts.IPAddr,
					Port: port,
				},
				BlockNumber: blockNumber,
			}

			newNode, err := providerCtx.Start(ctx, startOpts)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to spawn anvil node: %s", err)
			}

			// Lets now load faucet accounts for the newly spawned node
			if providerCtx.simulator.opts.FaucetsEnabled {
				if providerCtx.simulator.opts.FaucetsAutoReplenishEnabled {
					if err := providerCtx.SetupFaucetAccounts(ctx, newNode); err != nil {
						return nil, newNode, fmt.Errorf("failed to load faucet accounts: %s", err)
					}
				}
			}

			providerCtx.mu.Lock()
			if _, ok := providerCtx.nodes[newNode.BlockNumber.Uint64()]; !ok {
				providerCtx.nodes[newNode.BlockNumber.Uint64()] = newNode
			}
			providerCtx.mu.Unlock()

			if client, found := providerCtx.GetClientByGroupAndType(newNode.GetProvider().Type(), newNode.GetID().String()); found {
				return client, newNode, nil
			} else {
				return nil, nil, fmt.Errorf(
					"client for provider: %s - node %s - block number: %d does not exist",
					node.GetProvider(), node.GetID().String(), blockNumber,
				)
			}

		} else {
			if client, found := providerCtx.GetClientByGroupAndType(node.GetProvider().Type(), node.GetID().String()); found {
				return client, node, nil
			} else {
				return nil, nil, fmt.Errorf("client for provider: %s - node %s does not exist", node.GetProvider(), node.GetID().String())
			}
		}
	}

	return nil, nil, fmt.Errorf("provider %s is not fully implemented", provider)
}

// GetOptions returns the Simulator's configuration options.
// The options are used to configure the Simulator's behavior.
func (s *Simulator) GetOptions() *Options {
	return s.opts
}

// Close gracefully shuts down the simulator. It performs the following steps:
//  1. Stops the simulator by calling the Stop method with the simulator's context.
//     If stopping the simulator fails, it returns the encountered error.
//  2. Closes the client pool to release all associated resources.
//
// Returns an error if any issues occur during the stopping process, otherwise nil.
func (s *Simulator) Close() error {
	if err := s.Stop(s.ctx); err != nil {
		return err
	}

	s.clientPool.Close()
	return nil
}
