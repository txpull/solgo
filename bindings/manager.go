package bindings

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/unpackdev/solgo/clients"
	"github.com/unpackdev/solgo/standards"
	"github.com/unpackdev/solgo/utils"
)

// Manager acts as a central registry for smart contract bindings. It enables the configuration, management, and
// interaction with smart contracts across different networks. The Manager maintains a client pool for network
// communications, a context for managing lifecycle events, and a mutex for thread-safe operation.
type Manager struct {
	ctx        context.Context                            // The context for managing the lifecycle of network requests.
	clientPool *clients.ClientPool                        // A pool of blockchain network clients for executing RPC calls.
	bindings   map[utils.Network]map[BindingType]*Binding // A nested map storing contract bindings by network and type.
	mu         sync.RWMutex                               // A read/write mutex for thread-safe access to the bindings map.
}

// NewManager creates a new Manager instance with a specified context and client pool. It ensures that the contract
// standards are loaded before initialization. This constructor is suitable for production use where interaction with
// real network clients is required.
func NewManager(ctx context.Context, clientPool *clients.ClientPool) (*Manager, error) {
	if !standards.StandardsLoaded() {
		if err := standards.LoadStandards(); err != nil {
			return nil, fmt.Errorf("failed to load standards: %w", err)
		}
	}

	return &Manager{
		ctx:        ctx,
		clientPool: clientPool,
		bindings:   make(map[utils.Network]map[BindingType]*Binding),
		mu:         sync.RWMutex{},
	}, nil
}

// RegisterBinding adds a new contract binding to the Manager. It processes the contract's ABI and initializes
// a Binding struct, ensuring that each binding is uniquely registered within its network context.
func (m *Manager) RegisterBinding(network utils.Network, networkID utils.NetworkID, name BindingType, address common.Address, rawABI string) (*Binding, error) {
	parsedABI, err := abi.JSON(strings.NewReader(rawABI))
	if err != nil {
		return nil, err
	}

	binding := &Binding{
		network:   network,
		networkID: networkID,
		Type:      name,
		Address:   address,
		RawABI:    rawABI,
		ABI:       &parsedABI,
	}

	m.mu.RLock()
	if _, ok := m.bindings[network]; !ok {
		m.bindings[network] = make(map[BindingType]*Binding)
	}
	m.mu.RUnlock()

	// We don't want to overwrite existing bindings and we don't want to register the same binding twice
	if !m.BindingExist(network, name) {
		m.bindings[network][name] = binding
	}

	return binding, nil
}

// GetClient returns the client pool associated with the Manager, allowing for direct network interactions.
func (m *Manager) GetClient() *clients.ClientPool {
	return m.clientPool
}

// GetBinding retrieves a specific contract binding by its network and type, enabling contract interactions.
func (m *Manager) GetBinding(network utils.Network, name BindingType) (*Binding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if networkBindings, ok := m.bindings[network]; ok {
		if binding, ok := networkBindings[name]; ok {
			return binding, nil
		}
	}
	return nil, fmt.Errorf("binding %s not found", name)
}

// GetBindings returns all bindings registered under a specific network, providing a comprehensive overview of
// available contract interactions.
func (m *Manager) GetBindings(network utils.Network) map[BindingType]*Binding {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.bindings[network]
}

// BindingExist checks whether a specific binding exists within the Manager, aiding in conditional logic and
// binding management.
func (m *Manager) BindingExist(network utils.Network, name BindingType) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if networkBindings, ok := m.bindings[network]; ok {
		if _, ok := networkBindings[name]; ok {
			return true
		}
	}
	return false
}

// WatchEvents establishes a subscription to listen for specific contract events, facilitating real-time
// application responses to on-chain activities.
func (m *Manager) WatchEvents(network utils.Network, bindingType BindingType, eventName string, ch chan<- types.Log) (ethereum.Subscription, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	binding, ok := m.bindings[network][bindingType]
	if !ok {
		return nil, fmt.Errorf("binding %s not found for network %s", bindingType, network)
	}

	query := ethereum.FilterQuery{
		Addresses: []common.Address{binding.GetAddress()},
	}

	event, ok := binding.ABI.Events[eventName]
	if !ok {
		return nil, fmt.Errorf("event %s not found in ABI", eventName)
	}

	query.Topics = [][]common.Hash{{event.ID}}

	client := m.clientPool.GetClientByGroup(network.String())
	if client == nil {
		return nil, fmt.Errorf("client not found for network %s", network)
	}

	return client.SubscribeFilterLogs(context.Background(), query, ch)
}

// CallContractMethod executes a method call on a smart contract, handling the data packing, RPC call execution,
// and results unpacking.
func (m *Manager) CallContractMethod(ctx context.Context, network utils.Network, bindingType BindingType, toAddr common.Address, methodName string, params ...interface{}) (any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	binding, ok := m.bindings[network][bindingType]
	if !ok {
		return nil, fmt.Errorf("binding %s not found for network %s", bindingType, network)
	}

	method, ok := binding.ABI.Methods[methodName]
	if !ok {
		return nil, fmt.Errorf("binding %s method %s not found in ABI", bindingType, methodName)
	}

	data, err := method.Inputs.Pack(params...)
	if err != nil {
		return nil, err
	}

	destinationAddr := toAddr
	if destinationAddr == utils.ZeroAddress {
		destinationAddr = binding.Address
	}

	callMsg := ethereum.CallMsg{
		To:   &destinationAddr,
		Data: append(method.ID, data...),
	}

	var result []byte

	client := m.clientPool.GetClientByGroup(network.String())
	if client == nil {
		return nil, fmt.Errorf("client not found for network %s", network)
	}

	result, err = client.CallContract(context.Background(), callMsg, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to call contract: %w", err)
	}

	var unpackedResults any
	err = binding.ABI.UnpackIntoInterface(&unpackedResults, methodName, result)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack results: %w", err)
	}

	return unpackedResults, nil
}

// CallContractMethodAtBlock executes a method call on a smart contract, handling the data packing, RPC call execution,
// and results unpacking.
func (m *Manager) CallContractMethodAtBlock(ctx context.Context, network utils.Network, blockNumber *big.Int, bindingType BindingType, toAddr common.Address, methodName string, params ...interface{}) (any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	binding, ok := m.bindings[network][bindingType]
	if !ok {
		return nil, fmt.Errorf("binding %s not found for network %s", bindingType, network)
	}

	method, ok := binding.ABI.Methods[methodName]
	if !ok {
		return nil, fmt.Errorf("binding %s method %s not found in ABI", bindingType, methodName)
	}

	data, err := method.Inputs.Pack(params...)
	if err != nil {
		return nil, err
	}

	destinationAddr := toAddr
	if destinationAddr == utils.ZeroAddress {
		destinationAddr = binding.Address
	}

	callMsg := ethereum.CallMsg{
		To:   &destinationAddr,
		Data: append(method.ID, data...),
	}

	var result []byte

	client := m.clientPool.GetClientByGroup(network.String())
	if client == nil {
		return nil, fmt.Errorf("client not found for network %s", network)
	}

	result, err = client.CallContract(context.Background(), callMsg, blockNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to call contract: %w", err)
	}

	var unpackedResults any
	err = binding.ABI.UnpackIntoInterface(&unpackedResults, methodName, result)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack results: %w", err)
	}

	return unpackedResults, nil
}

// CallContractMethodUnpackMap executes a contract method call and unpacks the results into a map, providing
// a flexible interface for handling contract outputs.
func (m *Manager) CallContractMethodUnpackMap(ctx context.Context, network utils.Network, bindingType BindingType, toAddr common.Address, methodName string, params ...interface{}) (map[string]any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	binding, ok := m.bindings[network][bindingType]
	if !ok {
		return nil, fmt.Errorf("binding %s not found for network %s", bindingType, network)
	}

	method, ok := binding.ABI.Methods[methodName]
	if !ok {
		return nil, fmt.Errorf("binding %s method %s not found in ABI", bindingType, methodName)
	}

	data, err := method.Inputs.Pack(params...)
	if err != nil {
		return nil, err
	}

	destinationAddr := toAddr
	if destinationAddr == utils.ZeroAddress {
		destinationAddr = binding.Address
	}

	callMsg := ethereum.CallMsg{
		To:   &destinationAddr,
		Data: append(method.ID, data...),
	}

	var result []byte

	client := m.clientPool.GetClientByGroup(network.String())
	if client == nil {
		return nil, fmt.Errorf("client not found for network %s", network)
	}

	result, err = client.CallContract(context.Background(), callMsg, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to call contract: %w", err)
	}

	unpackedResults := map[string]any{}
	err = binding.ABI.UnpackIntoMap(unpackedResults, methodName, result)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack results: %w", err)
	}

	return unpackedResults, nil
}

// CallContractMethodUnpackMap executes a contract method call and unpacks the results into a map, providing
// a flexible interface for handling contract outputs.
func (m *Manager) CallContractMethodUnpackMapAtBlock(ctx context.Context, network utils.Network, blockNumber *big.Int, bindingType BindingType, toAddr common.Address, methodName string, params ...interface{}) (map[string]any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	binding, ok := m.bindings[network][bindingType]
	if !ok {
		return nil, fmt.Errorf("binding %s not found for network %s", bindingType, network)
	}

	method, ok := binding.ABI.Methods[methodName]
	if !ok {
		return nil, fmt.Errorf("binding %s method %s not found in ABI", bindingType, methodName)
	}

	data, err := method.Inputs.Pack(params...)
	if err != nil {
		return nil, err
	}

	destinationAddr := toAddr
	if destinationAddr == utils.ZeroAddress {
		destinationAddr = binding.Address
	}

	callMsg := ethereum.CallMsg{
		To:   &destinationAddr,
		Data: append(method.ID, data...),
	}

	var result []byte

	client := m.clientPool.GetClientByGroup(network.String())
	if client == nil {
		return nil, fmt.Errorf("client not found for network %s", network)
	}

	result, err = client.CallContract(context.Background(), callMsg, blockNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to call contract: %w", err)
	}

	unpackedResults := map[string]any{}
	err = binding.ABI.UnpackIntoMap(unpackedResults, methodName, result)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack results: %w", err)
	}

	return unpackedResults, nil
}
