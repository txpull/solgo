package storage

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/unpackdev/solgo/clients"
	"github.com/unpackdev/solgo/detector"
	"github.com/unpackdev/solgo/simulator"
	"github.com/unpackdev/solgo/utils"
)

// Storage is a struct that encapsulates various components required to interact with Ethereum smart contracts.
type Storage struct {
	ctx         context.Context
	network     utils.Network
	clientsPool *clients.ClientPool
	opts        *Options
	simulator   *simulator.Simulator
}

// NewStorage creates a new Storage instance. It requires context, network configuration, and various components
// such as a client pool, simulator, etherscan provider, compiler, and binding manager.
// It returns an initialized Storage object or an error if the initialization fails.
func NewStorage(
	ctx context.Context,
	network utils.Network,
	clientsPool *clients.ClientPool,
	simulator *simulator.Simulator,
	opts *Options,
) (*Storage, error) {
	if opts == nil {
		return nil, fmt.Errorf("options cannot be nil")
	}

	return &Storage{
		ctx:         ctx,
		network:     network,
		clientsPool: clientsPool,
		opts:        opts,
		simulator:   simulator,
	}, nil
}

// Describe queries and returns detailed information about a smart contract at a specific address.
// It requires context, the contract address, detector and the block number for the query.
// It returns a Reader instance containing contract details or an error if the query fails.
func (s *Storage) Describe(ctx context.Context, addr common.Address, detector *detector.Detector, atBlock *big.Int) (*Reader, error) {
	return s._describe(ctx, addr, detector, atBlock)
}

// _describe is an internal method that performs the actual description process of a contract.
// It constructs a Descriptor and utilizes a Reader to discover and calculate storage variables and layouts.
func (s *Storage) _describe(ctx context.Context, addr common.Address, detector *detector.Detector, atBlock *big.Int) (*Reader, error) {
	descriptor := &Descriptor{
		Detector:         detector,
		Address:          addr,
		Block:            atBlock,
		StateVariables:   make(map[string][]*Variable),
		TargetVariables:  make(map[string][]*Variable),
		ConstanVariables: make(map[string][]*Variable),
		StorageLayout: &StorageLayout{
			Slots: make([]*SlotDescriptor, 0),
		},
	}

	reader, err := NewReader(ctx, s, descriptor)
	if err != nil {
		return nil, err
	}

	if err := reader.DiscoverStorageVariables(); err != nil {
		return nil, err
	}

	if err := reader.CalculateStorageLayout(); err != nil {
		return nil, err
	}

	if err := s.populateStorageValues(ctx, addr, descriptor, atBlock); err != nil {
		return nil, err
	}

	return reader, nil
}

// populateStorageValues populates storage values for each slot in the descriptor's storage layout.
func (s *Storage) populateStorageValues(ctx context.Context, addr common.Address, descriptor *Descriptor, atBlock *big.Int) error {
	var lastStorageValue []byte
	var lastSlot int64 = -1
	var lastBlockNumber *big.Int

	for _, slot := range descriptor.GetSlots() {
		if slot.Slot != lastSlot {
			blockNumber, storageValue, err := s.getStorageValueAt(ctx, addr, slot.Slot, atBlock)
			if err != nil {
				return err
			}

			if descriptor.Block == nil {
				descriptor.Block = blockNumber
			}

			slot.BlockNumber = blockNumber
			lastStorageValue = storageValue
			lastSlot = slot.Slot
			lastBlockNumber = blockNumber
		}

		slot.BlockNumber = lastBlockNumber
		slot.RawValue = common.BytesToHash(lastStorageValue)
		if err := convertStorageToValue(slot, lastStorageValue); err != nil {
			return err
		}
	}

	return nil
}

// getStorageValueAt retrieves the storage value at a given slot for a contract.
func (s *Storage) getStorageValueAt(ctx context.Context, contractAddress common.Address, slot int64, blockNumber *big.Int) (*big.Int, []byte, error) {
	/* 	if s.simulator != nil && s.opts.UseSimulator {
	   		return s.getSimulatedStorageValueAt(ctx, contractAddress, slot, blockNumber)
	   	}
	*/
	client := s.clientsPool.GetClientByGroup(s.network.String())
	if client == nil {
		return blockNumber, nil, fmt.Errorf("no client found for network %s", s.network)
	}

	if blockNumber == nil {
		latestHeader, err := client.BlockByNumber(ctx, nil)
		if err != nil {
			return blockNumber, nil, fmt.Errorf("failed to get latest block header: %v", err)
		}
		blockNumber = latestHeader.Number()
	}

	bigIntIndex := big.NewInt(slot)
	position := common.BigToHash(bigIntIndex)

	response, err := client.StorageAt(ctx, contractAddress, position, blockNumber)
	return blockNumber, response, err
}

// getStorageValueAt retrieves the storage value at a given slot for a contract using local simulator instance (debugging purpose).
/* func (s *Storage) getSimulatedStorageValueAt(ctx context.Context, contractAddress common.Address, slot int64, blockNumber *big.Int) (*big.Int, []byte, error) {
	client := s.simulator.GetBackend()

	if blockNumber == nil {
		latestHeader, err := client.BlockByNumber(ctx, nil)
		if err != nil {
			return blockNumber, nil, fmt.Errorf("failed to get latest block header: %v", err)
		}
		blockNumber = latestHeader.Number()
	}

	bigIntIndex := big.NewInt(slot)
	position := common.BigToHash(bigIntIndex)

	response, err := client.StorageAt(ctx, contractAddress, position, blockNumber)
	return blockNumber, response, err
} */
