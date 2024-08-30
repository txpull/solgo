package storage

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/unpackdev/solgo/cfg"
	"github.com/unpackdev/solgo/clients"
	"github.com/unpackdev/solgo/detector"
	"github.com/unpackdev/solgo/utils"
)

// Storage is a struct that encapsulates various components required to interact with Ethereum smart contracts.
type Storage struct {
	ctx         context.Context
	network     utils.Network
	clientsPool *clients.ClientPool
	opts        *Options
	//simulator   *simulator.Simulator
}

// NewStorage creates a new Storage instance. It requires context, network configuration, and various components
// such as a client pool, simulator, etherscan provider, compiler, and binding manager.
// It returns an initialized Storage object or an error if the initialization fails.
func NewStorage(
	ctx context.Context,
	network utils.Network,
	pool *clients.ClientPool,
	//simulator *simulator.Simulator,
	opts *Options,
) (*Storage, error) {
	if opts == nil {
		return nil, fmt.Errorf("options cannot be nil")
	}

	return &Storage{
		ctx:         ctx,
		network:     network,
		clientsPool: pool,
		opts:        opts,
		//simulator:   simulator,
	}, nil
}

// Describe queries and returns detailed information about a smart contract at a specific address.
// It requires context, the contract address, detector and the block number for the query.
// It returns a Reader instance containing contract details or an error if the query fails.
func (s *Storage) Describe(ctx context.Context, addr common.Address, detector *detector.Detector, cfgBuilder *cfg.Builder, atBlock *big.Int) (*Reader, error) {
	return s._describe(ctx, addr, detector, cfgBuilder, atBlock, true)
}

func (s *Storage) DescribeLayout(ctx context.Context, addr common.Address, detector *detector.Detector, cfgBuilder *cfg.Builder, atBlock *big.Int) (*Reader, error) {
	return s._describe(ctx, addr, detector, cfgBuilder, atBlock, false)
}

// _describe is an internal method that performs the actual description process of a contract.
// It constructs a Descriptor and utilizes a Reader to discover and calculate storage variables and layouts.
func (s *Storage) _describe(ctx context.Context, addr common.Address, detector *detector.Detector, cfgBuilder *cfg.Builder, atBlock *big.Int, fetchValues bool) (*Reader, error) {
	descriptor := &Descriptor{
		Detector:          detector,
		cfgBuilder:        cfgBuilder,
		Address:           addr,
		Block:             atBlock,
		StateVariables:    make(map[string][]*Variable),
		TargetVariables:   make(map[string][]*Variable),
		ConstantVariables: make(map[string][]*Variable),
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

	if fetchValues {
		if err := s.populateStorageValues(ctx, reader, addr, descriptor, atBlock); err != nil {
			return nil, err
		}
	}

	return reader, nil
}

// populateStorageValues populates storage values for each slot in the descriptor's storage layout.
func (s *Storage) populateStorageValues(ctx context.Context, reader *Reader, addr common.Address, descriptor *Descriptor, atBlock *big.Int) error {
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
		if err := convertStorageToValue(s, addr, slot, lastStorageValue); err != nil {
			return err
		}
	}

	return nil
}

// getStorageValueAt retrieves the storage value at a given slot for a contract.
func (s *Storage) getStorageValueAt(ctx context.Context, contractAddress common.Address, slot int64, blockNumber *big.Int) (*big.Int, []byte, error) {
	client := s.clientsPool.GetClientByGroup(s.network.String())
	if client == nil {
		return blockNumber, nil, fmt.Errorf("no client found for network %s", s.network)
	}

	if blockNumber == nil {
		latestHeader, err := client.HeaderByNumber(ctx, nil)
		if err != nil {
			return blockNumber, nil, fmt.Errorf("failed to get latest block header: %v", err)
		}
		blockNumber = latestHeader.Number
	}

	bigIntIndex := big.NewInt(slot)
	position := common.BigToHash(bigIntIndex)

	response, err := client.StorageAt(ctx, contractAddress, position, blockNumber)
	return blockNumber, response, err
}

// ReadStorageSlot reads the storage at a given slot for a specific contract.
func (s *Storage) ReadStorageSlot(ctx context.Context, contractAddress common.Address, slot int64, blockNumber *big.Int) ([]byte, error) {
	_, storageValue, err := s.getStorageValueAt(ctx, contractAddress, slot, blockNumber)
	if err != nil {
		return nil, fmt.Errorf("error reading storage slot %d: %v", slot, err)
	}
	return storageValue, nil
}
