package contracts

import (
	"context"
	"fmt"
	"github.com/0x19/solc-switch"
	hypersyncgo "github.com/enviodev/hypersync-client-go"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/unpackdev/solgo/bindings"
	"github.com/unpackdev/solgo/clients"
	"github.com/unpackdev/solgo/metadata"
	"github.com/unpackdev/solgo/providers/bitquery"
	"github.com/unpackdev/solgo/providers/etherscan"
	"github.com/unpackdev/solgo/storage"
	"github.com/unpackdev/solgo/tokens"
	"github.com/unpackdev/solgo/utils"
)

// Metadata holds essential data related to an Ethereum smart contract.
// It includes information about the contract's bytecode, associated transactions, and blockchain context.
type Metadata struct {
	RuntimeBytecode  []byte
	DeployedBytecode []byte
	Block            *types.Block
	Transaction      *types.Transaction
	Receipt          *types.Receipt
}

// Contract represents an Ethereum smart contract within the context of a specific network.
// It encapsulates the contract's address, network information, and associated metadata,
// and provides methods to interact with the contract on the blockchain.
type Contract struct {
	ctx          context.Context
	clientPool   *clients.ClientPool
	hypersync    *hypersyncgo.Client
	client       *clients.Client
	addr         common.Address
	network      utils.Network
	descriptor   *Descriptor
	token        *tokens.Token
	bqp          *bitquery.Provider
	etherscan    *etherscan.Provider
	compiler     *solc.Solc
	bindings     *bindings.Manager
	tokenBind    *bindings.Token
	stor         *storage.Storage
	ipfsProvider metadata.Provider
}

// NewContract creates a new instance of Contract for a given Ethereum address and network.
// It initializes the contract's context, metadata, and associated blockchain clients.
// The function validates the contract's existence and its bytecode before creation.
func NewContract(ctx context.Context, network utils.Network, clientPool *clients.ClientPool, hypersync *hypersyncgo.Client, stor *storage.Storage, bqp *bitquery.Provider, etherscan *etherscan.Provider, compiler *solc.Solc, bindManager *bindings.Manager, ipfsProvider metadata.Provider, addr common.Address) (*Contract, error) {
	if clientPool == nil {
		return nil, fmt.Errorf("client pool is nil")
	}

	client := clientPool.GetClientByGroup(network.String())
	if client == nil {
		return nil, fmt.Errorf("client for network %s is nil", network.String())
	}

	if !common.IsHexAddress(addr.Hex()) {
		return nil, fmt.Errorf("invalid address provided: %s", addr.Hex())
	}

	tokenBind, err := bindings.NewToken(ctx, network, bindManager, bindings.DefaultTokenBindOptions(addr))
	if err != nil {
		return nil, fmt.Errorf("failed to create new token %s bindings: %w", addr, err)
	}

	token, err := tokens.NewToken(
		ctx,
		network,
		addr,
		bindManager,
		clientPool,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create new token %s instance: %w", addr, err)
	}

	toReturn := &Contract{
		ctx:        ctx,
		network:    network,
		hypersync:  hypersync,
		clientPool: clientPool,
		client:     client,
		addr:       addr,
		bqp:        bqp,
		etherscan:  etherscan,
		compiler:   compiler,
		descriptor: &Descriptor{
			Network:         network,
			NetworkID:       utils.GetNetworkID(network),
			Address:         addr,
			Implementations: make([]common.Address, 0),
		},
		bindings:     bindManager,
		token:        token,
		tokenBind:    tokenBind,
		stor:         stor,
		ipfsProvider: ipfsProvider,
	}

	return toReturn, nil
}

// GetAddress returns the Ethereum address of the contract.
func (c *Contract) GetAddress() common.Address {
	return c.addr
}

// GetNetwork returns the network (e.g., Mainnet, Ropsten) on which the contract is deployed.
func (c *Contract) GetNetwork() utils.Network {
	return c.network
}

// GetDeployedBytecode returns the deployed bytecode of the contract.
// This bytecode is the compiled contract code that exists on the Ethereum blockchain.
func (c *Contract) GetDeployedBytecode() []byte {
	return c.descriptor.DeployedBytecode
}

// GetExecutionBytecode returns the runtime bytecode of the contract.
// This bytecode is used during the execution of contract calls and transactions.
func (c *Contract) GetExecutionBytecode() []byte {
	return c.descriptor.ExecutionBytecode
}

// GetBlock returns the blockchain block in which the contract was deployed or involved.
func (c *Contract) GetBlock() *types.Header {
	return c.descriptor.Block
}

// SetBlock sets the blockchain block in which the contract was deployed or involved.
func (c *Contract) SetBlock(block *types.Header) {
	c.descriptor.Block = block
}

// GetTransaction returns the Ethereum transaction associated with the contract's deployment or a specific operation.
func (c *Contract) GetTransaction() *types.Transaction {
	return c.descriptor.Transaction
}

// SetTransaction sets the Ethereum transaction associated with the contract's deployment or a specific operation.
func (c *Contract) SetTransaction(tx *types.Transaction) {
	c.descriptor.Transaction = tx
	c.descriptor.ExecutionBytecode = tx.Data()
}

// GetReceipt returns the receipt of the transaction in which the contract was involved,
// providing details such as gas used and logs generated.
func (c *Contract) GetReceipt() *types.Receipt {
	return c.descriptor.Receipt
}

// SetReceipt sets the receipt of the transaction in which the contract was involved,
// providing details such as gas used and logs generated.
func (c *Contract) SetReceipt(receipt *types.Receipt) {
	c.descriptor.Receipt = receipt
}

// GetSender returns the Ethereum address of the sender of the contract's transaction.
// It extracts the sender's address using the transaction's signature.
func (c *Contract) GetSender() (common.Address, error) {
	from, err := types.Sender(types.LatestSignerForChainID(c.descriptor.Transaction.ChainId()), c.descriptor.Transaction)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to get sender: %s", err)
	}

	return from, nil
}

// GetToken returns contract related discovered token (if found)
func (c *Contract) GetToken() *tokens.Token {
	return c.token
}

// IsValid checks if the contract is valid by verifying its deployed bytecode.
// A contract is considered valid if it has non-empty deployed bytecode on the blockchain.
func (c *Contract) IsValid() (bool, error) {
	if err := c.DiscoverDeployedBytecode(); err != nil {
		return false, err
	}
	return len(c.descriptor.DeployedBytecode) > 2, nil
}

// GetDescriptor a public member to return back processed contract descriptor
func (c *Contract) GetDescriptor() *Descriptor {
	return c.descriptor
}
