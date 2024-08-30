package bindings

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/pkg/errors"
	"github.com/unpackdev/solgo/clients"
	"github.com/unpackdev/solgo/utils"
	"math/big"
	"time"
)

var (
	// These values should be set based on current network conditions.
	// 2 Gwei is often a reasonable default for priority fee.
	defaultMaxPriorityFeePerGas = big.NewInt(2e9) // 2 Gwei

)

func (m *Manager) GetTransactionByHash(ctx context.Context, network utils.Network, txHash common.Hash) (*types.Transaction, bool, error) {
	client := m.clientPool.GetClientByGroup(string(network))
	if client == nil {
		return nil, false, fmt.Errorf("client not found for network %s", network)
	}

	return client.TransactionByHash(ctx, txHash)
}

func (m *Manager) WaitForReceipt(ctx context.Context, network utils.Network, simulatorType utils.SimulatorType, client *clients.Client, txHash common.Hash) (*types.Receipt, error) {
	// TODO: This should be configurable per network... (this: 60 seconds)
	ctxWait, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	for {
		select {
		case <-ctxWait.Done():
			return nil, fmt.Errorf("context cancelled while waiting to get transaction receipt: %s", txHash.Hex())
		default:
			receipt, err := client.TransactionReceipt(ctxWait, txHash)
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					return nil, fmt.Errorf("timeout waiting to get transaction receipt: %s", txHash.Hex())
				}
				// Transaction not yet mined
				time.Sleep(500 * time.Millisecond) // Configurable delay
				continue
			}

			return receipt, nil
		}
	}
}

func (m *Manager) SendTransaction(opts *bind.TransactOpts, network utils.Network, simulateType utils.SimulatorType, client *clients.Client, contract *common.Address, input []byte) (*types.Transaction, error) {
	var rawTx *types.Transaction
	var err error
	if opts.GasPrice != nil {
		rawTx, err = createLegacyTx(opts, contract, input)
	} else {
		var head *types.Header
		var errHead error

		head, errHead = client.HeaderByNumber(opts.Context, nil)
		if errHead != nil {
			return nil, errHead
		}

		if head.BaseFee != nil {
			rawTx, err = createDynamicTx(opts, contract, input, head)
		} else {
			rawTx, err = createLegacyTx(opts, contract, input)
		}
	}
	if err != nil {
		return nil, err
	}

	if opts.Signer == nil {
		return nil, fmt.Errorf(
			"no signer to authorize the transaction with, network: %s, simulate_type: %s, contract: %s",
			network, simulateType, contract.Hex(),
		)
	}

	signedTx, err := opts.Signer(opts.From, rawTx)
	if err != nil {
		return nil, err
	}

	if opts.NoSend {
		return signedTx, nil
	}

	if err := client.SendTransaction(opts.Context, signedTx); err != nil {
		return nil, err
	}

	return signedTx, nil
}

func createLegacyTx(opts *bind.TransactOpts, contract *common.Address, input []byte) (*types.Transaction, error) {
	// Create a legacy transaction
	tx := types.NewTransaction(opts.Nonce.Uint64(), *contract, opts.Value, opts.GasLimit, opts.GasPrice, input)
	return tx, nil
}

func createDynamicTx(opts *bind.TransactOpts, contract *common.Address, input []byte, head *types.Header) (*types.Transaction, error) {
	// Calculate the effective gas fee cap and tip cap
	gasFeeCap := opts.GasFeeCap
	gasTipCap := opts.GasTipCap

	if gasFeeCap == nil {
		// Set default max fee per gas if not provided
		gasFeeCap = new(big.Int).Add(head.BaseFee, defaultMaxPriorityFeePerGas)
	}

	if gasTipCap == nil {
		// Set default priority fee if not provided
		gasTipCap = defaultMaxPriorityFeePerGas
	}

	// Create a dynamic fee transaction (EIP-1559)
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   big.NewInt(int64(utils.EthereumNetworkID)),
		Nonce:     opts.Nonce.Uint64(),
		GasTipCap: gasTipCap,
		GasFeeCap: gasFeeCap,
		Gas:       opts.GasLimit,
		To:        contract,
		Value:     opts.Value,
		Data:      input,
	})
	return tx, nil
}
