package bindings

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/unpackdev/solgo/utils"
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

func (m *Manager) WaitForReceipt(ctx context.Context, network utils.Network, txHash common.Hash) (*types.Receipt, error) {
	client := m.clientPool.GetClientByGroup(string(network))
	if client == nil {
		return nil, fmt.Errorf("client not found for network %s", network)
	}

	// TODO: This should be configurable per network... (this: 2 seconds)
	ctxWait, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
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

func (m *Manager) SendTransaction(opts *bind.TransactOpts, network utils.Network, contract *common.Address, input []byte) (*types.Transaction, error) {
	var rawTx *types.Transaction
	var err error
	if opts.GasPrice != nil {
		rawTx, err = createLegacyTx(opts, contract, input)
	} else {
		var head *types.Header
		var errHead error

		if m.simulatedClient != nil {
			head, errHead = m.simulatedClient.HeaderByNumber(opts.Context, nil)
			if errHead != nil {
				return nil, errHead
			}
		} else {
			client := m.clientPool.GetClientByGroup(string(network))
			if client == nil {
				return nil, fmt.Errorf("client not found for network %s", network)
			}

			head, errHead = client.HeaderByNumber(opts.Context, nil)
			if errHead != nil {
				return nil, errHead
			}
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

	// Sign the transaction
	if opts.Signer == nil {
		return nil, errors.New("no signer to authorize the transaction with")
	}
	signedTx, err := opts.Signer(opts.From, rawTx)
	if err != nil {
		return nil, err
	}

	if !opts.NoSend {
		if m.simulatedClient != nil {
			if err := m.simulatedClient.SendTransaction(opts.Context, signedTx); err != nil {
				return nil, err
			}
			m.simulatedClient.Commit()
		} else {
			client := m.clientPool.GetClientByGroup(string(network))
			if client == nil {
				return nil, errors.New("client not found for network")
			}

			if err := client.SendTransaction(opts.Context, signedTx); err != nil {
				return nil, err
			}
		}
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
