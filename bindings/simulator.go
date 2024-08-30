package bindings

import (
	"fmt"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/unpackdev/solgo/clients"
	"github.com/unpackdev/solgo/utils"
)

type JSONRPCRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

func (m *Manager) ImpersonateAccount(network utils.Network, contract common.Address) (common.Address, error) {
	client := m.clientPool.GetClientByGroup(string(network))
	if client == nil {
		return contract, fmt.Errorf("client not found for network %s", network)
	}

	rpcClient := client.GetRpcClient()
	if err := rpcClient.Call(nil, "anvil_impersonateAccount", contract.Hex()); err != nil {
		return contract, fmt.Errorf("failed to impersonate account: %v", err)
	}

	return contract, nil
}

func (m *Manager) StopImpersonateAccount(network utils.Network, contract common.Address) (common.Address, error) {
	client := m.clientPool.GetClientByGroup(string(network))
	if client == nil {
		return contract, fmt.Errorf("client not found for network %s", network)
	}

	rpcClient := client.GetRpcClient()
	if err := rpcClient.Call(nil, "anvil_stopImpersonatingAccount", contract.Hex()); err != nil {
		return contract, fmt.Errorf("failed to stop impersonating account: %v", err)
	}

	return contract, nil
}

func (m *Manager) SendSimulatedTransaction(opts *bind.TransactOpts, network utils.Network, simulatorType utils.SimulatorType, client *clients.Client, contract *common.Address, method abi.Method, input []byte) (*common.Hash, error) {
	txArgs := map[string]interface{}{
		"from": opts.From.Hex(),
		"to":   contract.Hex(),
		"data": hexutil.Encode(input), // method + arguments...
	}

	if opts.Value != nil {
		txArgs["value"] = hexutil.EncodeBig(opts.Value)
	}

	var txHash common.Hash
	if err := client.GetRpcClient().Call(&txHash, "eth_sendTransaction", txArgs); err != nil {
		return nil, fmt.Errorf("failed to send transaction: %v - contract: %v - args: %v", err, contract.Hex(), txArgs)
	}

	return &txHash, nil
}
