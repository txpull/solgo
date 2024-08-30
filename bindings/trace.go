package bindings

import (
	"context"
	"fmt"
	"github.com/pkg/errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/unpackdev/solgo/utils"
)

type Action struct {
	CallType string `json:"callType,omitempty"`
	From     string `json:"from"`
	Gas      string `json:"gas"`
	Input    string `json:"input"`
	To       string `json:"to"`
	Value    string `json:"value"`
	// Fields specific to reward actions
	Author     string `json:"author,omitempty"`
	RewardType string `json:"rewardType,omitempty"`
}

type Result struct {
	GasUsed string `json:"gasUsed"`
	Output  string `json:"output"`
}

type BlockTrace struct {
	Action              Action  `json:"action"`
	BlockHash           string  `json:"blockHash"`
	BlockNumber         int     `json:"blockNumber"`
	Error               string  `json:"error"`
	Result              *Result `json:"result,omitempty"`
	Subtraces           int     `json:"subtraces"`
	TraceAddress        []int   `json:"traceAddress"`
	TransactionHash     string  `json:"transactionHash,omitempty"`
	TransactionPosition int64   `json:"transactionPosition,omitempty"`
	Type                string  `json:"type"`
}

func (m *Manager) TraceBlock(ctx context.Context, network utils.Network, number *big.Int) ([]BlockTrace, error) {
	client := m.clientPool.GetClientByGroup(network.String())
	if client == nil {
		return nil, fmt.Errorf("client not found for network %s", network)
	}

	rpcClient := client.GetRpcClient()
	var result []BlockTrace
	var tmp interface{}

	// Convert number to hexadecimal string
	numberHex := fmt.Sprintf("0x%x", number)

	if err := rpcClient.CallContext(ctx, &result, "trace_block", numberHex); err != nil {
		if err := rpcClient.CallContext(ctx, &tmp, "trace_block", numberHex); err != nil {
			return nil, errors.Wrap(err, "failed to execute trace_block")
		}
		return nil, errors.Wrap(err, "failed to execute trace_block")
	}

	return result, nil
}

func (m *Manager) TraceCallMany(ctx context.Context, network utils.Network, sender common.Address, nonce int64) (*common.Hash, error) {
	client := m.clientPool.GetClientByGroup(network.String())
	if client == nil {
		return nil, fmt.Errorf("client not found for network %s", network)
	}

	rpcClient := client.GetRpcClient()
	var result *common.Hash

	if err := rpcClient.CallContext(ctx, &result, "trace_callMany", sender.Hex(), nonce); err != nil {
		return nil, errors.Wrap(err, "failed to execute trace_callMany")
	}

	return result, nil
}
