package bindings

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/pkg/errors"
	"github.com/unpackdev/solgo/clients"
	"github.com/unpackdev/solgo/utils"
	"github.com/unpackdev/solgo/utils/entities"
	"math/big"
)

const (
	UniswapV2Factory BindingType = "UniswapV2Factory"
	UniswapV2Pair    BindingType = "UniswapV2Pair"
	UniswapV2Router  BindingType = "UniswapV2Router"
)

type UniswapV2Reserves struct {
	Reserve0           *big.Int
	Reserve1           *big.Int
	BlockTimestampLast uint32
}

// UniswapV2 encapsulates data and functions for interacting with a blockchain Uniswap V2 contracts.
type UniswapV2 struct {
	*Manager
	network utils.Network
	ctx     context.Context
	opts    []*BindOptions
}

func NewUniswapV2(ctx context.Context, network utils.Network, manager *Manager, opts []*BindOptions) (*UniswapV2, error) {
	if opts == nil {
		opts = DefaultUniswapV2BindOptions()
	}

	if manager == nil {
		return nil, errors.New("binding manager is not set while creating new uniswap_v2 bindings")
	}

	for _, opt := range opts {
		if err := opt.Validate(); err != nil {
			return nil, err
		}
	}

	for _, opt := range opts {
		for _, oNetwork := range opt.Networks {
			if _, err := manager.RegisterBinding(
				oNetwork,
				opt.NetworkID,
				opt.Type,
				opt.Address,
				opt.ABI,
			); err != nil {
				return nil, err
			}
		}
	}

	return &UniswapV2{
		network: network,
		Manager: manager,
		ctx:     ctx,
		opts:    opts,
	}, nil
}

func (u *UniswapV2) GetAddress(bindingType BindingType) (common.Address, error) {
	for _, opt := range u.opts {
		if opt.Type == bindingType {
			return opt.Address, nil
		}
	}

	return common.Address{}, fmt.Errorf("binding not found for type %s", bindingType)
}

func (u *UniswapV2) WETH(ctx context.Context) (common.Address, error) {
	result, err := u.Manager.CallContractMethod(ctx, u.network, UniswapV2Router, utils.ZeroAddress, "WETH")
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to get WETH address: %w", err)
	}

	return result.(common.Address), nil
}

func (u *UniswapV2) GetPair(ctx context.Context, tokenA, tokenB common.Address) (common.Address, error) {
	result, err := u.Manager.CallContractMethod(ctx, u.network, UniswapV2Factory, utils.ZeroAddress, "getPair", tokenA, tokenB)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to get pair: %w", err)
	}

	pairAddress, ok := result.(common.Address)
	if !ok {
		return common.Address{}, fmt.Errorf("failed to assert result as common.Address - pair address")
	}

	return pairAddress, nil
}

func (u *UniswapV2) GetToken0(ctx context.Context, pairAddr common.Address) (common.Address, error) {
	result, err := u.Manager.CallContractMethod(ctx, u.network, UniswapV2Pair, pairAddr, "token0")
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to get token0 of a pair: %w", err)
	}

	pairAddress, ok := result.(common.Address)
	if !ok {
		return common.Address{}, fmt.Errorf("failed to assert result as common.Address - token0 address")
	}

	return pairAddress, nil
}

func (u *UniswapV2) GetToken1(ctx context.Context, pairAddr common.Address) (common.Address, error) {
	result, err := u.Manager.CallContractMethod(ctx, u.network, UniswapV2Pair, pairAddr, "token1")
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to get token1 of a pair: %w", err)
	}

	pairAddress, ok := result.(common.Address)
	if !ok {
		return common.Address{}, fmt.Errorf("failed to assert result as common.Address - token1 address")
	}

	return pairAddress, nil
}

func (u *UniswapV2) GetReserves(ctx context.Context, pairAddr common.Address) (*UniswapV2Reserves, error) {
	result, err := u.Manager.CallContractMethodUnpackMap(ctx, u.network, UniswapV2Pair, pairAddr, "getReserves")
	if err != nil {
		return nil, fmt.Errorf("failed to get pair reserves: %w", err)
	}

	return &UniswapV2Reserves{
		Reserve0:           result["_reserve0"].(*big.Int),
		Reserve1:           result["_reserve1"].(*big.Int),
		BlockTimestampLast: result["_blockTimestampLast"].(uint32),
	}, nil
}

func (u *UniswapV2) GetAmountOut(ctx context.Context, amountIn *big.Int, reserveIn *big.Int, reserveOut *big.Int) (*big.Int, error) {
	result, err := u.Manager.CallContractMethod(ctx, u.network, UniswapV2Router, utils.ZeroAddress, "getAmountOut", amountIn, reserveIn, reserveOut)
	if err != nil {
		return nil, fmt.Errorf("failed to get amounts out: %w", err)
	}

	amountOut, ok := result.(*big.Int)
	if !ok {
		return nil, fmt.Errorf("failed to assert amount result as []*big.Int: %v", result)
	}

	return amountOut, nil
}

func (u *UniswapV2) Buy(opts *bind.TransactOpts, network utils.Network, simulatorType utils.SimulatorType, client *clients.Client, amountOutMin *big.Int, path []common.Address, to common.Address, amount *entities.CurrencyAmount, deadline *big.Int) (*types.Transaction, *types.Receipt, error) {
	bind, err := u.GetBinding(utils.Ethereum, UniswapV2Router)
	if err != nil {
		return nil, nil, err
	}
	bindAbi := bind.GetABI()

	method, exists := bindAbi.Methods["swapExactETHForTokens"]
	if !exists {
		return nil, nil, errors.New("swapExactETHForTokens method not found")
	}

	input, err := bindAbi.Pack(method.Name, amountOutMin, path, to, deadline)
	if err != nil {
		return nil, nil, err
	}

	// Estimate gas limit
	gasLimit, err := client.EstimateGas(context.Background(), ethereum.CallMsg{
		From:  opts.From,
		To:    &bind.Address,
		Data:  input,
		Value: amount.Quotient(),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to estimate gas: %w", err)
	}
	opts.GasLimit = gasLimit

	// Set gas price or fees if not already set
	if opts.GasPrice == nil && opts.GasFeeCap == nil && opts.GasTipCap == nil {
		head, err := client.HeaderByNumber(context.Background(), nil)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get latest block header: %w", err)
		}

		if head.BaseFee != nil {
			// EIP-1559 transaction (dynamic fee)
			opts.GasFeeCap = new(big.Int).Add(head.BaseFee, defaultMaxPriorityFeePerGas)
			opts.GasTipCap = defaultMaxPriorityFeePerGas
		} else {
			// Legacy transaction
			opts.GasPrice = big.NewInt(2e9) // 2 Gwei
		}
	}

	tx, err := u.Manager.SendTransaction(opts, u.network, simulatorType, client, &bind.Address, input)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to send swapExactETHForTokens transaction: %w", err)
	}

	receipt, err := u.Manager.WaitForReceipt(u.ctx, network, simulatorType, client, tx.Hash())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get swapExactETHForTokens transaction receipt: %w", err)
	}

	return tx, receipt, nil
}

func (u *UniswapV2) Sell(opts *bind.TransactOpts, network utils.Network, simulatorType utils.SimulatorType, client *clients.Client, amountIn *big.Int, amountOutMin *big.Int, path []common.Address, to common.Address, deadline *big.Int) (*types.Transaction, *types.Receipt, error) {
	bind, err := u.GetBinding(utils.Ethereum, UniswapV2Router)
	if err != nil {
		return nil, nil, err
	}

	bindAbi := bind.GetABI()

	method, exists := bindAbi.Methods["swapExactTokensForETHSupportingFeeOnTransferTokens"]
	if !exists {
		return nil, nil, errors.New("swapExactTokensForETH method not found")
	}

	input, err := bindAbi.Pack(method.Name, amountIn, amountOutMin, path, to, deadline)
	if err != nil {
		return nil, nil, err
	}

	// Estimate gas limit
	gasLimit, err := client.EstimateGas(context.Background(), ethereum.CallMsg{
		From:  opts.From,
		To:    &bind.Address,
		Data:  input,
		//Value: amountIn,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to estimate gas: %w", err)
	}
	opts.GasLimit = gasLimit

	// Set gas price or fees if not already set
	if opts.GasPrice == nil && opts.GasFeeCap == nil && opts.GasTipCap == nil {
		head, err := client.HeaderByNumber(context.Background(), nil)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get latest block header: %w", err)
		}

		if head.BaseFee != nil {
			// EIP-1559 transaction (dynamic fee)
			opts.GasFeeCap = new(big.Int).Add(head.BaseFee, defaultMaxPriorityFeePerGas)
			opts.GasTipCap = defaultMaxPriorityFeePerGas
		} else {
			// Legacy transaction
			opts.GasPrice = big.NewInt(2e9) // 2 Gwei
		}
	}

	tx, err := u.Manager.SendTransaction(opts, u.network, simulatorType, client, &bind.Address, input)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to send swapExactTokensForETH transaction: %w", err)
	}

	receipt, err := u.Manager.WaitForReceipt(u.ctx, network, simulatorType, client, tx.Hash())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get swapExactTokensForETH transaction receipt: %w", err)
	}

	return tx, receipt, nil
}

func DefaultUniswapV2BindOptions() []*BindOptions {
	return []*BindOptions{
		{
			Networks:  []utils.Network{utils.Ethereum, utils.AnvilNetwork},
			NetworkID: utils.EthereumNetworkID,
			Name:      "UniswapV2: Router",
			Type:      UniswapV2Router,
			Address:   common.HexToAddress("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"),
			ABI:       `[{"inputs":[{"internalType":"address","name":"_factory","type":"address"},{"internalType":"address","name":"_WETH","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"WETH","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"tokenA","type":"address"},{"internalType":"address","name":"tokenB","type":"address"},{"internalType":"uint256","name":"amountADesired","type":"uint256"},{"internalType":"uint256","name":"amountBDesired","type":"uint256"},{"internalType":"uint256","name":"amountAMin","type":"uint256"},{"internalType":"uint256","name":"amountBMin","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"addLiquidity","outputs":[{"internalType":"uint256","name":"amountA","type":"uint256"},{"internalType":"uint256","name":"amountB","type":"uint256"},{"internalType":"uint256","name":"liquidity","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"amountTokenDesired","type":"uint256"},{"internalType":"uint256","name":"amountTokenMin","type":"uint256"},{"internalType":"uint256","name":"amountETHMin","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"addLiquidityETH","outputs":[{"internalType":"uint256","name":"amountToken","type":"uint256"},{"internalType":"uint256","name":"amountETH","type":"uint256"},{"internalType":"uint256","name":"liquidity","type":"uint256"}],"stateMutability":"payable","type":"function"},{"inputs":[],"name":"factory","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountOut","type":"uint256"},{"internalType":"uint256","name":"reserveIn","type":"uint256"},{"internalType":"uint256","name":"reserveOut","type":"uint256"}],"name":"getAmountIn","outputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"}],"stateMutability":"pure","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"},{"internalType":"uint256","name":"reserveIn","type":"uint256"},{"internalType":"uint256","name":"reserveOut","type":"uint256"}],"name":"getAmountOut","outputs":[{"internalType":"uint256","name":"amountOut","type":"uint256"}],"stateMutability":"pure","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountOut","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"}],"name":"getAmountsIn","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"}],"name":"getAmountsOut","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountA","type":"uint256"},{"internalType":"uint256","name":"reserveA","type":"uint256"},{"internalType":"uint256","name":"reserveB","type":"uint256"}],"name":"quote","outputs":[{"internalType":"uint256","name":"amountB","type":"uint256"}],"stateMutability":"pure","type":"function"},{"inputs":[{"internalType":"address","name":"tokenA","type":"address"},{"internalType":"address","name":"tokenB","type":"address"},{"internalType":"uint256","name":"liquidity","type":"uint256"},{"internalType":"uint256","name":"amountAMin","type":"uint256"},{"internalType":"uint256","name":"amountBMin","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"removeLiquidity","outputs":[{"internalType":"uint256","name":"amountA","type":"uint256"},{"internalType":"uint256","name":"amountB","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"liquidity","type":"uint256"},{"internalType":"uint256","name":"amountTokenMin","type":"uint256"},{"internalType":"uint256","name":"amountETHMin","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"removeLiquidityETH","outputs":[{"internalType":"uint256","name":"amountToken","type":"uint256"},{"internalType":"uint256","name":"amountETH","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"liquidity","type":"uint256"},{"internalType":"uint256","name":"amountTokenMin","type":"uint256"},{"internalType":"uint256","name":"amountETHMin","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"removeLiquidityETHSupportingFeeOnTransferTokens","outputs":[{"internalType":"uint256","name":"amountETH","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"liquidity","type":"uint256"},{"internalType":"uint256","name":"amountTokenMin","type":"uint256"},{"internalType":"uint256","name":"amountETHMin","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"},{"internalType":"bool","name":"approveMax","type":"bool"},{"internalType":"uint8","name":"v","type":"uint8"},{"internalType":"bytes32","name":"r","type":"bytes32"},{"internalType":"bytes32","name":"s","type":"bytes32"}],"name":"removeLiquidityETHWithPermit","outputs":[{"internalType":"uint256","name":"amountToken","type":"uint256"},{"internalType":"uint256","name":"amountETH","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"liquidity","type":"uint256"},{"internalType":"uint256","name":"amountTokenMin","type":"uint256"},{"internalType":"uint256","name":"amountETHMin","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"},{"internalType":"bool","name":"approveMax","type":"bool"},{"internalType":"uint8","name":"v","type":"uint8"},{"internalType":"bytes32","name":"r","type":"bytes32"},{"internalType":"bytes32","name":"s","type":"bytes32"}],"name":"removeLiquidityETHWithPermitSupportingFeeOnTransferTokens","outputs":[{"internalType":"uint256","name":"amountETH","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"tokenA","type":"address"},{"internalType":"address","name":"tokenB","type":"address"},{"internalType":"uint256","name":"liquidity","type":"uint256"},{"internalType":"uint256","name":"amountAMin","type":"uint256"},{"internalType":"uint256","name":"amountBMin","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"},{"internalType":"bool","name":"approveMax","type":"bool"},{"internalType":"uint8","name":"v","type":"uint8"},{"internalType":"bytes32","name":"r","type":"bytes32"},{"internalType":"bytes32","name":"s","type":"bytes32"}],"name":"removeLiquidityWithPermit","outputs":[{"internalType":"uint256","name":"amountA","type":"uint256"},{"internalType":"uint256","name":"amountB","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountOut","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapETHForExactTokens","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountOutMin","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapExactETHForTokens","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountOutMin","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapExactETHForTokensSupportingFeeOnTransferTokens","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"},{"internalType":"uint256","name":"amountOutMin","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapExactTokensForETH","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"},{"internalType":"uint256","name":"amountOutMin","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapExactTokensForETHSupportingFeeOnTransferTokens","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"},{"internalType":"uint256","name":"amountOutMin","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapExactTokensForTokens","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"},{"internalType":"uint256","name":"amountOutMin","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapExactTokensForTokensSupportingFeeOnTransferTokens","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountOut","type":"uint256"},{"internalType":"uint256","name":"amountInMax","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapTokensForExactETH","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountOut","type":"uint256"},{"internalType":"uint256","name":"amountInMax","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapTokensForExactTokens","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"nonpayable","type":"function"},{"stateMutability":"payable","type":"receive"}]`,
		},
		{
			Networks:  []utils.Network{utils.Ethereum, utils.AnvilNetwork},
			NetworkID: utils.EthereumNetworkID,
			Name:      "UniswapV2: Factory Contract",
			Type:      UniswapV2Factory,
			Address:   common.HexToAddress("0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f"),
			ABI:       `[{"inputs":[{"internalType":"address","name":"_feeToSetter","type":"address"}],"payable":false,"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"token0","type":"address"},{"indexed":true,"internalType":"address","name":"token1","type":"address"},{"indexed":false,"internalType":"address","name":"pair","type":"address"},{"indexed":false,"internalType":"uint256","name":"","type":"uint256"}],"name":"PairCreated","type":"event"},{"constant":true,"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"allPairs","outputs":[{"internalType":"address","name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"allPairsLength","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"tokenA","type":"address"},{"internalType":"address","name":"tokenB","type":"address"}],"name":"createPair","outputs":[{"internalType":"address","name":"pair","type":"address"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"feeTo","outputs":[{"internalType":"address","name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"feeToSetter","outputs":[{"internalType":"address","name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"address","name":"","type":"address"}],"name":"getPair","outputs":[{"internalType":"address","name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"_feeTo","type":"address"}],"name":"setFeeTo","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"_feeToSetter","type":"address"}],"name":"setFeeToSetter","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"}]`,
		},
		{
			Networks:  []utils.Network{utils.Ethereum, utils.AnvilNetwork},
			NetworkID: utils.EthereumNetworkID,
			Name:      "UniswapV2: Pair",
			Type:      UniswapV2Pair,
			Address:   common.HexToAddress("0x3356c9a8f40f8e9c1d192a4347a76d18243fabc5"),
			ABI:       `[{"inputs":[],"payable":false,"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"owner","type":"address"},{"indexed":true,"internalType":"address","name":"spender","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"sender","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount0","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"amount1","type":"uint256"},{"indexed":true,"internalType":"address","name":"to","type":"address"}],"name":"Burn","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"sender","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount0","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"amount1","type":"uint256"}],"name":"Mint","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"sender","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount0In","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"amount1In","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"amount0Out","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"amount1Out","type":"uint256"},{"indexed":true,"internalType":"address","name":"to","type":"address"}],"name":"Swap","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint112","name":"reserve0","type":"uint112"},{"indexed":false,"internalType":"uint112","name":"reserve1","type":"uint112"}],"name":"Sync","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"from","type":"address"},{"indexed":true,"internalType":"address","name":"to","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"}],"name":"Transfer","type":"event"},{"constant":true,"inputs":[],"name":"DOMAIN_SEPARATOR","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"MINIMUM_LIQUIDITY","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"PERMIT_TYPEHASH","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"address","name":"","type":"address"}],"name":"allowance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"}],"name":"approve","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"to","type":"address"}],"name":"burn","outputs":[{"internalType":"uint256","name":"amount0","type":"uint256"},{"internalType":"uint256","name":"amount1","type":"uint256"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"decimals","outputs":[{"internalType":"uint8","name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"factory","outputs":[{"internalType":"address","name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"getReserves","outputs":[{"internalType":"uint112","name":"_reserve0","type":"uint112"},{"internalType":"uint112","name":"_reserve1","type":"uint112"},{"internalType":"uint32","name":"_blockTimestampLast","type":"uint32"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"_token0","type":"address"},{"internalType":"address","name":"_token1","type":"address"}],"name":"initialize","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"kLast","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"to","type":"address"}],"name":"mint","outputs":[{"internalType":"uint256","name":"liquidity","type":"uint256"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"name","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"nonces","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"},{"internalType":"uint256","name":"deadline","type":"uint256"},{"internalType":"uint8","name":"v","type":"uint8"},{"internalType":"bytes32","name":"r","type":"bytes32"},{"internalType":"bytes32","name":"s","type":"bytes32"}],"name":"permit","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"price0CumulativeLast","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"price1CumulativeLast","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"to","type":"address"}],"name":"skim","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"uint256","name":"amount0Out","type":"uint256"},{"internalType":"uint256","name":"amount1Out","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"swap","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"symbol","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[],"name":"sync","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"token0","outputs":[{"internalType":"address","name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"token1","outputs":[{"internalType":"address","name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"}],"name":"transfer","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"from","type":"address"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"}],"name":"transferFrom","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"}]`,
		},
	}
}
