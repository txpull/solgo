package inspector

import (
	"context"
	"math/big"

	ast_pb "github.com/unpackdev/protos/dist/go/ast"
	"github.com/unpackdev/solgo/accounts"
	"github.com/unpackdev/solgo/ast"
	"github.com/unpackdev/solgo/bindings"
	"github.com/unpackdev/solgo/utils"
	"go.uber.org/zap"
)

type AuditResults struct {
	Detected                    bool              `json:"detected"`
	HoneyPot                    bool              `json:"honey_pot"`
	ApproveEnabled              bool              `json:"approve_enabled"`
	ApproveTx                   string            `json:"approve_tx"`
	ApproveStatus               int               `json:"approve_status"`
	BuyEnabled                  bool              `json:"buy_enabled"`
	BuyTax                      *big.Float        `json:"buy_tax"`
	SellEnabled                 bool              `json:"sell_enabled"`
	SellTax                     *big.Float        `json:"sell_tax"`
	FaucetAccount               *accounts.Account `json:"faucet_account"`
	FaucetAccountInitialBalance *big.Int          `json:"faucet_account_initial_balance"`
}

type AuditDetector struct {
	ctx context.Context
	*Inspector
	results *AuditResults
}

func NewAuditDetector(ctx context.Context, inspector *Inspector) Detector {
	return &AuditDetector{
		ctx:       ctx,
		Inspector: inspector,
		results:   &AuditResults{},
	}
}

func (m *AuditDetector) Name() string {
	return "State Variable Detector"
}

func (m *AuditDetector) Type() DetectorType {
	return AuditDetectorType
}

func (m *AuditDetector) Enter(ctx context.Context) (DetectorFn, error) {
	return map[ast_pb.NodeType]func(node ast.Node[ast.NodeType]) (bool, error){}, nil
}

func (m *AuditDetector) Detect(ctx context.Context) (DetectorFn, error) {
	if m.GetDetector() != nil && m.GetDetector().GetIR() != nil && m.GetDetector().GetIR().GetRoot() != nil {
		report := m.GetReport()
		if report.HasDetector(TokenDetectorType) {
			if tokenDetector, ok := report.GetDetector(TokenDetectorType).(*TokenResults); ok && tokenDetector.Detected {
				if client := m.GetBindingManager().GetClient().GetClientByGroup(string(utils.Ethereum)); client != nil {
					latestBlock, err := client.HeaderByNumber(ctx, nil)
					if err != nil {
						zap.L().Error(
							"failed to get latest block",
							zap.Error(err),
							zap.Any("network", utils.Ethereum),
							zap.Any("address", m.GetAddress().Hex()),
						)
						return map[ast_pb.NodeType]func(node ast.Node[ast.NodeType]) (bool, error){}, err
					}

					// Following function will return client by block. In case that block is not yet ready it will spawn new anvil node
					// and wait for it to be ready. Once it's ready it will return the client.
					client, err := m.sim.GetClient(ctx, utils.AnvilSimulator, latestBlock.Number)
					if err != nil {
						zap.L().Error(
							"failed to get simulated client",
							zap.Error(err),
							zap.Any("simulator", utils.AnvilSimulator),
							zap.Any("network", utils.AnvilNetwork),
							zap.Any("address", m.GetAddress().Hex()),
						)
						return map[ast_pb.NodeType]func(node ast.Node[ast.NodeType]) (bool, error){}, err
					}

					bindingManager, err := bindings.NewManager(ctx, m.sim.GetProvider(utils.AnvilSimulator).GetClientPool())
					if err != nil {
						zap.L().Error(
							"failed to create binding manager",
							zap.Error(err),
							zap.Any("simulator", utils.AnvilSimulator),
							zap.Any("network", utils.AnvilNetwork),
							zap.Any("address", m.GetAddress().Hex()),
						)
						return map[ast_pb.NodeType]func(node ast.Node[ast.NodeType]) (bool, error){}, err
					}

					uniswapBind, err := bindings.NewUniswap(ctx, utils.AnvilNetwork, bindingManager, bindings.DefaultUniswapBindOptions())
					if err != nil {
						zap.L().Error(
							"failed to create uniswap bindings",
							zap.Error(err),
							zap.Any("simulator", utils.AnvilSimulator),
							zap.Any("network", utils.AnvilNetwork),
							zap.Any("address", m.GetAddress().Hex()),
						)
						return map[ast_pb.NodeType]func(node ast.Node[ast.NodeType]) (bool, error){}, err
					}

					tokenBind, err := bindings.NewToken(ctx, utils.AnvilNetwork, bindingManager, bindings.DefaultTokenBindOptions(m.GetAddress()))
					if err != nil {
						zap.L().Error(
							"failed to create token bindings",
							zap.Error(err),
							zap.Any("simulator", utils.AnvilSimulator),
							zap.Any("network", utils.AnvilNetwork),
							zap.Any("address", m.GetAddress().Hex()),
						)
						return map[ast_pb.NodeType]func(node ast.Node[ast.NodeType]) (bool, error){}, err
					}

					ethAddr, err := uniswapBind.WETH()
					if err != nil {
						zap.L().Error(
							"failed to get WETH address",
							zap.Error(err),
							zap.Any("simulator", utils.AnvilSimulator),
							zap.Any("network", utils.AnvilNetwork),
							zap.Any("address", m.GetAddress().Hex()),
						)
						return map[ast_pb.NodeType]func(node ast.Node[ast.NodeType]) (bool, error){}, err
					}

					// Lets figure out what the pair address is...
					_, err = uniswapBind.GetPair(m.GetAddress(), ethAddr)
					if err != nil {
						zap.L().Error(
							"failed to get pair address",
							zap.Error(err),
							zap.Any("simulator", utils.AnvilSimulator),
							zap.Any("network", utils.AnvilNetwork),
							zap.Any("address", m.GetAddress().Hex()),
							zap.Any("eth_address", ethAddr.Hex()),
						)
						return map[ast_pb.NodeType]func(node ast.Node[ast.NodeType]) (bool, error){}, err
					}

					anvilProvider := m.sim.GetProvider(utils.AnvilSimulator)
					if _, found := anvilProvider.GetNodeByBlockNumber(latestBlock.Number); found {
						account := m.sim.GetFaucet().List(utils.AnvilNetwork)[0]
						m.results.FaucetAccount = account
						faucetInitialBalance, err := tokenBind.BalanceOf(account.Address)
						if err != nil {
							zap.L().Error(
								"failed to get faucet account balance",
								zap.Error(err),
								zap.Any("simulator", utils.AnvilSimulator),
								zap.Any("network", utils.AnvilNetwork),
								zap.Any("address", m.GetAddress().Hex()),
								zap.Any("eth_address", ethAddr.Hex()),
								zap.Any("faucet_address", account.Address.Hex()),
							)
							return map[ast_pb.NodeType]func(node ast.Node[ast.NodeType]) (bool, error){}, err
						}
						m.results.FaucetAccountInitialBalance = faucetInitialBalance

						uniswapAddr, err := uniswapBind.GetAddress(bindings.UniswapV2Router)
						if err != nil {
							zap.L().Error(
								"failed to get uniswap address",
								zap.Error(err),
								zap.Any("simulator", utils.AnvilSimulator),
								zap.Any("network", utils.AnvilNetwork),
								zap.Any("address", m.GetAddress().Hex()),
								zap.Any("eth_address", ethAddr.Hex()),
								zap.Any("faucet_address", account.Address.Hex()),
							)
							return map[ast_pb.NodeType]func(node ast.Node[ast.NodeType]) (bool, error){}, err
						}

						purchaseAmount := new(big.Int).Mul(big.NewInt(10), new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(tokenDetector.Decimals)), nil))
						authApprove, err := account.TransactOpts(client, purchaseAmount, true)
						if err != nil {
							zap.L().Error(
								"failed to create transaction options",
								zap.Error(err),
								zap.Any("simulator", utils.AnvilSimulator),
								zap.Any("network", utils.AnvilNetwork),
								zap.Any("address", m.GetAddress().Hex()),
								zap.Any("eth_address", ethAddr.Hex()),
								zap.Any("faucet_address", account.Address.Hex()),
							)
							return map[ast_pb.NodeType]func(node ast.Node[ast.NodeType]) (bool, error){}, err
						}

						_, approveReceiptTx, err := tokenBind.Approve(authApprove, uniswapAddr, purchaseAmount, false)
						if err != nil {
							zap.L().Error(
								"failed to approve tokens",
								zap.Error(err),
								zap.Any("simulator", utils.AnvilSimulator),
								zap.Any("network", utils.AnvilNetwork),
								zap.Any("address", m.GetAddress().Hex()),
								zap.Any("eth_address", ethAddr.Hex()),
								zap.Any("faucet_address", account.Address.Hex()),
							)
							return map[ast_pb.NodeType]func(node ast.Node[ast.NodeType]) (bool, error){}, err
						}

						m.results.ApproveEnabled = true
						m.results.ApproveTx = approveReceiptTx.TxHash.Hex()
						m.results.ApproveStatus = int(approveReceiptTx.Status)

					}

					m.results.Detected = true

					_ = client
				}

				//simBinding, err := bindings.NewSimulatedManager(m.ctx, m.GetStorage(), m.GetBindingManager(), m.GetAddress(), m.GetDetector())
			}
		}
	}
	return map[ast_pb.NodeType]func(node ast.Node[ast.NodeType]) (bool, error){}, nil
}

func (m *AuditDetector) Exit(ctx context.Context) (DetectorFn, error) {
	return map[ast_pb.NodeType]func(node ast.Node[ast.NodeType]) (bool, error){}, nil
}

func (m *AuditDetector) Results() any {
	return m.results
}
