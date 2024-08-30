package simulator

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unpackdev/solgo/clients"
	"github.com/unpackdev/solgo/utils"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestSimulatorConnectivity(t *testing.T) {
	tAssert := assert.New(t)

	config := zap.NewDevelopmentConfig()
	config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	logger, err := config.Build()
	tAssert.NoError(err)
	zap.ReplaceGlobals(logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	simulator, err := CreateNewTestSimulator(ctx, nil, t, nil)
	require.NoError(t, err)
	require.NotNil(t, simulator)
	defer simulator.Close()

	testCases := []struct {
		name      string
		provider  utils.SimulatorType
		expectErr bool
	}{
		{
			name:      "Anvil simulator start and stop with periodic status checks",
			provider:  utils.AnvilSimulator,
			expectErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			err := simulator.Start(ctx)
			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			for i := 0; i < 2; i++ {
				statuses, err := simulator.Status(ctx)
				if tc.expectErr {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
					tAssert.NotNil(statuses)
				}

				anvilStatuses, found := statuses.GetNodesByType(utils.AnvilSimulator)
				tAssert.NotNil(anvilStatuses)
				tAssert.True(found)
				tAssert.Exactly(1, len(anvilStatuses))

				time.Sleep(300 * time.Millisecond)
			}

			err = simulator.Stop(ctx)
			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAnvilSimulator(t *testing.T) {
	tAssert := assert.New(t)

	config := zap.NewDevelopmentConfig()
	config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	logger, err := config.Build()
	tAssert.NoError(err)
	zap.ReplaceGlobals(logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clientOptions := &clients.Options{
		Nodes: []clients.Node{
			{
				Group:                   string(utils.Ethereum),
				Type:                    "mainnet",
				Endpoint:                "https://ethereum.publicnode.com",
				NetworkId:               1,
				ConcurrentClientsNumber: 1,
			},
		},
	}

	pool, err := clients.NewClientPool(ctx, clientOptions)
	tAssert.NoError(err)
	tAssert.NotNil(pool)

	simulator, err := CreateNewTestSimulator(ctx, nil, t, nil)
	require.NoError(t, err)
	require.NotNil(t, simulator)
	defer simulator.Close()

	err = simulator.Start(ctx)
	require.NoError(t, err)

	defer func() {
		err := simulator.Stop(ctx)
		require.NoError(t, err)
	}()

	testCases := []struct {
		name      string
		provider  utils.SimulatorType
		expectErr bool
		testFunc  func(t *testing.T, simulator *Simulator, name string, provider utils.SimulatorType, expectErr bool)
	}{
		{
			name:      "Anvil simulator periodic status checks",
			provider:  utils.AnvilSimulator,
			expectErr: false,
			testFunc: func(t *testing.T, simulator *Simulator, name string, provider utils.SimulatorType, expectErr bool) {
				ctx, cancel := context.WithCancel(ctx)
				defer cancel()

				for i := 0; i < 2; i++ {
					statuses, err := simulator.Status(ctx)
					if expectErr {
						require.Error(t, err)
					} else {
						require.NoError(t, err)
						tAssert.NotNil(statuses)
					}

					anvilStatuses, found := statuses.GetNodesByType(utils.AnvilSimulator)
					tAssert.NotNil(anvilStatuses)
					tAssert.True(found)
					tAssert.Exactly(1, len(anvilStatuses))

					time.Sleep(100 * time.Millisecond)
				}

			},
		},
		{
			name:      "Get anvil client from latest block",
			provider:  utils.AnvilSimulator,
			expectErr: false,
			testFunc: func(t *testing.T, simulator *Simulator, name string, provider utils.SimulatorType, expectErr bool) {
				ctx, cancel := context.WithCancel(ctx)
				defer cancel()

				client := pool.GetClientByGroup(string(utils.Ethereum))
				require.NotNil(t, client)

				latestBlock, err := client.HeaderByNumber(ctx, nil)
				require.NoError(t, err)
				require.NotNil(t, latestBlock)

				simulatorClient, node, err := simulator.GetClient(ctx, utils.AnvilSimulator, latestBlock.Number)
				if expectErr {
					require.Error(t, err)
					require.Nil(t, simulatorClient)
					require.Nil(t, node)
				} else {
					require.NoError(t, err)
					require.NotNil(t, simulatorClient)
					require.NotNil(t, node)
				}

				// Just for testing purpose lets fetch from each faucet account balance at latest block
				for _, account := range simulator.GetFaucet().List(utils.AnvilNetwork) {
					balance, err := simulatorClient.BalanceAt(ctx, account.GetAddress(), nil)
					require.NoError(t, err)
					require.NotNil(t, balance)
				}

				anvilProvider, found := ToAnvilProvider(simulator.GetProvider(utils.AnvilSimulator))
				require.True(t, found)
				require.NotNil(t, anvilProvider)

				// Some random etherscan address... (Have no affiliation with it)
				randomAddress := common.HexToAddress("0x235eE805F962690254e9a440E01574376136ecb1")

				impersonatedAddr, err := anvilProvider.ImpersonateAccount(randomAddress)
				require.NoError(t, err)
				require.Equal(t, randomAddress, impersonatedAddr)

				impersonatedAddr, err = anvilProvider.StopImpersonateAccount(randomAddress)
				require.NoError(t, err)
				require.Equal(t, randomAddress, impersonatedAddr)
			},
		},
		{
			name:      "Attempt to impersonate account and to stop impersonating account",
			provider:  utils.AnvilSimulator,
			expectErr: false,
			testFunc: func(t *testing.T, simulator *Simulator, name string, provider utils.SimulatorType, expectErr bool) {
				ctx, cancel := context.WithCancel(ctx)
				defer cancel()

				client := pool.GetClientByGroup(string(utils.Ethereum))
				require.NotNil(t, client)

				latestBlock, err := client.HeaderByNumber(ctx, nil)
				require.NoError(t, err)
				require.NotNil(t, latestBlock)

				simulatorClient, node, err := simulator.GetClient(ctx, utils.AnvilSimulator, latestBlock.Number)
				if expectErr {
					require.Error(t, err)
					require.Nil(t, simulatorClient)
					require.Nil(t, node)
				} else {
					require.NoError(t, err)
					require.NotNil(t, simulatorClient)
					require.NotNil(t, node)
				}

				// Just for testing purpose lets fetch from each faucet account balance at latest block
				for _, account := range simulator.GetFaucet().List(utils.AnvilNetwork) {
					balance, err := simulatorClient.BalanceAt(ctx, account.GetAddress(), nil)
					require.NoError(t, err)
					require.NotNil(t, balance)
					fmt.Println("Balance", balance)
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.testFunc(t, simulator, tc.name, tc.provider, tc.expectErr)
		})
	}
}
