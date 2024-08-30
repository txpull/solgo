package simulator

import (
	"context"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unpackdev/solgo/clients"
	"github.com/unpackdev/solgo/utils"
)

// CreateNewTestSimulator initializes and configures a new Simulator instance for testing purposes.
// It performs the following steps:
//  1. Determines the current working directory and verifies it's not empty.
//  2. Sets up the keystore path, which is assumed to be one level up from the current directory.
//  3. Establishes a base simulator with predefined options such as keystore path, supported networks,
//     faucet configurations, and a default password for the accounts.
//  4. Creates a new AnvilProvider instance with specified options including network settings,
//     client count limits, process ID path, executable path, and port range.
//  5. Registers the AnvilProvider with the newly created simulator.
//
// Returns the initialized Simulator instance and an error if any occurs during the setup process.
// This function utilizes the 'assert' and 'require' packages from 'testify' to ensure that each setup step is successful.
func CreateNewTestSimulator(ctx context.Context, clientPool *clients.ClientPool, t *testing.T, opts *AnvilProviderOptions) (*Simulator, error) {
	tAssert := assert.New(t)

	// Get the current working directory
	cwd, err := os.Getwd()
	tAssert.NoError(err)
	tAssert.NotEmpty(cwd)

	// Navigate up one level
	keystorePath := filepath.Join(filepath.Dir(cwd), "data", "faucets")

	// Establish base simulator
	// It acts as a faucet provider and manager for all the simulation providers.
	// It also provides a way to manage the simulation providers.
	simulator, err := NewSimulator(ctx, clientPool, &Options{
		KeystorePath:                keystorePath,
		SupportedNetworks:           []utils.Network{utils.Ethereum, utils.AnvilNetwork},
		FaucetsEnabled:              true,
		FaucetAccountCount:          10,
		FaucetAccountDefaultBalance: new(big.Int).Mul(big.NewInt(1000), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)),
		DefaultPassword:             "wearegoingtogethacked",
	})

	require.NoError(t, err)
	tAssert.NotNil(simulator)

	if opts == nil {
		opts = &AnvilProviderOptions{
			Network:             utils.AnvilNetwork,
			NetworkID:           utils.EthereumNetworkID,
			ClientCount:         1,
			MaxClientCount:      10,
			AutoImpersonate:     true,
			PidPath:             filepath.Join("/", "tmp", ".solgo", "/", "simulator", "/", "anvil"),
			AnvilExecutablePath: os.Getenv("SOLGO_ANVIL_PATH"),
			Fork:                true,
			ForkEndpoint:        os.Getenv("SOLGO_SIMULATOR_FORK_ENDPOINT"),
			IPAddr:              net.ParseIP("127.0.0.1"),
			StartPort:           5400,
			EndPort:             5500,
		}
	}

	anvilProvider, err := NewAnvilProvider(ctx, simulator, opts)

	require.NoError(t, err)
	tAssert.NotNil(anvilProvider)

	simulator.RegisterProvider(utils.AnvilSimulator, anvilProvider)

	return simulator, nil
}
