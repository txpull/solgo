package ir

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/txpull/solgo"
	"github.com/txpull/solgo/tests"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestIrBuilderFromSources(t *testing.T) {
	config := zap.NewDevelopmentConfig()
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	logger, err := config.Build()
	assert.NoError(t, err)

	// Replace the global logger.
	zap.ReplaceGlobals(logger)

	// Define multiple test cases
	testCases := []struct {
		name                 string
		outputPath           string
		sources              solgo.Sources
		expected             string
		unresolvedReferences int64
	}{
		{
			name:       "Empty Contract Test",
			outputPath: "ast/",
			sources: solgo.Sources{
				SourceUnits: []*solgo.SourceUnit{
					{
						Name:    "Empty",
						Path:    tests.ReadContractFileForTest(t, "Empty").Path,
						Content: tests.ReadContractFileForTest(t, "Empty").Content,
					},
				},
				EntrySourceUnitName:  "Empty",
				MaskLocalSourcesPath: false,
				LocalSourcesPath:     "../sources/",
			},
			expected:             tests.ReadJsonBytesForTest(t, "ast/Empty.solgo.ast").Content,
			unresolvedReferences: 0,
		},
		{
			name:       "Simple Storage Contract Test",
			outputPath: "ast/",
			sources: solgo.Sources{
				SourceUnits: []*solgo.SourceUnit{
					{
						Name:    "MathLib",
						Path:    "MathLib.sol",
						Content: tests.ReadContractFileForTest(t, "ast/MathLib").Content,
					},
					{
						Name:    "SimpleStorage",
						Path:    "SimpleStorage.sol",
						Content: tests.ReadContractFileForTest(t, "ast/SimpleStorage").Content,
					},
				},
				EntrySourceUnitName:  "SimpleStorage",
				MaskLocalSourcesPath: true,
				LocalSourcesPath:     buildFullPath("../sources/"),
			},
			expected:             tests.ReadJsonBytesForTest(t, "ast/SimpleStorage.solgo.ast").Content,
			unresolvedReferences: 0,
		},
		{
			name:       "OpenZeppelin ERC20 Test",
			outputPath: "ast/",
			sources: solgo.Sources{
				SourceUnits: []*solgo.SourceUnit{
					{
						Name:    "SafeMath",
						Path:    "SafeMath.sol",
						Content: tests.ReadContractFileForTest(t, "ast/SafeMath").Content,
					},
					{
						Name:    "IERC20",
						Path:    "IERC20.sol",
						Content: tests.ReadContractFileForTest(t, "ast/IERC20").Content,
					},
					{
						Name:    "IERC20Metadata",
						Path:    "IERC20Metadata.sol",
						Content: tests.ReadContractFileForTest(t, "ast/IERC20Metadata").Content,
					},
					{
						Name:    "Context",
						Path:    "Context.sol",
						Content: tests.ReadContractFileForTest(t, "ast/Context").Content,
					},
					{
						Name:    "ERC20",
						Path:    "ERC20.sol",
						Content: tests.ReadContractFileForTest(t, "ast/ERC20").Content,
					},
				},
				EntrySourceUnitName:  "ERC20",
				MaskLocalSourcesPath: true,
				LocalSourcesPath:     "../sources/",
			},
			expected:             tests.ReadJsonBytesForTest(t, "ast/ERC20.solgo.ast").Content,
			unresolvedReferences: 0,
		},
		/*
			{
				name:       "Token Sale ERC20 Test",
				outputPath: "ast/",
				sources: solgo.Sources{
					SourceUnits: []*solgo.SourceUnit{
						{
							Name:    "TokenSale",
							Path:    "TokenSale.sol",
							Content: tests.ReadContractFileForTest(t, "ast/TokenSale").Content,
						},
						{
							Name:    "SafeMath",
							Path:    "SafeMath.sol",
							Content: tests.ReadContractFileForTest(t, "ast/SafeMath").Content,
						},
						{
							Name:    "IERC20",
							Path:    "IERC20.sol",
							Content: tests.ReadContractFileForTest(t, "ast/IERC20").Content,
						},
					},
					EntrySourceUnitName: "TokenSale",
					LocalSourcesPath:    "../sources/",
				},
				expected:             tests.ReadJsonBytesForTest(t, "ast/TokenSale.solgo.ast").Content,
				unresolvedReferences: 0,
			},
			{
				name:       "Lottery Test",
				outputPath: "ast/",
				sources: solgo.Sources{
					SourceUnits: []*solgo.SourceUnit{
						{
							Name:    "Lottery",
							Path:    "Lottery.sol",
							Content: tests.ReadContractFileForTest(t, "ast/Lottery").Content,
						},
					},
					EntrySourceUnitName: "Lottery",
					LocalSourcesPath:    "../sources/",
				},
				expected:             tests.ReadJsonBytesForTest(t, "ast/Lottery.solgo.ast").Content,
				unresolvedReferences: 0,
			},
			{
				name:       "Cheelee Test", // Took this one as I could discover ipfs metadata :joy:
				outputPath: "contracts/cheelee/",
				sources: solgo.Sources{
					SourceUnits: []*solgo.SourceUnit{
						{
							Name:    "Import",
							Path:    "Import.sol",
							Content: tests.ReadContractFileForTest(t, "contracts/cheelee/Import").Content,
						},
						{
							Name:    "BeaconProxy",
							Path:    "BeaconProxy.sol",
							Content: tests.ReadContractFileForTest(t, "contracts/cheelee/BeaconProxy").Content,
						},
						{
							Name:    "UpgradeableBeacon",
							Path:    "UpgradeableBeacon.sol",
							Content: tests.ReadContractFileForTest(t, "contracts/cheelee/UpgradeableBeacon").Content,
						},
						{
							Name:    "ERC1967Proxy",
							Path:    "ERC1967Proxy.sol",
							Content: tests.ReadContractFileForTest(t, "contracts/cheelee/ERC1967Proxy").Content,
						},
						{
							Name:    "TransparentUpgradeableProxy",
							Path:    "TransparentUpgradeableProxy.sol",
							Content: tests.ReadContractFileForTest(t, "contracts/cheelee/TransparentUpgradeableProxy").Content,
						},
						{
							Name:    "ProxyAdmin",
							Path:    "ProxyAdmin.sol",
							Content: tests.ReadContractFileForTest(t, "contracts/cheelee/ProxyAdmin").Content,
						},
						{
							Name:    "IBeacon",
							Path:    "IBeacon.sol",
							Content: tests.ReadContractFileForTest(t, "contracts/cheelee/IBeacon").Content,
						},
						{
							Name:    "Proxy",
							Path:    "Proxy.sol",
							Content: tests.ReadContractFileForTest(t, "contracts/cheelee/Proxy").Content,
						},
						{
							Name:    "ERC1967Upgrade",
							Path:    "ERC1967Upgrade.sol",
							Content: tests.ReadContractFileForTest(t, "contracts/cheelee/ERC1967Upgrade").Content,
						},
						{
							Name:    "Address",
							Path:    "Address.sol",
							Content: tests.ReadContractFileForTest(t, "contracts/cheelee/Address").Content,
						},
						{
							Name:    "StorageSlot",
							Path:    "StorageSlot.sol",
							Content: tests.ReadContractFileForTest(t, "contracts/cheelee/StorageSlot").Content,
						},
						{
							Name:    "Ownable",
							Path:    "Ownable.sol",
							Content: tests.ReadContractFileForTest(t, "contracts/cheelee/Ownable").Content,
						},
						{
							Name:    "Context",
							Path:    "Context.sol",
							Content: tests.ReadContractFileForTest(t, "contracts/cheelee/Context").Content,
						},
					},
					EntrySourceUnitName: "TransparentUpgradeableProxy",
					LocalSourcesPath:    buildFullPath("../sources/"),
				},
				expected:             tests.ReadJsonBytesForTest(t, "contracts/cheelee/TransparentUpgradeableProxy.solgo.ast").Content,
				unresolvedReferences: 0,
			}, */
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			parser, err := NewBuilderFromSources(context.TODO(), testCase.sources)
			assert.NoError(t, err)
			assert.NotNil(t, parser)

			// Important step which will parse the sources and build the AST including check for
			// reference errors and syntax errors.
			// If you wish to only parse the sources without checking for errors, use
			// parser.GetParser().Parse()
			assert.Empty(t, parser.Parse())

			// Now we can get into the business of building the intermediate representation
			assert.NoError(t, parser.Build())

			// Get the root node of the IR
			root := parser.GetRoot()
			assert.NotNil(t, root)

			pretty, err := parser.ToJSONPretty()
			assert.NoError(t, err)
			assert.NotNil(t, pretty)
			fmt.Println(string(pretty))

		})
	}
}

func buildFullPath(relativePath string) string {
	absPath, _ := filepath.Abs(relativePath)
	return absPath
}