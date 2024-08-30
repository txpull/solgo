package contracts

import (
	"context"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/unpackdev/solgo/detector"
	"github.com/unpackdev/solgo/utils"
	"go.uber.org/zap"
)

// Parse processes the source code of the contract to update its metadata, including detecting
// contract features and parsing its source to build an intermediate representation (IR).
func (c *Contract) Parse(ctx context.Context) error {
	// Defer a function to catch and handle a panic
	// TODO: Will be great day we can drop this off and have no panic recovery at all!
	defer func() {
		if r := recover(); r != nil {
			zap.L().Error(
				"Recovered from panic while parsing contract...",
				zap.Any("panic", r),
				zap.String("contract_address", c.addr.String()),
			)
		}
	}()

	// We are interested in an attempt to decompile source code only if we actually have source code available.
	if c.descriptor.Sources != nil && c.descriptor.Sources.HasUnits() {
		parser, err := detector.NewDetectorFromSources(ctx, c.compiler, c.descriptor.Sources)
		if err != nil {
			zap.L().Error(
				"Failed to create detector from sources",
				zap.Error(err),
				zap.Any("network", c.network),
				zap.String("contract_address", c.addr.String()),
			)
			return err
		}

		// Sets the address for more understanding when we need to troubleshoot contract parsing
		parser.GetIR().SetAddress(c.addr)

		c.descriptor.Detector = parser
		c.descriptor.SolgoVersion = utils.GetBuildVersionByModule("github.com/unpackdev/solgo")

		// Up until this point all is good for all contracts, however, from this stage moving forward
		// we are getting into issues where we are not capable ATM to parse contracts with < 0.6.0 version.
		// Because of it, we are going to disable all functionality for this particular contract related to
		// source code parsing. :( In the future we should sort this out, but right now, MVP is the most important thing.
		if utils.IsSemanticVersionLowerOrEqualTo(c.descriptor.CompilerVersion, utils.SemanticVersion{Major: 0, Minor: 4, Patch: 0}) {
			// There are some contracts we want to ensure to go through parsing logic regardless of semantic versioning check
			// ETH: 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 - 0.4.19 - WETH9
			// NOTE: Temporary allowing all of the 0.4+
			if c.descriptor.Address != common.HexToAddress("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2") {
				return fmt.Errorf("not supported compiler version (older version): %v", c.descriptor.CompilerVersion)
			}
		}

		if errs := parser.Parse(); errs != nil {
			for _, err := range errs {
				zap.L().Debug(
					"failed to parse contract sources",
					zap.Error(err),
					zap.Any("network", c.network),
					zap.String("contract_address", c.addr.String()),
				)
			}
		}

		if err := parser.Build(); err != nil {
			zap.L().Error(
				"failed to build contract sources",
				zap.Error(err),
				zap.Any("network", c.network),
				zap.String("contract_address", c.addr.String()),
			)
			return err
		}
		c.descriptor.IRRoot = parser.GetIR().GetRoot()

		// What we should update here is get basically missing information from external sources corrected now...
		if c.descriptor.Name == "" {
			c.descriptor.Name = c.descriptor.IRRoot.GetEntryName()
		}

		if c.descriptor.License == "" || c.descriptor.License == "None" && c.descriptor.IRRoot.GetEntryContract() != nil {
			c.descriptor.License = c.descriptor.IRRoot.GetEntryContract().GetLicense()
			c.descriptor.License = strings.ReplaceAll(c.descriptor.License, "\r", "")
			c.descriptor.License = strings.ReplaceAll(c.descriptor.License, "\n", "")
			c.descriptor.License = strings.TrimSpace(c.descriptor.License)
			c.descriptor.License = strings.ToLower(c.descriptor.License)
		}
	}

	return nil
}
