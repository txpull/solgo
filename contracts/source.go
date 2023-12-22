package contracts

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/unpackdev/solgo"
	"go.uber.org/zap"
)

func (c *Contract) DiscoverSourceCode(ctx context.Context) error {
	response, err := c.etherscan.ScanContract(c.addr)
	if err != nil {
		if !strings.Contains(err.Error(), "not found") &&
			!strings.Contains(err.Error(), "not verified") { // Do not print error if contract is not found. Just clusterfucks the logs...
			zap.L().Error(
				"failed to scan contract source code",
				zap.Error(err),
				zap.String("network", c.network.String()),
				zap.String("contract_address", c.addr.String()),
			)
		}
		return fmt.Errorf("failed to scan contract source code from %s: %s", c.etherscan.ProviderName(), err)
	}
	c.descriptor.SourcesRaw = response

	sources, err := solgo.NewSourcesFromEtherScan(response.Name, response.SourceCode)
	if err != nil {
		zap.L().Error(
			"failed to create new sources from etherscan response",
			zap.Error(err),
			zap.String("network", c.network.String()),
			zap.String("contract_address", c.addr.String()),
		)
		return fmt.Errorf("failed to create new sources from etherscan response: %s", err)
	}

	c.descriptor.Sources = sources
	c.descriptor.License = c.descriptor.SourcesRaw.LicenseType

	// Contract has no source code available. This is not critical error but annoyance that we can't decompile
	// contract's source code. @TODO: Figure out with external toolings how to decompile bytecode...
	// However we could potentially get information such as ABI from etherscan for future use...
	// We are setting it here, however we are going to replace it with the one from the sources if we have it.

	optimized, err := strconv.ParseBool(c.descriptor.SourcesRaw.OptimizationUsed)
	if err != nil {
		zap.L().Error(
			"failed to parse OptimizationUsed to bool",
			zap.Error(err),
			zap.String("OptimizationUsed", c.descriptor.SourcesRaw.OptimizationUsed),
		)
		return err
	}

	optimizationRuns, err := strconv.ParseUint(c.descriptor.SourcesRaw.Runs, 10, 64)
	if err != nil {
		zap.L().Error(
			"failed to parse OptimizationRuns to uint64",
			zap.Error(err),
			zap.String("OptimizationRuns", c.descriptor.SourcesRaw.Runs),
		)
		return err
	}

	c.descriptor.Name = response.Name
	c.descriptor.CompilerVersion = c.descriptor.SourcesRaw.CompilerVersion
	c.descriptor.Optimized = optimized
	c.descriptor.OptimizationRuns = optimizationRuns
	c.descriptor.EVMVersion = c.descriptor.SourcesRaw.EVMVersion
	c.descriptor.ABI = c.descriptor.SourcesRaw.ABI
	c.descriptor.SourcesProvider = c.etherscan.ProviderName()
	c.descriptor.Verified = true
	c.descriptor.VerificationProvider = c.etherscan.ProviderName()

	return nil
}
