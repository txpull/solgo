package contracts

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"strconv"
	"strings"
	"time"

	"github.com/unpackdev/solgo"
	"github.com/unpackdev/solgo/providers/etherscan"
	"go.uber.org/zap"
)

// DiscoverSourceCode queries Etherscan (or another configured source code provider) to retrieve
// the source code and metadata for the smart contract at the specified address. It attempts to
// enrich the contract's descriptor with details such as the source code, compiler version,
// optimization settings, and contract ABI, among others.
//
// This method implements a retry mechanism to handle rate limiting by the provider. It logs
// and returns errors encountered during the process, except for cases where the contract
// source code is not found or not verified, which are considered non-critical errors.
func (c *Contract) DiscoverSourceCode(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return nil
	default:
		var response *etherscan.Contract // Assuming ScanResponse is the type returned by ScanContract
		var err error

		// Retry mechanism
		const maxRetries = 15
		for i := 0; i < maxRetries; i++ {
			dCtx, dCancel := context.WithTimeout(ctx, 60*time.Second)
			response, err = c.etherscan.ScanContract(dCtx, c.addr)
			if err != nil {
				if strings.Contains(err.Error(), "Max rate limit reached") ||
					strings.Contains(err.Error(), "context deadline exceeded") {
					// Wait for i*1000ms before retrying
					time.Sleep(time.Duration(i*1000) * time.Millisecond)
					dCancel()
					continue
				} else if strings.Contains(err.Error(), "Max calls per sec rate limit reached") {
					// Wait for i*1000ms before retrying
					time.Sleep(time.Duration(i*1000) * time.Millisecond)
					dCancel()
					continue
				} else if strings.Contains(err.Error(), "invalid character") {
					// Wait for i*1000ms before retrying
					time.Sleep(time.Duration(i*100) * time.Millisecond)
					dCancel()
					continue
				} else if strings.Contains(err.Error(), "connection reset by peer") {
					// Wait for i*1000ms before retrying
					time.Sleep(time.Duration(i*100) * time.Millisecond)
					dCancel()
					continue
				} else if strings.Contains(err.Error(), "i/o timeout") {
					// Wait for i*1000ms before retrying
					time.Sleep(time.Duration(i*100) * time.Millisecond)
					dCancel()
					continue
				} else if strings.Contains(err.Error(), "EOF") {
					// Wait for i*1000ms before retrying
					time.Sleep(time.Duration(i*100) * time.Millisecond)
					dCancel()
					continue
				} else if strings.Contains(err.Error(), "TLS handshake timeout") {
					// Wait for i*1000ms before retrying
					time.Sleep(time.Duration(i*100) * time.Millisecond)
					dCancel()
					continue
				} else if !strings.Contains(err.Error(), "not found") &&
					!strings.Contains(err.Error(), "not verified") {
					zap.L().Error(
						"failed to scan contract source code",
						zap.Error(err),
						zap.String("network", c.network.String()),
						zap.String("contract_address", c.addr.String()),
					)
				}
				dCancel()
				return fmt.Errorf("failed to scan contract source code from %s: %s", c.etherscan.ProviderName(), err)
			}
			dCancel()
			break // Exit loop if ScanContract is successful
		}

		// Handle the case when all retries fail
		if err != nil {
			return fmt.Errorf("after %d retries, failed to scan contract source code from %s: %s", maxRetries, c.etherscan.ProviderName(), err)
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

		unsortedSources, err := solgo.NewUnsortedSourcesFromEtherScan(response.Name, response.SourceCode)
		if err != nil {
			zap.L().Error(
				"failed to create new unsorted sources from etherscan response",
				zap.Error(err),
				zap.String("network", c.network.String()),
				zap.String("contract_address", c.addr.String()),
			)
			return fmt.Errorf("failed to create new unsorted sources from etherscan response: %s", err)
		}

		c.descriptor.Sources = sources
		c.descriptor.SourcesUnsorted = unsortedSources

		license := strings.ReplaceAll(c.descriptor.SourcesRaw.LicenseType, "\r", "")
		license = strings.ReplaceAll(license, "\n", "")
		license = strings.TrimSpace(c.descriptor.SourcesRaw.LicenseType)
		c.descriptor.License = license

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
		c.descriptor.UnitName = response.Name
		c.descriptor.CompilerVersion = c.descriptor.SourcesRaw.CompilerVersion
		c.descriptor.Optimized = optimized
		c.descriptor.OptimizationRuns = optimizationRuns
		c.descriptor.EVMVersion = c.descriptor.SourcesRaw.EVMVersion
		c.descriptor.ABI = c.descriptor.SourcesRaw.ABI
		c.descriptor.SourceProvider = c.etherscan.ProviderName()
		c.descriptor.Verified = true
		c.descriptor.VerificationProvider = c.etherscan.ProviderName()

		proxy, _ := strconv.ParseBool(response.Proxy)
		c.descriptor.Proxy = proxy

		if len(response.Implementation) > 10 {
			c.descriptor.Implementations = append(
				c.descriptor.Implementations,
				common.HexToAddress(response.Implementation),
			)
		}

		return nil
	}
}
