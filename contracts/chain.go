package contracts

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/unpackdev/solgo/bindings"
	"github.com/unpackdev/solgo/utils"
)

// DiscoverChainInfo retrieves information about the contract's deployment chain, including transaction, receipt, and block details.
// If `otsLookup` is true, it queries the contract creator's information using the provided context. If `otsLookup` is false or
// if the creator's information is not available, it queries the contract creation transaction hash using etherscan.
// It then fetches the transaction, receipt, and block information associated with the contract deployment from the blockchain.
// This method populates the contract descriptor with the retrieved information.
func (c *Contract) DiscoverChainInfo(ctx context.Context, otsLookup bool) error {
	var info *bindings.CreatorInformation

	// What we are going to do, as erigon node is used in this particular case, is to query etherscan only if
	// otterscan is not available.
	if otsLookup {
		var err error
		info, err = c.bindings.GetContractCreator(ctx, c.network, c.addr)
		if err != nil {
			return fmt.Errorf("failed to get contract creator: %w", err)
		}
	}


	var txHash common.Hash

	/*	if info == nil || info.CreationHash == utils.ZeroHash {
		cInfo, err := c.hypersync.GetContractCreator(ctx, c.addr)
		if err != nil && !errors.Is(err, errorshs.ErrContractNotFound) {
			return errors.Wrap(err, "failed to get contract creator transaction information")
		} else if cInfo != nil {
			txHash = cInfo.Hash
		}
	}*/

	if info == nil || info.CreationHash == utils.ZeroHash {
		// Prior to continuing with the unpacking of the contract, we want to make sure that we can reach properly
		// contract transaction and associated creation block. If we can't, we're not going to unpack it.
		cInfo, err := c.etherscan.QueryContractCreationTx(ctx, c.addr)
		if err != nil {
			return fmt.Errorf("failed to query contract creation block and tx hash: %w", err)
		}
		txHash = cInfo.GetTransactionHash()
	} else {
		txHash = info.CreationHash
	}

	// Alright now lets extract block and transaction as well as receipt from the blockchain.
	// We're going to use archive node for this, as we want to be sure that we can get all the data.

	tx, _, err := c.client.TransactionByHash(ctx, txHash)
	if err != nil {
		return fmt.Errorf("failed to get transaction by hash: %s", err)
	}
	c.descriptor.Transaction = tx

	receipt, err := c.client.TransactionReceipt(ctx, txHash)
	if err != nil {
		return fmt.Errorf("failed to get transaction receipt by hash: %s", err)
	}
	c.descriptor.Receipt = receipt

	block, err := c.client.HeaderByNumber(ctx, receipt.BlockNumber)
	if err != nil {
		return fmt.Errorf("failed to get block by number: %s", err)
	}
	c.descriptor.Block = block

	if len(c.descriptor.ExecutionBytecode) < 1 {
		c.descriptor.ExecutionBytecode = c.descriptor.Transaction.Data()
	}

	if len(c.descriptor.DeployedBytecode) < 1 {
		code, err := c.client.CodeAt(ctx, receipt.ContractAddress, nil)
		if err != nil {
			return fmt.Errorf("failed to get contract code: %s", err)
		}
		c.descriptor.DeployedBytecode = code
	}

	return nil
}
