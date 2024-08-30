package contracts

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/unpackdev/solgo/bytecode"
	"github.com/unpackdev/solgo/utils"
	"go.uber.org/zap"
)

// DiscoverConstructor discovers and decodes the constructor of the contract based on the provided context.
// It utilizes the contract's descriptor to gather information about the contract's bytecode, ABI, and transaction data.
// If a constructor is found in the bytecode, it decodes it using the provided ABI.
// The decoded constructor information is stored within the contract descriptor.
func (c *Contract) DiscoverConstructor(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return nil
	default:
		if c.descriptor.Detector != nil && c.descriptor.Detector.GetIR() != nil && c.descriptor.Detector.GetIR().GetRoot() != nil {
			detector := c.descriptor.Detector
			irRoot := detector.GetIR().GetRoot()
			abiRoot := detector.GetABI().GetRoot()

			if irRoot.GetEntryContract() != nil && irRoot.GetEntryContract().GetConstructor() != nil &&
				abiRoot != nil && abiRoot.GetEntryContract().GetMethodByType("constructor") != nil {
				cAbi, _ := utils.ToJSON(abiRoot.GetEntryContract().GetMethodByType("constructor"))
				constructorAbi := fmt.Sprintf("[%s]", string(cAbi))
				//utils.DumpNodeWithExit(abiRoot.GetEntryContract().GetMethodByType("constructor"))
				//utils.DumpNodeWithExit(irRoot.GetEntryContract().GetConstructor().GetParameters())
				tx := c.descriptor.Transaction
				deployedBytecode := c.descriptor.DeployedBytecode

				// Ensure that empty bytecode is not processed, otherwise:
				// panic: runtime error: slice bounds out of range [:20] with capacity 0
				// TODO: Consider applying error here, not sure if we should really.
				if len(deployedBytecode) < 20 {
					return nil
				}

				position := bytes.Index(tx.Data(), deployedBytecode[:20])
				if position != -1 {
					adjustedData := tx.Data()[position:]
					constructorDataIndex := len(deployedBytecode)
					if constructorDataIndex > len(adjustedData) {
						return fmt.Errorf("constructor data index out of range")
					}

					// TODO: Fix
					// - 0x47CE0C6eD5B0Ce3d3A51fdb1C52DC66a7c3c2936 (239 bytes more) - Some shitty text...
					//spew.Dump(hex.EncodeToString(tx.Data()))
					//fmt.Println("")
					//spew.Dump(hex.EncodeToString(adjustedData[constructorDataIndex:]))
					//spew.Dump(constructorAbi) // 239
					//utils.DumpNodeWithExit(irRoot.GetEntryContract().GetConstructor().GetParameters())
					constructor, err := bytecode.DecodeConstructorFromAbi(adjustedData[constructorDataIndex:], constructorAbi)
					if err != nil {
						if !strings.Contains(err.Error(), "would go over slice boundary") {
							zap.L().Error(
								"failed to decode constructor from bytecode",
								zap.Error(err),
								zap.Any("network", c.network),
								zap.String("contract_address", c.addr.String()),
							)
						}
						return fmt.Errorf("failed to decode constructor from bytecode: %s", err)
					}
					c.descriptor.Constructor = constructor
				}
			}
		}

		return nil
	}
}
