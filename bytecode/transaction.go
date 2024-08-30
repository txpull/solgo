package bytecode

import (
	"bytes"
	"fmt"
	"strings"

	abi "github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/unpackdev/solgo/utils"
)

// Transaction encapsulates a decoded Ethereum transaction, providing detailed information
// about the transaction's method, its arguments, and the associated ABI.
// This structured format makes it easier to work with Ethereum transactions programmatically.
type Transaction struct {
	Abi            string                      `json:"abi"`             // ABI string of the transaction's method.
	SignatureBytes []byte                      `json:"signature_bytes"` // Raw signature bytes of the transaction.
	Signature      string                      `json:"signature"`       // Human-readable signature of the transaction's method.
	Type           utils.TransactionMethodType `json:"type"`            // Type of the transaction, classified by its method name.
	Name           string                      `json:"name"`            // Name of the transaction's method.
	Method         *abi.Method                 `json:"-"`               // ABI method information, not serialized to JSON.
	Inputs         map[string]interface{}      `json:"inputs"`          // Decoded arguments passed to the transaction's method.
}

// DecodeTransactionFromAbi decodes an Ethereum transaction using the provided ABI.
// It extracts the method signature and arguments from the raw transaction data, constructing
// a Transaction object that includes this information along with the method's ABI.
//
// The function requires the raw transaction data (`data`) and the ABI of the smart contract
// (`abiData`) in JSON format. It returns a pointer to a Transaction object, populated with
// the decoded method information and its arguments, or an error if decoding fails.
//
// This function simplifies the process of interacting with raw Ethereum transactions, making
// it easier to analyze and use the transaction data programmatically.
func DecodeTransactionFromAbi(data []byte, abiData []byte) (*Transaction, error) {
	// The first 4 bytes of the data represent the ID of the method in the ABI.
	methodSigData := data[:4]

	contractABI, err := abi.JSON(bytes.NewReader(abiData))
	if err != nil {
		return nil, fmt.Errorf("failed to parse abi: %s", err)
	}

	method, err := contractABI.MethodById(methodSigData)
	if err != nil {
		return nil, fmt.Errorf("failed to get method by id: %s", err)
	}

	inputsSigData := data[4:]
	inputsMap := make(map[string]interface{})
	if err := method.Inputs.UnpackIntoMap(inputsMap, inputsSigData); err != nil {
		return nil, fmt.Errorf("failed to unpack inputs into map: %s", err)
	}

	txAbi, err := utils.MethodToABI(method)
	if err != nil {
		return nil, fmt.Errorf("failure to cast method into abi: %w", err)
	}

	return &Transaction{
		Abi:            txAbi,
		SignatureBytes: methodSigData,
		Signature:      method.String(),
		Name:           method.Name,
		Method:         method,
		Type:          func() utils.TransactionMethodType {
			if len(method.Name) > 0 {
				return  utils.TransactionMethodType(strings.ToLower(method.Name))
			}
			return utils.UnknownTransactionMethodType
		}(),
		Inputs:         inputsMap,
	}, nil
}
