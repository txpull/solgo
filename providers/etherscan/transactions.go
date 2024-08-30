package etherscan

import (
	"context"
	"errors"
	"fmt"
	"github.com/goccy/go-json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// ContractCreation represents the creation details of a smart contract, including
// its address, creator's address, and the transaction hash of the creation transaction.
type ContractCreation struct {
	Address         string `json:"contractAddress"` // The smart contract address.
	CreatorAddress  string `json:"contractCreator"` // The address of the creator of the contract.
	TransactionHash string `json:"txHash"`          // The hash of the transaction that created the contract.
}

// MarshalBinary implements encoding.BinaryMarshaler to provide binary encoding for a ContractCreation.
func (c *ContractCreation) MarshalBinary() ([]byte, error) {
	return json.Marshal(c)
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler to provide binary decoding for a ContractCreation.
func (c *ContractCreation) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, c)
}

// GetTransactionHash returns the Ethereum transaction hash of the contract creation as a common.Hash.
func (c *ContractCreation) GetTransactionHash() common.Hash {
	return common.HexToHash(c.TransactionHash)
}

// ContractCreationResponse encapsulates the API response for a contract creation query,
// containing the status, message, and the result of the query.
type ContractCreationResponse struct {
	Status  string              `json:"status"`  // The response status.
	Message string              `json:"message"` // A descriptive message of the response.
	Result  []*ContractCreation `json:"result"`  // The contract creation details.
}

// QueryContractCreationTx queries the blockchain for contract creation details given a contract address.
// It first checks for cached responses; if none are found, it queries the Etherscan API directly.
//
// This function returns a ContractCreation if found, or an error if the query fails, the response
// is not satisfactory, or the result cannot be properly unmarshaled.
func (e *Provider) QueryContractCreationTx(ctx context.Context, addr common.Address) (*ContractCreation, error) {
	if e.cache != nil {
		cacheKey := e.CacheKey("getcontractcreation", addr.Hex())
		if result, err := e.cache.Exists(e.ctx, cacheKey).Result(); err == nil && result == 1 {
			if result, err := e.cache.Get(e.ctx, cacheKey).Result(); err == nil {
				var response *ContractCreation
				if err := json.Unmarshal([]byte(result), &response); err != nil {
					return nil, fmt.Errorf("failed to unmarshal %s response: %s", e.ProviderName(), err)
				}
				return response, nil
			}
		}
	}

	url := fmt.Sprintf(
		"%s?module=contract&action=getcontractcreation&contractaddresses=%s&apikey=%s",
		e.opts.Endpoint, addr.Hex(), e.GetNextKey(),
	)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to send HTTP request: %s", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %s", err)
	}

	if strings.Contains(string(body), "NOTOK") {
		var creationResponse ErrorResponse
		if err := json.Unmarshal(body, &creationResponse); err != nil {
			return nil, fmt.Errorf("failed to unmarshal error response: %s", err)
		}

		return nil, errors.New(creationResponse.Result)
	}

	var creationResponse ContractCreationResponse
	if err := json.Unmarshal(body, &creationResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal contract creation response: %s - %s", err, url)
	}

	if e.cache != nil {
		cacheKey := e.CacheKey("getcontractcreation", addr.Hex())
		if len(creationResponse.Result) > 0 {
			if err := e.cache.Set(e.ctx, cacheKey, creationResponse.Result[0], 1*time.Hour).Err(); err != nil {
				return nil, fmt.Errorf("failed to write to cache: %s", err)
			}
		}
	}

	if creationResponse.Result == nil || len(creationResponse.Result) == 0 {
		return nil, fmt.Errorf("failed to find contract creation response for addr: %s", addr.Hex())
	}

	return creationResponse.Result[0], nil
}
