package etherscan

import (
	"context"
	"errors"
	"fmt"
	"github.com/goccy/go-json"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/unpackdev/solgo/metadata"
)

// Contract represents the detailed information of a smart contract
// including its source code, ABI, and other metadata as returned by the Etherscan API.
type Contract struct {
	SourceCode           interface{} `json:"SourceCode"`           // The source code of the contract. Can be a plain string or a structured metadata object.
	ABI                  string      `json:"ABI"`                  // The ABI (Application Binary Interface) of the contract in JSON format.
	Name                 string      `json:"ContractName"`         // The name of the contract.
	CompilerVersion      string      `json:"CompilerVersion"`      // The version of the Solidity compiler used to compile the contract.
	OptimizationUsed     string      `json:"OptimizationUsed"`     // Indicates if optimization was used during compilation.
	Runs                 string      `json:"Runs"`                 // The number of runs specified for the optimizer.
	ConstructorArguments string      `json:"ConstructorArguments"` // The constructor arguments used when deploying the contract.
	EVMVersion           string      `json:"EVMVersion"`           // The version of the Ethereum Virtual Machine (EVM) for which the contract was compiled.
	Library              string      `json:"Library"`              // Specifies any library used in the contract.
	LicenseType          string      `json:"LicenseType"`          // The license type under which the contract source code is provided.
	Proxy                string      `json:"Proxy"`                // Indicates if the contract is a proxy contract.
	Implementation       string      `json:"Implementation"`       // The address of the implementation contract, if this is a proxy contract.
	SwarmSource          string      `json:"SwarmSource"`          // The Swarm source of the contract's metadata.
}

// MarshalBinary implements the encoding.BinaryMarshaler interface for Contract.
// It returns the JSON encoding of the contract.
func (c Contract) MarshalBinary() ([]byte, error) {
	return json.Marshal(c)
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface for Contract.
// It parses a JSON-encoded contract and stores the result in the Contract.
func (c Contract) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, c)
}

// ContractResponse encapsulates the response structure for contract queries
// made to the Etherscan API.
type ContractResponse struct {
	Status  string     `json:"status"`  // The status of the API response, "1" for success and "0" for failure.
	Message string     `json:"message"` // A message accompanying the status, often indicating the nature of any error.
	Result  []Contract `json:"result"`  // The contracts returned by the query, typically containing a single contract.
}

// ScanContract retrieves the source code and other related details of a smart contract
// from the Ethereum blockchain using the Etherscan API. It attempts to retrieve the data
// from a local cache first; if not available, it fetches it from the API. The address of
// the contract (addr) must be provided. On success, a Contract instance containing the
// source code and related metadata is returned. Various errors encountered during the
// data retrieval and parsing process, including API and network errors, are propagated.
func (e *Provider) ScanContract(ctx context.Context, addr common.Address) (*Contract, error) {
	cacheKey := e.CacheKey("getsourcecode_method_1", addr.Hex())

	if e.cache != nil {
		if result, err := e.cache.Exists(e.ctx, cacheKey).Result(); err == nil && result == 1 {
			if result, err := e.cache.Get(e.ctx, cacheKey).Result(); err == nil {
				var response *Contract
				if err := json.Unmarshal([]byte(result), &response); err != nil {
					return nil, fmt.Errorf("failed to unmarshal %s response: %s", e.ProviderName(), err)
				}
				return response, nil
			}
		}
	}

	// Wait for the next token to be available
	e.rateLimiter.WaitForToken()

	url := fmt.Sprintf(
		"%s?module=contract&action=getsourcecode&address=%s&apikey=%s",
		e.opts.Endpoint, addr.Hex(), e.GetNextKey(),
	)

	customHttpClient := &http.Client{
		// Timeout for the whole request, including dialing, reading the response, etc.
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			// Timeout for the connection to be established
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			// Timeout for the TLS handshake
			TLSHandshakeTimeout: 5 * time.Second,
			// Max idle connections per host
			MaxIdleConnsPerHost: 10,
			// Idle connection timeout
			IdleConnTimeout: 90 * time.Second,
		},
	}

	// Create a new request with context
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %s", err)
	}

	resp, err := customHttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send HTTP request: %s", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %s", err)
	}

	if strings.Contains(string(body), "NOTOK") {
		var contractResponse ErrorResponse
		if err := json.Unmarshal(body, &contractResponse); err != nil {
			return nil, fmt.Errorf("failed to unmarshal error response: %s", err)
		}
		return nil, fmt.Errorf("%s - %s", contractResponse.Result, url)
	}

	var contractResponse ContractResponse
	if err := json.Unmarshal(body, &contractResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal etherscan response: %s - %s", err, url)
	}

	toReturn := contractResponse.Result[0]

	if toReturn.ABI == "Contract source code not verified" {
		return nil, fmt.Errorf("contract source code not verified")
	}

	// Well we have standard metadata response probably from IPFS within the source code and we need to parse it...
	// Not to mention with excuse Etherscan bullshit we need to unquote it manually...
	if len(toReturn.SourceCode.(string)) > 2 && (toReturn.SourceCode.(string)[:2] == "{{" || toReturn.SourceCode.(string)[:1] == "{") {
		cm := metadata.ContractMetadata{}

		// This is just nasty, but I don't really care at this moment...
		sourceCode, _ := prepareJSON(manualUnquote(toReturn.SourceCode.(string)))

		if err := json.Unmarshal([]byte(sourceCode), &cm); err != nil {
			var onlySources map[string]metadata.ContractSource
			if nErr := json.Unmarshal([]byte(fmt.Sprint(toReturn.SourceCode.(string))), &onlySources); nErr != nil {
				return nil, fmt.Errorf("failed to unmarshal metadata response (string): %w", errors.Join(err, nErr))
			} else {
				cm.Sources = onlySources
			}

		}

		toReturn.SourceCode = cm
	} else if _, ok := toReturn.SourceCode.(map[string]interface{}); ok {
		cm := metadata.ContractMetadata{}
		encoded, _ := json.Marshal(toReturn.SourceCode)
		if err := json.Unmarshal(encoded, &cm); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata response (map): %s", err)
		}
		toReturn.SourceCode = cm
	}

	if toReturn.ABI == "Contract source code not verified" {
		return nil, fmt.Errorf("contract not found")
	}

	if e.cache != nil {
		if err := e.cache.Set(e.ctx, cacheKey, toReturn, 1*time.Hour).Err(); err != nil {
			return nil, fmt.Errorf("failed to write to cache: %s", err)
		}
	}

	return &toReturn, nil
}

// manualUnquote handles specific cases of encoded JSON strings that need to be
// manually adjusted before unmarshalling. It primarily deals with removing
// excess quotation marks and brackets from JSON-encoded strings.
func manualUnquote(s string) string {
	// Check if it starts with `{{` and ends with `}}`
	if strings.HasPrefix(s, "{{") && strings.HasSuffix(s, "}}") {
		s = "{" + s[2:len(s)-2] + "}"
	}

	return s
}

// prepareJSON converts a formatted (pretty) JSON string into a compact,
// unformatted string. This is useful for processing JSON strings that need
// to be compacted for storage or further processing.
func prepareJSON(prettyJSON string) (string, error) {
	var data interface{}

	// Unmarshal the pretty JSON into an interface{}
	err := json.Unmarshal([]byte(prettyJSON), &data)
	if err != nil {
		return "", fmt.Errorf("error unmarshaling JSON: %w", err)
	}

	// Marshal the data back into JSON without indentation
	compactJSON, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("error marshaling JSON: %w", err)
	}

	return string(compactJSON), nil
}
