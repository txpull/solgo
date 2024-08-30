package accounts

import (
	"context"
	"encoding/base64"
	"fmt"
	account "github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/goccy/go-json"
	"github.com/unpackdev/solgo/clients"
	"github.com/unpackdev/solgo/utils"
	"log"
	"math/big"
	"os"
)

const (
	DEFAULT_GAS_LIMIT = uint64(90000)
)

// Account represents an Ethereum account with extended functionalities.
// It embeds ClientPool for network interactions and KeyStore for account management.
// It also includes fields for account details, network information, and additional tags.
type Account struct {
	client             *clients.Client
	*keystore.KeyStore `json:"-" yaml:"-"` // KeyStore for managing account keys
	Address            common.Address      `json:"address" yaml:"address"`         // Ethereum address of the account
	Type               utils.AccountType   `json:"type" yaml:"type"`               // Account type
	PrivateKey         string              `json:"private_key" yaml:"private_key"` // Private key of the account
	PublicKey          string              `json:"public_key" yaml:"public_key"`   // Public key of the account
	KeystoreAccount    account.Account     `json:"account" yaml:"account"`         // Ethereum account information
	Password           string              `json:"password" yaml:"password"`       // Account's password
	Network            utils.Network       `json:"network" yaml:"network"`         // Network information
	Tags               []string            `json:"tags" yaml:"tags"`               // Arbitrary tags for the account
}

// HasTag checks if the account has a specific tag.
// Returns true if the tag exists, false otherwise.
func (a *Account) HasTag(tag string) bool {
	for _, t := range a.Tags {
		if t == tag {
			return true
		}
	}

	return false
}

// DecodePassword decodes the base64-encoded password.
// Returns the decoded password or an error if decoding fails.
func (a *Account) DecodePassword() (string, error) {
	passwd, err := base64.StdEncoding.DecodeString(a.Password)
	return string(passwd), err
}

// GetAddress retrieves the Ethereum address of the account.
func (a *Account) GetAddress() common.Address {
	return a.Address
}

// SetClient assigns a specific Ethereum client to the account for network interactions.
func (a *Account) SetClient(client *clients.Client) {
	a.client = client
}

// GetClient retrieves the assigned Ethereum client associated with the account.
func (a *Account) GetClient() *clients.Client {
	return a.client
}

// SetAccountBalance sets the account's balance to a specific amount.
// This method is mainly used for testing purposes in simulation environments like Anvil.
// It does not affect the real balance on the Ethereum network.
func (a *Account) SetAccountBalance(ctx context.Context, amount *big.Int) error {
	return a.client.GetRpcClient().CallContext(ctx, nil, "anvil_setBalance", a.GetAddress(), amount.String())
}

// Balance retrieves the account's balance from the Ethereum network at a specified block number.
// Returns the balance as *big.Int or an error if the balance query fails.
func (a *Account) Balance(ctx context.Context, blockNum *big.Int) (*big.Int, error) {
	balance, err := a.client.BalanceAt(ctx, a.Address, blockNum)
	if err != nil {
		return big.NewInt(0), err
	}

	return balance, nil
}

// TransactOpts generates transaction options for interacting with the Ethereum network.
// It configures nonce, gas price, gas limit, and value for the transaction.
// The method also handles different account types: simple and keystore-based accounts.
// For simple accounts, it directly uses the provided private key.
// For keystore accounts, it decrypts the key using the stored password.
// If 'simulate' is true, it returns transaction options without signing.
func (a *Account) TransactOpts(client *clients.Client, amount *big.Int, simulate bool) (*bind.TransactOpts, error) {
	nonce, err := client.NonceAt(context.Background(), a.Address, nil)
	if err != nil {
		return nil, err
	}

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, err
	}

	if !simulate {
		if a.Type == utils.SimpleAccountType {
			/*			privateKey, err := crypto.HexToECDSA(strings.TrimLeft(a.PrivateKey, "0x"))
						if err != nil {
							return nil, err
						}*/

			/*			auth, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(client.GetNetworkID()))
						if err != nil {
							return nil, err
						}

						auth.Nonce = big.NewInt(int64(nonce))
						auth.GasPrice = gasPrice
						auth.GasLimit = DEFAULT_GAS_LIMIT
						auth.Value = amount
						return auth, nil*/
			return nil, nil
		} else if a.Type == utils.KeystoreAccountType {
			password, _ := a.DecodePassword()

			keyJson, err := os.ReadFile(a.KeystoreAccount.URL.Path)
			if err != nil {
				log.Fatalf("Failed to read the keystore file: %v", err)
			}

			// Decrypt the key with the password
			key, err := keystore.DecryptKey(keyJson, password)
			if err != nil {
				log.Fatalf("Failed to decrypt key: %v", err)
			}

			auth, err := bind.NewKeyedTransactorWithChainID(key.PrivateKey, big.NewInt(client.GetNetworkID()))
			if err != nil {
				return nil, err
			}

			auth.Nonce = big.NewInt(int64(nonce))
			auth.GasPrice = gasPrice
			auth.GasLimit = DEFAULT_GAS_LIMIT
			auth.Value = amount
			return auth, nil
		} else {
			return nil, fmt.Errorf("failure to build transact opts due to invalid account type: %s", a.Type)
		}
	}

	return &bind.TransactOpts{
		From:     a.Address,
		GasPrice: gasPrice,
		GasLimit: DEFAULT_GAS_LIMIT,
		Nonce:    big.NewInt(int64(nonce)),
		Context:  context.Background(),
		Value:    amount,
	}, nil
}

// Transfer initiates an Ethereum transfer from this account to another address.
// It ensures the account has sufficient balance and then constructs and signs a transaction.
// The method uses the account's stored passphrase for signing.
// Returns the signed transaction or an error if the transfer process fails.
func (a *Account) Transfer(ctx context.Context, to common.Address, value *big.Int) (*types.Transaction, error) {
	currentBalance, err := a.Balance(ctx, nil)
	if err != nil {
		return nil, err
	}

	if currentBalance.Cmp(value) < 0 {
		return nil, fmt.Errorf("insufficient balance")
	}

	passwd, err := a.DecodePassword()
	if err != nil {
		return nil, fmt.Errorf("failed to decode password: %s", err.Error())
	}

	nonce, err := a.client.PendingNonceAt(context.Background(), a.Address)
	if err != nil {
		return nil, err
	}

	gasLimit := uint64(21000)
	gasPrice, err := a.client.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, err
	}

	var data []byte
	tx := types.NewTransaction(nonce, to, value, gasLimit, gasPrice, data)

	signedTx, err := a.KeyStore.SignTxWithPassphrase(a.KeystoreAccount, passwd, tx, big.NewInt(a.client.GetNetworkID()))
	if err != nil {
		return nil, err
	}

	if err := a.client.SendTransaction(ctx, signedTx); err != nil {
		return nil, err
	}

	return signedTx, nil
}

// SaveToPath serializes the account information and writes it to a specified file path.
// The account data is saved in JSON format. Returns an error if the writing process fails.
func (a *Account) SaveToPath(path string) error {
	file, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, file, 0644)
}

// LoadAccount loads an account from a JSON file located at a given path.
// The method reads the file, unmarshals the JSON content into an Account struct,
// and returns the populated Account instance or an error if the loading process fails.
func LoadAccount(path string) (*Account, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var account Account
	err = json.Unmarshal(file, &account)
	if err != nil {
		return nil, err
	}
	account.Address = account.KeystoreAccount.Address
	account.Type = utils.KeystoreAccountType

	return &account, nil
}
