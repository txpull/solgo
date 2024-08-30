package simulator

import (
	"context"
	"fmt"
	"time"

	"github.com/unpackdev/solgo/accounts"
	"github.com/unpackdev/solgo/clients"
	"github.com/unpackdev/solgo/utils"
)

// Faucet is responsible for creating and managing simulated blockchain accounts.
// It integrates with solgo's accounts.Manager to leverage existing account management features.
// Faucet is primarily used in testing environments where multiple accounts with
// specific configurations are required.
type Faucet struct {
	*accounts.Manager
	ctx        context.Context
	opts       *Options
	clientPool *clients.ClientPool
}

// NewFaucet creates a new instance of Faucet. It requires a context and options to
// initialize the underlying accounts manager and other configurations.
// Returns an error if the options are not provided or if the accounts manager fails to initialize.
func NewFaucet(ctx context.Context, clientPool *clients.ClientPool, opts *Options) (*Faucet, error) {
	if opts == nil {
		return nil, fmt.Errorf("in order to create a new faucet, you must provide options")
	}

	manager, err := accounts.NewManager(ctx, clientPool, &accounts.Options{KeystorePath: opts.KeystorePath, SupportedNetworks: opts.SupportedNetworks})
	if err != nil {
		return nil, fmt.Errorf("failed to create new faucet manager: %w", err)
	}

	return &Faucet{
		ctx:        ctx,
		opts:       opts,
		Manager:    manager,
		clientPool: clientPool,
	}, nil
}

// Create generates a new simulated account for a specific network.
// This method is particularly useful in testing scenarios where multiple accounts
// are needed with different configurations. If no password is provided, the default
// password from Faucet options is used. The account can be optionally pinned, and
// additional tags can be assigned for further categorization or identification.
// Returns the created account or an error if the account creation fails.
func (f *Faucet) Create(network utils.Network, password string, pin bool, tags ...string) (*accounts.Account, error) {
	tags = append(tags, utils.SimulatorAccountType.String())

	var pwd string
	if password == "" {
		pwd = f.opts.DefaultPassword
	} else {
		pwd = password
	}

	var account *accounts.Account
	var err error
	attempts := 3
	for i := 0; i < attempts; i++ {
		account, err = f.Manager.Create(network, pwd, pin, tags...)
		if err == nil {
			time.Sleep(100 * time.Millisecond)
			return account, nil
		}
	}

	return nil, fmt.Errorf("failed to generate faucet account for network: %s after %d attempts, err: %s", network, attempts, err)
}
