package simulator

import (
	"github.com/ethereum/go-ethereum/common"
)

// https://book.getfoundry.sh/reference/anvil/#custom-methods
// TODO: We should integrate all anvil custom methods into the simulator package.
// WARN: Methods such as autoImpersonateAccount, reset, setRpcUrl, setLoggingEnabled have direct impact to the nodes and simulator
// and should be treated according.

// ImpersonateAccount requests the binding manager to impersonate a specified account.
// This is typically used in a testing environment to simulate transactions and interactions
// from the perspective of the given account.
func (a *AnvilProvider) ImpersonateAccount(contract common.Address) (common.Address, error) {
	return a.bindingManager.ImpersonateAccount(a.Network(), contract)
}

// StopImpersonateAccount instructs the binding manager to stop impersonating a specified account.
// This method reverts the effects of ImpersonateAccount, ceasing any further simulation of transactions
// or interactions from the perspective of the given account.
func (a *AnvilProvider) StopImpersonateAccount(contract common.Address) (common.Address, error) {
	return a.bindingManager.StopImpersonateAccount(a.Network(), contract)
}
