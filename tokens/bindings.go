package tokens

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/unpackdev/solgo/bindings"
)

// PrepareBindings initializes the token binding for the Token struct based on the current network and contract address.
func (t *Token) PrepareBindings(ctx context.Context) error {
	var err error
	t.tokenBind, err = t.GetTokenBind(ctx, t.bindManager)
	if err != nil {
		return fmt.Errorf("failed to get token bindings: %w", err)
	}
	return err
}

// GetUniswapV2Bind ...
func (t *Token) GetUniswapV2Bind(bindManager *bindings.Manager) (*bindings.UniswapV2, error) {
	return bindings.NewUniswapV2(t.ctx, t.network, bindManager, bindings.DefaultUniswapV2BindOptions())
}

// GetTokenBind connects to a blockchain simulator or live network to create a token binding.
// It uses bindings.Manager and can target a specific block number.
func (t *Token) GetTokenBind(ctx context.Context, bindManager *bindings.Manager) (*bindings.Token, error) {
	return bindings.NewToken(ctx, t.network, bindManager, bindings.DefaultTokenBindOptions(t.descriptor.Address))
}

func (t *Token) GetBinding() *bindings.Token {
	return t.tokenBind
}

// ResolveName fetches the name property of the token from the blockchain.
func (t *Token) ResolveName(ctx context.Context, from common.Address, bind *bindings.Token) (string, error) {
	return bind.GetName(ctx, from)
}

// ResolveSymbol fetches the symbol property of the token from the blockchain.
func (t *Token) ResolveSymbol(ctx context.Context, from common.Address, bind *bindings.Token) (string, error) {
	return bind.GetSymbol(ctx, from)
}

// ResolveDecimals fetches the decimals property of the token from the blockchain.
func (t *Token) ResolveDecimals(ctx context.Context, from common.Address, bind *bindings.Token) (uint8, error) {
	return bind.GetDecimals(ctx, from)
}

// ResolveTotalSupply fetches the total supply of the token from the blockchain.
func (t *Token) ResolveTotalSupply(ctx context.Context, from common.Address, bind *bindings.Token) (*big.Int, error) {
	return bind.GetTotalSupply(ctx, from)
}

// ResolveBalance retrieves the balance of a specific address for the token.
func (t *Token) ResolveBalance(ctx context.Context, from common.Address, bind *bindings.Token, address common.Address) (*big.Int, error) {
	return bind.BalanceOf(ctx, from, address)
}
