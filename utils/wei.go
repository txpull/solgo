package utils

import (
	"github.com/unpackdev/solgo/utils/entities"
	"math/big"
)

var Ether = big.NewInt(1e18)
var GWei = big.NewInt(1e9)

// FromWei converts a balance in wei to Ether.
func FromWei(wei *big.Int, token *entities.Token) *entities.CurrencyAmount {
	if wei == nil || token == nil {
		return nil
	}
	return entities.FromRawAmount(token, wei)
}

func ToOne(token *entities.Token) *entities.CurrencyAmount {
	if token == nil {
		return nil
	}

	divisor := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(token.Decimals())), nil)
	return entities.FromRawAmount(token, divisor)
}

func ToMany(amount *big.Int, token *entities.Token) *entities.CurrencyAmount {
	if amount == nil || token == nil {
		return nil
	}

	divisor := new(big.Int).Mul(amount, ToOne(token).Quotient())
	return entities.FromRawAmount(token, divisor)
}
