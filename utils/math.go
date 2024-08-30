package utils

import "math/big"

func Pow(i, e *big.Int) *big.Int {
	return new(big.Int).Exp(i, e, nil)
}
