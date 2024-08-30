package entities

import (
	"github.com/goccy/go-json"
	"math/big"

	"github.com/shopspring/decimal"
)

type CurrencyAmount struct {
	*Fraction    `json:"fraction"`
	Currency     Currency `json:"currency"`
	DecimalScale *big.Int `json:"decimalScale"`
}

func (c *CurrencyAmount) UnmarshalJSON(data []byte) error {
	var tempMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &tempMap); err != nil {
		return err
	}

	if fractionData, ok := tempMap["fraction"]; ok {
		fraction := &Fraction{}
		if err := json.Unmarshal(fractionData, fraction); err != nil {
			return err
		}
		c.Fraction = fraction
	}

	if decimalScaleData, ok := tempMap["decimalScale"]; ok {
		decimalScale := new(big.Int)
		if err := decimalScale.UnmarshalText(decimalScaleData); err != nil {
			return err
		}
		c.DecimalScale = decimalScale
	}

	if currencyData, ok := tempMap["currency"]; ok {
		// Attempt to unmarshal as BaseCurrency by default
		var baseCurrency BaseCurrency
		if err := json.Unmarshal(currencyData, &baseCurrency); err != nil {
			return err
		}
		c.Currency = &baseCurrency
	}

	return nil
}

/**
 * Returns a new currency amount instance from the unitless amount of token, i.e. the raw amount
 * @param currency the currency in the amount
 * @param rawAmount the raw token or ether amount
 */
func FromRawAmount(currency Currency, rawAmount *big.Int) *CurrencyAmount {
	return newCurrencyAmount(currency, rawAmount, big.NewInt(1))
}

/**
 * Construct a currency amount with a denominator that is not equal to 1
 * @param currency the currency
 * @param numerator the numerator of the fractional token amount
 * @param denominator the denominator of the fractional token amount
 */
func FromFractionalAmount(currency Currency, numerator *big.Int, denominator *big.Int) *CurrencyAmount {
	return newCurrencyAmount(currency, numerator, denominator)
}

// NewCurrencyAmount creates a new CurrencyAmount instance
func newCurrencyAmount(currency Currency, numerator, denominator *big.Int) *CurrencyAmount {
	f := NewFraction(numerator, denominator)

	if f.Quotient().Cmp(MaxUint256) > 0 {
		panic("Currency amount exceeds maximum value(uint256)")
	}

	return &CurrencyAmount{
		Currency:     currency,
		Fraction:     f,
		DecimalScale: new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(currency.Decimals())), nil),
	}
}

// Add adds two currency amounts together
func (ca *CurrencyAmount) Add(other *CurrencyAmount) *CurrencyAmount {
	added := ca.Fraction.Add(other.Fraction)
	return FromFractionalAmount(ca.Currency, added.Numerator, added.Denominator)
}

// Subtract subtracts one currency amount from another
func (ca *CurrencyAmount) Subtract(other *CurrencyAmount) *CurrencyAmount {
	subtracted := ca.Fraction.Subtract(other.Fraction)
	return FromFractionalAmount(ca.Currency, subtracted.Numerator, subtracted.Denominator)
}

// Multiply multiplies two currency amounts
func (ca *CurrencyAmount) Multiply(other *Fraction) *CurrencyAmount {
	multiplied := ca.Fraction.Multiply(other)
	return FromFractionalAmount(ca.Currency, multiplied.Numerator, multiplied.Denominator)
}

// Divide divides one currency amount by another
func (ca *CurrencyAmount) Divide(other *Fraction) *CurrencyAmount {
	divided := ca.Fraction.Divide(other)
	return FromFractionalAmount(ca.Currency, divided.Numerator, divided.Denominator)
}

// ToSignificant returns the currency amount as a string with the most significant digits
func (ca *CurrencyAmount) ToSignificant(significantDigits int32) string {
	return ca.Fraction.Divide(NewFraction(ca.DecimalScale, big.NewInt(1))).ToSignificant(significantDigits)
}

// ToFixed returns the currency amount as a string with the specified number of digits after the decimal
func (ca *CurrencyAmount) ToFixed(decimalPlaces int32) string {
	if uint(decimalPlaces) > ca.Currency.Decimals() {
		panic("Decimal places exceeds currency decimals")
	}
	return ca.Fraction.Divide(NewFraction(ca.DecimalScale, big.NewInt(1))).ToFixed(decimalPlaces)
}

// ToExact returns the currency amount as a string with the specified number of digits after the decimal
func (ca *CurrencyAmount) ToExactRaw() decimal.Decimal {
	return decimal.NewFromBigInt(ca.Quotient(), 0).Div(decimal.NewFromBigInt(ca.DecimalScale, 0))
}

// ToExact returns the currency amount as a string with the specified number of digits after the decimal
func (ca *CurrencyAmount) ToExact() string {
	return decimal.NewFromBigInt(ca.Quotient(), 0).Div(decimal.NewFromBigInt(ca.DecimalScale, 0)).String()
}

func (ca *CurrencyAmount) Wrapped() *CurrencyAmount {
	if ca.Currency.IsToken() {
		return ca
	}
	return newCurrencyAmount(ca.Currency.Wrapped(), ca.Numerator, ca.Denominator)
}
