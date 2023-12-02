package utils

import (
	"math/big"
)

type Network string
type NetworkID uint64

const (
	AnvilNetwork Network = "anvil"
	Ethereum     Network = "ethereum"
	Bsc          Network = "bsc"
	Polygon      Network = "polygon"
	Avalanche    Network = "avalanche"
	Fantom       Network = "fantom"
	Arbitrum     Network = "arbitrum"
	Optimism     Network = "optimism"

	// Mainnets
	EthereumNetworkID  NetworkID = 1
	BscNetworkID       NetworkID = 56
	PolygonNetworkID   NetworkID = 137
	AvalancheNetworkID NetworkID = 43114
	FantomNetworkID    NetworkID = 250
	ArbitrumNetworkID  NetworkID = 42161
	OptimismNetworkID  NetworkID = 10

	// Testnets
	RopstenNetworkID    NetworkID = 3
	RinkebyNetworkID    NetworkID = 4
	GoerliNetworkID     NetworkID = 5
	KovanNetworkID      NetworkID = 42
	BscTestnetNetworkID NetworkID = 97
	MumbaiNetworkID     NetworkID = 80001
	FujiNetworkID       NetworkID = 43113
	FantomTestNetworkID NetworkID = 4002
	ArbitrumRinkebyID   NetworkID = 421611
	OptimismKovanID     NetworkID = 69
)

func (n Network) String() string {
	return string(n)
}

func (n NetworkID) ToBig() *big.Int {
	return new(big.Int).SetUint64(uint64(n))
}

func GetNetworkID(network Network) NetworkID {
	switch network {
	case Ethereum:
		return EthereumNetworkID
	case Bsc:
		return BscNetworkID
	case Polygon:
		return PolygonNetworkID
	case Avalanche:
		return AvalancheNetworkID
	case Fantom:
		return FantomNetworkID
	case Arbitrum:
		return ArbitrumNetworkID
	case Optimism:
		return OptimismNetworkID
	default:
		return 0
	}
}
