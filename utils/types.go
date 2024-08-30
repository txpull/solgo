package utils

// Strategy represents the strategy used in transaction processing or data fetching.
// Available strategies include "head" for latest data and "archive" for historical data.
type Strategy string

// String returns the string representation of a Strategy.
func (s Strategy) String() string {
	return string(s)
}

// AddressType categorizes Ethereum addresses based on their usage context.
// Types include "zero_address" for the null address, "address" for standard addresses,
// and "contract" for contract addresses.
type AddressType string

// String returns the string representation of an AddressType.
func (r AddressType) String() string {
	return string(r)
}

// TransactionMethodType defines the type of transaction method used in Ethereum transactions.
// Types include "unknown" for undetermined, "contract_creation" for contract deployments,
// "transfer" for token transfers, and "no_signature" for transactions without a signature.
type TransactionMethodType string

// String returns the string representation of a TransactionMethodType.
func (t TransactionMethodType) String() string {
	return string(t)
}

// LogEventType represents the type of event logged by Ethereum smart contracts.
// Types include various events such as "swap", "transfer", "deposit", "withdraw",
// "mint", and "burn", along with "unknown" for undetermined event types.
type LogEventType string

// String returns the string representation of a LogEventType.
func (t LogEventType) String() string {
	return string(t)
}

// AccountType categorizes the types of accounts used, particularly in simulations.
// Types include "simulator" for simulated accounts, "simple", and "keystore" for accounts
// stored in encrypted format.
type AccountType string

// String returns the string representation of an AccountType.
func (t AccountType) String() string {
	return string(t)
}

// SimulatorType represents the types of simulators used for transaction execution or testing.
// Types include "no_simulator", "anvil" for the Anvil Ethereum simulator, and "trace" for simulators
// that support tracing capabilities.
type SimulatorType string

// String returns the string representation of a SimulatorType.
func (t SimulatorType) String() string {
	return string(t)
}

// ExchangeType represents various decentralized exchange (DEX) protocols.
// Types include "no_exchange", "uniswap_v2", "uniswap_v3", "sushiswap", and "pancakeswap_v2".
type ExchangeType string

// String returns the string representation of an ExchangeType.
func (t ExchangeType) String() string {
	return string(t)
}

// TokenType categorizes the types of tokens, such as "erc20" for standard fungible tokens
// and "erc721" for non-fungible tokens (NFTs).
type TokenType string

// String returns the string representation of a TokenType.
func (t TokenType) String() string {
	return string(t)
}

// AntiWhaleType represents types of anti-whale measures, such as "pinksale" for specific
// project launches with anti-whale features.
type AntiWhaleType string

// String returns the string representation of an AntiWhaleType.
func (t AntiWhaleType) String() string {
	return string(t)
}

// TradeType defines the type of trade action, including "buy" and "sell".
type TradeType string

// String returns the string representation of a TradeType.
func (t TradeType) String() string {
	return string(t)
}

// SafetyStateType represents the safety state of a transaction or contract, including
// "unknown", "safe", "warning", and "unsafe".
type SafetyStateType string

// String returns the string representation of a SafetyStateType.
func (t SafetyStateType) String() string {
	return string(t)
}

// BlacklistType defines types of blacklist categories for tokens or contracts,
// such as "rugpull", "honeypot", and others related to specific risks.
type BlacklistType string

// String returns the string representation of a BlacklistType.
func (t BlacklistType) String() string {
	return string(t)
}

// TransferType defines the type of transfer, including "account" and "contract".
type TransferType string

// String returns the string representation of a TradeType.
func (t TransferType) String() string {
	return string(t)
}

// Constants defining various strategies, address types, transaction method types, etc.
const (
	HeadStrategy    Strategy = "head"
	ArchiveStrategy Strategy = "archive"

	ZeroAddressRecipient AddressType = "zero_address"
	AddressRecipient     AddressType = "address"
	ContractRecipient    AddressType = "contract"

	ZeroAddressType AddressType = "zero_address"
	AccountAddressType        AddressType = "account"
	ContractAddressType       AddressType = "contract"


	AccountTransferType       TransferType = "account"
	ContractTransferType      TransferType = "contract"


	UnknownTransactionMethodType TransactionMethodType = "unknown"
	ContractCreationType         TransactionMethodType = "contract_creation"
	ApproveMethodType           TransactionMethodType = "approve"
	TransferMethodType           TransactionMethodType = "transfer"
	TransferFromMethodType           TransactionMethodType = "transferfrom"
	DepositMethodType           TransactionMethodType = "deposit"
	NoSignatureMethodType        TransactionMethodType = "no_signature"

	UnknownLogEventType  LogEventType = "unknown"
	SwapLogEventType     LogEventType = "swap"
	TransferFromLogEventType LogEventType = "transferfrom"
	TransferLogEventType LogEventType = "transfer"
	DepositLogEventType  LogEventType = "deposit"
	WithdrawLogEventType LogEventType = "withdraw"
	MintLogEventType     LogEventType = "mint"
	BurnLogEventType     LogEventType = "burn"
	PairCreatedEventType LogEventType = "paircreated"

	NoSimulator    SimulatorType = "no_simulator"
	AnvilSimulator SimulatorType = "anvil"
	TraceSimulator SimulatorType = "trace"

	SimulatorAccountType AccountType = "simulator"
	SimpleAccountType    AccountType = "simple"
	KeystoreAccountType  AccountType = "keystore"

	NoExchange    ExchangeType = "no_exchange"
	UniswapV2     ExchangeType = "uniswap_v2"
	UniswapV3     ExchangeType = "uniswap_v3"
	SushiSwap     ExchangeType = "sushiswap"
	PancakeswapV2 ExchangeType = "pancakeswap_v2"

	Erc20TokenType  TokenType = "erc20"
	Erc721TokenType TokenType = "erc721"

	AntiWhalePinksale AntiWhaleType = "pinksale"

	BuyTradeType  TradeType = "buy"
	SellTradeType TradeType = "sell"

	UnknownSafetyState SafetyStateType = "unknown"
	SafeSafetyState    SafetyStateType = "safe"
	WarnSafetyState    SafetyStateType = "warning"
	UnsafeSafetyState  SafetyStateType = "unsafe"

	RugpullBlacklistType          BlacklistType = "rugpull"
	HoneypotBlacklistType         BlacklistType = "honeypot"
	HighTaxTokenBlacklistType     BlacklistType = "high_tax_token"
	PumpAndDumpTokenBlacklistType BlacklistType = "pump_and_dump_token"
	MixerUsageBlacklistType       BlacklistType = "mixer_usage"
)

// ZeroSignatureBytes and ZeroSignature represent a null signature in Ethereum transactions.
var (
	ZeroSignatureBytes = []byte{0x00, 0x00, 0x00, 0x00}
	ZeroSignature      = "0x00000000"
)
