package contracts

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/unpackdev/solgo"
	"github.com/unpackdev/solgo/audit"
	"github.com/unpackdev/solgo/bytecode"
	"github.com/unpackdev/solgo/detector"
	"github.com/unpackdev/solgo/ir"
	"github.com/unpackdev/solgo/providers/etherscan"
	"github.com/unpackdev/solgo/tokens"
	"github.com/unpackdev/solgo/utils"
)

// Descriptor encapsulates comprehensive metadata about an Ethereum contract. It includes
// network information, bytecode data, ownership details, and associated resources like ABI,
// source code, and audit reports. This type serves as a central repository for detailed
// insights into contract specifications and state.
type Descriptor struct {
	Network           utils.Network      `json:"network"`
	NetworkID         utils.NetworkID    `json:"network_id"`
	Address           common.Address     `json:"address"`
	ExecutionBytecode []byte             `json:"execution_bytecode"`
	DeployedBytecode  []byte             `json:"deployed_bytecode"`
	Block             *types.Header      `json:"block,omitempty"`
	Transaction       *types.Transaction `json:"transaction,omitempty"`
	Receipt           *types.Receipt     `json:"receipt,omitempty"`
	ABI               string             `json:"abi,omitempty"`
	Name              string             `json:"name,omitempty"`
	UnitName 		  string 			 `json:"unitName,omitempty"`
	License           string             `json:"license,omitempty"`
	SolgoVersion      string             `json:"solgo_version,omitempty"`
	CompilerVersion   string             `json:"compiler_version,omitempty"`
	Optimized         bool               `json:"optimized,omitempty"`
	OptimizationRuns  uint64             `json:"optimization_runs,omitempty"`
	EVMVersion        string             `json:"evm_version,omitempty"`

	// Identity related fields
	Owner common.Address `json:"owner,omitempty"`

	// SourcesRaw is the raw sources from Etherscan|BscScan|etc. Should not be used anywhere except in
	// the contract discovery process.
	SourcesRaw      *etherscan.Contract `json:"-"`
	Sources         *solgo.Sources      `json:"sources,omitempty"`
	SourcesUnsorted *solgo.Sources      `json:"-"`
	SourceProvider  string              `json:"source_provider,omitempty"`

	// Source detection related fields.
	Detector    *detector.Detector    `json:"-"`
	IRRoot      *ir.RootSourceUnit    `json:"ir,omitempty"`
	Constructor *bytecode.Constructor `json:"constructor,omitempty"`
	Metadata    *bytecode.Metadata    `json:"metadata,omitempty"`

	// Auditing related fields.
	Verified             bool          `json:"verified,omitempty"`
	VerificationProvider string        `json:"verification_provider,omitempty"`
	Safe                 bool          `json:"safe,omitempty"`
	Audit                *audit.Report `json:"audit,omitempty"`

	// Proxy
	Proxy           bool             `json:"proxy"`
	Implementations []common.Address `json:"implementations"`

	// Token related fields.
	Token *tokens.Descriptor `json:"token,omitempty"`
}

// HasToken checks if the contract has token details available.
func (d *Descriptor) HasToken() bool {
	return d.Token != nil
}

// HasConstructor checks if contract constructor details are available.
func (d *Descriptor) HasConstructor() bool {
	return d.Constructor != nil
}

// HasSources checks if source code details are available for the contract.
func (d *Descriptor) HasSources() bool {
	return d.Sources != nil && d.Sources.HasUnits()
}

// HasAudit checks if an audit report is available for the contract.
func (d *Descriptor) HasAudit() bool {
	return d.Audit != nil
}

// HasMetadata checks if metadata is available for the contract.
func (d *Descriptor) HasMetadata() bool {
	return d.Metadata != nil
}

// SetCompilerVersion sets the compiler version used for the contract.
func (d *Descriptor) SetCompilerVersion(ver string) {
	d.CompilerVersion = ver
}

// HasDetector checks if a detector for analyzing the contract is available.
func (d *Descriptor) HasDetector() bool {
	if d.Detector != nil && d.Detector.GetIR() != nil && d.Detector.GetIR().GetRoot() != nil {
		return true
	}

	return false
}

// HasContracts checks if the contract or its components have been detected.
func (d *Descriptor) HasContracts() bool {
	if d.HasDetector() && d.Detector.GetIR().GetRoot().HasContracts() {
		return true
	}

	return false
}

// GetIrRoot returns the IR root source unit, providing insights into the contract's structure.
func (d *Descriptor) GetIrRoot() *ir.RootSourceUnit {
	return d.IRRoot
}

// GetToken returns the token descriptor associated with the contract, if available. This descriptor
// contains detailed token information such as name, symbol, and decimals.
func (d *Descriptor) GetToken() *tokens.Descriptor {
	return d.Token
}

// GetAudit returns the audit report for the contract, if available. This report includes findings
// and security analysis details.
func (d *Descriptor) GetAudit() *audit.Report {
	return d.Audit
}

// GetMetadata returns the contract's metadata, including the compiler version, language, and settings used for compilation.
func (d *Descriptor) GetMetadata() *bytecode.Metadata {
	return d.Metadata
}

// GetConstructor returns the constructor details of the contract, if available, including input parameters and bytecode.
func (d *Descriptor) GetConstructor() *bytecode.Constructor {
	return d.Constructor
}

// GetSources returns the parsed sources of the contract, providing a structured view of the contract's code.
func (d *Descriptor) GetSources() *solgo.Sources {
	return d.Sources
}

// GetUnsortedSources returns the parsed sources of the contract, providing a structured view of the contract's code.
func (d *Descriptor) GetUnsortedSources() *solgo.Sources {
	return d.SourcesUnsorted
}

// GetSourcesRaw returns the raw contract source as obtained from external providers like Etherscan.
func (d *Descriptor) GetSourcesRaw() *etherscan.Contract {
	return d.SourcesRaw
}

// GetSourceProvider returns the name of the source provider, indicating where the contract source was obtained from.
func (d *Descriptor) GetSourceProvider() string {
	return d.SourceProvider
}

// IsOptimized checks whether the contract compilation was optimized, returning true if so.
func (d *Descriptor) IsOptimized() bool {
	return d.Optimized
}

// GetOptimizationRuns returns the number of optimization runs performed during the contract's compilation.
func (d *Descriptor) GetOptimizationRuns() uint64 {
	return d.OptimizationRuns
}

// GetEVMVersion returns the EVM version target specified during the contract's compilation.
func (d *Descriptor) GetEVMVersion() string {
	return d.EVMVersion
}

// GetABI returns the contract's ABI (Application Binary Interface), essential for interacting with the contract.
func (d *Descriptor) GetABI() string {
	return d.ABI
}

// GetLicense returns the software license under which the contract source code is distributed.
func (d *Descriptor) GetLicense() string {
	return d.License
}

// GetName returns the name of the contract.
func (d *Descriptor) GetName() string {
	return d.Name
}

// GetCompilerVersion returns the version of the compiler used to compile the contract.
func (d *Descriptor) GetCompilerVersion() string {
	return d.CompilerVersion
}

// GetSolgoVersion returns the version of the Solgo tool used in processing the contract.
func (d *Descriptor) GetSolgoVersion() string {
	return d.SolgoVersion
}

// GetNetwork returns the network (e.g., Mainnet, Ropsten) on which the contract is deployed.
func (d *Descriptor) GetNetwork() utils.Network {
	return d.Network
}

// GetNetworkID returns the unique identifier of the network on which the contract is deployed.
func (d *Descriptor) GetNetworkID() utils.NetworkID {
	return d.NetworkID
}

// GetAddress returns the Ethereum address of the contract.
func (d *Descriptor) GetAddress() common.Address {
	return d.Address
}

// GetExecutionBytecode returns the execution bytecode of the contract, which is the code that is executed on the Ethereum Virtual Machine.
func (d *Descriptor) GetExecutionBytecode() []byte {
	return d.ExecutionBytecode
}

// GetDeployedBytecode returns the deployed bytecode of the contract, which is the code stored on the blockchain.
func (d *Descriptor) GetDeployedBytecode() []byte {
	return d.DeployedBytecode
}

// GetBlock returns the block header in which the contract transaction was included, providing context such as block number and hash.
func (d *Descriptor) GetBlock() *types.Header {
	return d.Block
}

// GetTransaction returns the transaction through which the contract was created or interacted with.
func (d *Descriptor) GetTransaction() *types.Transaction {
	return d.Transaction
}

// GetReceipt returns the receipt of the transaction through which the contract was created or interacted with, detailing execution outcome.
func (d *Descriptor) GetReceipt() *types.Receipt {
	return d.Receipt
}

// GetDetector returns the detector used for analyzing the contract, providing access to advanced analysis tools like IR generation.
func (d *Descriptor) GetDetector() *detector.Detector {
	return d.Detector
}

// IsVerified indicates whether the contract's source code has been verified on platforms like Etherscan.
func (d *Descriptor) IsVerified() bool {
	return d.Verified
}

// GetVerificationProvider returns the name of the service provider where the contract's source code was verified.
func (d *Descriptor) GetVerificationProvider() string {
	return d.VerificationProvider
}

// IsSafe indicates whether the contract has been marked as safe based on audits or security reports.
func (d *Descriptor) IsSafe() bool {
	return d.Safe
}

// HasAuditReport checks if an audit report is available for the contract, providing insights into security assessments.
func (d *Descriptor) HasAuditReport() bool {
	return d.Audit != nil
}

// GetOwner returns the address recognized as the owner of the contract, who has administrative privileges.
func (d *Descriptor) GetOwner() common.Address {
	return d.Owner
}
