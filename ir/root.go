package ir

import (
	"github.com/ethereum/go-ethereum/common"
	ast_pb "github.com/unpackdev/protos/dist/go/ast"
	ir_pb "github.com/unpackdev/protos/dist/go/ir"
	"github.com/unpackdev/solgo/ast"
	"github.com/unpackdev/solgo/standards"
	"go.uber.org/zap"
)

// RootSourceUnit represents the root of a Solidity contract's AST as an IR node.
type RootSourceUnit struct {
	builder           *Builder        `json:"-"`
	Unit              *ast.RootNode   `json:"ast"`
	NodeType          ast_pb.NodeType `json:"nodeType"`
	Address           common.Address  `json:"address"`
	EntryContractId   int64           `json:"entryContractId"`
	EntryContractName string          `json:"entryContractName"`
	ContractsCount    int32           `json:"contractsCount"`
	ContractTypes     []string        `json:"contractTypes"`
	Standards         []*Standard     `json:"standards"`
	Contracts         []*Contract     `json:"contracts"`
	Links             []*Link         `json:"links"`
}

// GetAST returns the underlying AST node of the RootSourceUnit.
func (r *RootSourceUnit) GetAST() *ast.RootNode {
	return r.Unit
}

// GetNodeType returns the type of the node in the AST.
func (r *RootSourceUnit) GetNodeType() ast_pb.NodeType {
	return r.NodeType
}

// GetEntryId returns the entry contract ID.
func (r *RootSourceUnit) GetEntryId() int64 {
	return r.EntryContractId
}

// GetEntryName returns the entry contract name.
func (r *RootSourceUnit) GetEntryName() string {
	return r.EntryContractName
}

// GetContracts returns the list of contracts in the IR.
func (r *RootSourceUnit) GetContracts() []*Contract {
	return r.Contracts
}

// GetContractByName returns the contract with the given name from the IR.
// If no contract with the given name is found, it returns nil.
func (r *RootSourceUnit) GetContractByName(name string) *Contract {
	for _, su := range r.Contracts {
		if su.Name == name {
			return su
		}
	}

	return nil
}

// GetContractById returns the contract with the given ID from the IR.
// If no contract with the given ID is found, it returns nil.
func (r *RootSourceUnit) GetContractById(id int64) *Contract {
	for _, su := range r.Contracts {
		if su.Id == id {
			return su
		}
	}

	return nil
}

// GetContractBySourceUnitId returns the contract with the given source unit ID from the IR.
func (r *RootSourceUnit) GetContractBySourceUnitId(id int64) *Contract {
	for _, su := range r.Contracts {
		if su.GetSourceUnitId() == id {
			return su
		}
	}

	return nil
}

// GetEntryContract returns the entry contract from the IR.
func (r *RootSourceUnit) GetEntryContract() *Contract {
	return r.GetContractById(r.EntryContractId)
}

// HasContracts returns true if the AST has one or more contracts, false otherwise.
func (r *RootSourceUnit) HasContracts() bool {
	return len(r.Contracts) > 0
}

// GetContractsCount returns the count of contracts in the AST.
func (r *RootSourceUnit) GetContractsCount() int32 {
	return r.ContractsCount
}

// GetStandards returns the EIPs discovered for any contract in the source units.
func (r *RootSourceUnit) GetStandards() []*Standard {
	return r.Standards
}

// GetStandard returns the EIP with the given type.
func (r *RootSourceUnit) GetStandard(standard standards.Standard) *Standard {
	for _, e := range r.Standards {
		if e.Standard.Type == standard {
			return e
		}
	}
	return nil
}

// HasStandard returns true if standard is already registered false otherwise.
func (r *RootSourceUnit) HasStandard(standard standards.Standard) bool {
	for _, e := range r.Standards {
		if e.Standard.Type == standard {
			return true
		}
	}

	return false
}

// HasHighConfidenceStandard returns true if high standard is already registered false otherwise.
func (r *RootSourceUnit) HasHighConfidenceStandard(standard standards.Standard) bool {
	for _, e := range r.Standards {
		if e.Standard.Type == standard {
			if e.GetConfidence().Confidence == standards.HighConfidence {
				return true
			}
		}
	}

	return false
}

// HasPerfectConfidenceStandard returns true if perfect standard is already registered false otherwise.
func (r *RootSourceUnit) HasPerfectConfidenceStandard(standard standards.Standard) bool {
	for _, e := range r.Standards {
		if e.Standard.Type == standard {
			if e.GetConfidence().Confidence == standards.PerfectConfidence {
				return true
			}
		}
	}

	return false
}

// GetContractTypes returns the list of contract types.
func (r *RootSourceUnit) GetContractTypes() []string {
	return r.ContractTypes
}

// HasContractType returns the list of contract types.
func (r *RootSourceUnit) HasContractType(ctype string) bool {
	for _, t := range r.ContractTypes {
		if t == ctype {
			return true
		}
	}

	return false
}

// GetContractsCountByKind returns the count of contracts in the AST by the given kind.
func (r *RootSourceUnit) GetContractsCountByKind(kind ast_pb.NodeType) int64 {
	var count int64
	for _, c := range r.Contracts {
		if c.Kind == kind {
			count++
		}
	}
	return count
}

// SetContractType sets the contract type for the given standard.
func (r *RootSourceUnit) SetContractType(standard standards.Standard) {
	switch standard {
	case standards.ERC20:
		r.appendContractType("token")
	case standards.ERC721, standards.ERC1155:
		r.appendContractType("nft")
	case standards.ERC1967, standards.ERC1820:
		r.appendContractType("proxy")
		r.appendContractType("upgradeable")
	}
}

// appendContractType appends the given contract type to the list of contract types.
// It does not append if the contract type already exists in the list.
func (r *RootSourceUnit) appendContractType(contractType string) {
	if !r.HasContractType(contractType) {
		r.ContractTypes = append(r.ContractTypes, contractType)
	}
}

// GetLinks returns the list of links discovered in the AST comments.
func (r *RootSourceUnit) GetLinks() []*Link {
	return r.Links
}

// IsEntryContract checks if provided contract is root unit entry contract
func (r *RootSourceUnit) IsEntryContract(contract *Contract) bool {
	return r.EntryContractId == contract.Id
}

// ToProto is a placeholder function for converting the RootSourceUnit to a protobuf message.
func (r *RootSourceUnit) ToProto() *ir_pb.Root {
	proto := &ir_pb.Root{
		Id:                0,
		NodeType:          r.GetNodeType(),
		EntryContractId:   r.GetEntryId(),
		EntryContractName: r.GetEntryName(),
		ContractsCount:    r.GetContractsCount(),
		Contracts:         make([]*ir_pb.Contract, 0),
		ContractTypes:     r.GetContractTypes(),
	}

	for _, c := range r.GetContracts() {
		proto.Contracts = append(proto.Contracts, c.ToProto())
	}

	return proto
}

// Walk iterates through the AST (Abstract Syntax Tree) of a RootSourceUnit, applying the provided NodeVisitor to each node.
// This function facilitates traversal of the AST, allowing for operations such as analysis, modification, or inspection to be
// performed on each node.
func (r *RootSourceUnit) Walk(nodeVisitor *ast.NodeVisitor) error {
	return r.builder.GetAstBuilder().GetTree().Walk(nodeVisitor)
}

// processRoot processes the given root node of an AST and returns a RootSourceUnit.
// It populates the RootSourceUnit with the contracts from the AST.
func (b *Builder) processRoot(root *ast.RootNode) *RootSourceUnit {
	rootNode := &RootSourceUnit{
		builder:        b,
		Unit:           root,
		NodeType:       root.GetType(),
		ContractsCount: root.GetSourceUnitCount(),
		Contracts:      make([]*Contract, 0),
		ContractTypes:  make([]string, 0),
		Standards:      make([]*Standard, 0),
	}

	// No source units to process, so we're going to stop processing the root from here...
	if !root.HasSourceUnits() {
		return rootNode
	}

	entrySourceUnit := root.GetSourceUnitById(root.GetEntrySourceUnit())
	if entrySourceUnit == nil {
		zap.L().Debug(
			"Entry source unit not found. Make sure it's correctly set.",
			zap.String("contract_address", b.GetAddress().Hex()),
			zap.Int64("requested_source_unit_id", root.GetEntrySourceUnit()),
		)
	} else {
		if entrySourceUnit.GetContract() != nil {
			rootNode.EntryContractId = entrySourceUnit.GetContract().GetId()
			rootNode.EntryContractName = entrySourceUnit.GetName()
		}
	}

	if len(root.GetSourceUnits()) > 0 {
		for _, su := range root.GetSourceUnits() {
			if su.GetContract() != nil {
				rootNode.Contracts = append(
					rootNode.Contracts,
					b.processContract(su),
				)
			}
		}
	}

	// Discovery and processing of the contract standards (EIPs)
	b.processEips(rootNode)

	// Discovery and processing of links within the AST comments.
	// This is useful to extract social links from the comments in the code.
	b.processLinks(rootNode)

	return rootNode
}
