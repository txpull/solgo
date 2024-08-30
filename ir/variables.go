package ir

import (
	"strings"

	ast_pb "github.com/unpackdev/protos/dist/go/ast"
	ir_pb "github.com/unpackdev/protos/dist/go/ir"
	"github.com/unpackdev/solgo/ast"
)

// StateVariable represents a state variable in the Intermediate Representation (IR) of Solidity contracts' Abstract Syntax Tree (AST).
type StateVariable struct {
	Unit            *ast.StateVariableDeclaration `json:"ast"`
	Id              int64                         `json:"id"`              // Id is the unique identifier of the state variable.
	ContractId      int64                         `json:"contractId"`      // ContractId is the unique identifier of the contract containing the state variable.
	Name            string                        `json:"name"`            // Name is the name of the state variable.
	NodeType        ast_pb.NodeType               `json:"nodeType"`        // NodeType is the type of the state variable node in the AST.
	Visibility      ast_pb.Visibility             `json:"visibility"`      // Visibility represents the visibility of the state variable (e.g., public, private, internal, external).
	Constant        bool                          `json:"isConstant"`      // Constant is true if the state variable is constant, false otherwise.
	StorageLocation ast_pb.StorageLocation        `json:"storageLocation"` // StorageLocation represents the storage location of the state variable.
	StateMutability ast_pb.Mutability             `json:"stateMutability"` // StateMutability represents the mutability of the state variable (e.g., pure, view, nonpayable, payable).
	Type            string                        `json:"type"`            // Type is the type of the state variable.
	TypeDescription *ast.TypeDescription          `json:"typeDescription"` // TypeDescription is the description of the type of the state variable.
}

// GetAST returns the underlying AST node of the state variable.
func (v *StateVariable) GetAST() *ast.StateVariableDeclaration {
	return v.Unit
}

// GetId returns the unique identifier of the state variable.
func (v *StateVariable) GetId() int64 {
	return v.Id
}

// GetContractId returns the unique identifier of the contract containing the state variable.
func (v *StateVariable) GetContractId() int64 {
	return v.ContractId
}

// GetName returns the name of the state variable.
func (v *StateVariable) GetName() string {
	return v.Name
}

// GetNodeType returns the type of the state variable node in the AST.
func (v *StateVariable) GetNodeType() ast_pb.NodeType {
	return v.NodeType
}

// GetVisibility returns the visibility of the state variable (e.g., public, private, internal, external).
func (v *StateVariable) GetVisibility() ast_pb.Visibility {
	return v.Visibility
}

// IsConstant returns true if the state variable is constant, false otherwise.
func (v *StateVariable) IsConstant() bool {
	return v.Constant
}

// GetStorageLocation returns the storage location of the state variable.
func (v *StateVariable) GetStorageLocation() ast_pb.StorageLocation {
	return v.StorageLocation
}

// GetStateMutability returns the mutability of the state variable (e.g., pure, view, nonpayable, payable).
func (v *StateVariable) GetStateMutability() ast_pb.Mutability {
	return v.StateMutability
}

// GetType returns the type of the state variable.
func (v *StateVariable) GetType() string {
	return v.Type
}

// GetTypeDescription returns the description of the type of the state variable.
func (v *StateVariable) GetTypeDescription() *ast.TypeDescription {
	return v.TypeDescription
}

// GetSrc returns the source node of the state variable.
func (v *StateVariable) GetSrc() ast.SrcNode {
	return v.Unit.GetSrc()
}

func (v *StateVariable) GetStorageSize() (int64, bool) {
	return v.Unit.GetTypeName().StorageSize()
}

// ToProto is a function that converts the StateVariable to a protobuf message.
func (v *StateVariable) ToProto() *ir_pb.StateVariable {
	proto := &ir_pb.StateVariable{
		Id:              v.GetId(),
		ContractId:      v.GetContractId(),
		Name:            v.GetName(),
		NodeType:        v.GetNodeType(),
		Visibility:      v.GetVisibility(),
		IsConstant:      v.IsConstant(),
		StorageLocation: v.GetStorageLocation(),
		StateMutability: v.GetStateMutability(),
		Type:            v.GetType(),
		TypeDescription: v.GetTypeDescription().ToProto(),
	}

	return proto
}

// processStateVariables is a function that processes the given state variable declaration node and returns a StateVariable.
func (b *Builder) processStateVariables(unit *ast.StateVariableDeclaration) *StateVariable {
	variableNode := &StateVariable{
		Unit:            unit,
		Id:              unit.GetId(),
		ContractId:      unit.GetScope(),
		Name:            unit.GetName(),
		NodeType:        unit.GetType(),
		Visibility:      unit.GetVisibility(),
		Constant:        unit.IsConstant(),
		StorageLocation: unit.GetStorageLocation(),
		StateMutability: unit.GetStateMutability(),
		Type:            unit.GetTypeName().GetName(),
		TypeDescription: unit.GetTypeName().GetTypeDescription(),
	}

	if strings.HasPrefix(unit.GetTypeName().GetName(), "contract") {
		variableNode.Type = "address"
	}

	// It could be that the name of the type name node is not set, but the type description string is.
	if variableNode.Type == "" {
		/*		if variableNode.TypeDescription == nil {
				utils.DumpNodeWithExit(variableNode)
			}*/
		variableNode.Type = variableNode.TypeDescription.TypeString
	}

	return variableNode
}
