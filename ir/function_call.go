package ir

import (
	"strings"

	v3 "github.com/cncf/xds/go/xds/type/v3"
	ast_pb "github.com/unpackdev/protos/dist/go/ast"
	ir_pb "github.com/unpackdev/protos/dist/go/ir"
	"github.com/unpackdev/solgo/ast"
)

// FunctionCall represents a function call statement in the IR.
type FunctionCall struct {
	Unit                    *ast.FunctionCall         `json:"-"`
	referencedUnit          *Function                 `json:"-"`
	referencedContract      ContractNode              `json:"-"`
	Id                      int64                     `json:"id"`
	NodeType                ast_pb.NodeType           `json:"nodeType"`
	Kind                    ast_pb.NodeType           `json:"kind"`
	Name                    string                    `json:"name"`
	ArgumentTypes           []*ast_pb.TypeDescription `json:"argumentTypes"`
	External                bool                      `json:"external"`
	ExternalContractId      int64                     `json:"externalContractId"`
	ExternalContractName    string                    `json:"externalContractName,omitempty"`
	ReferenceStatementId    int64                     `json:"referenceStatementId"`
	ReferencedDeclarationId int64                     `json:"referencedDeclarationId"`
	TypeDescription         *ast_pb.TypeDescription   `json:"typeDescription"`
}

// GetAST returns the AST (Abstract Syntax Tree) for the function call statement.
func (e *FunctionCall) GetAST() *ast.FunctionCall {
	return e.Unit
}

// GetId returns the ID of the function call statement.
func (e *FunctionCall) GetId() int64 {
	return e.Id
}

// GetNodeType returns the NodeType of the function call statement.
func (e *FunctionCall) GetNodeType() ast_pb.NodeType {
	return e.NodeType
}

// GetKind returns the kind of the function call statement.
func (e *FunctionCall) GetKind() ast_pb.NodeType {
	return e.Kind
}

// GetSrc returns the source location of the function call statement.
func (e *FunctionCall) GetSrc() ast.SrcNode {
	return e.Unit.GetSrc()
}

// GetNodes returns the nodes of the statement.
func (e *FunctionCall) GetNodes() []Statement {
	return nil
}

// GetTypeDescription returns the type description of the function call statement.
func (e *FunctionCall) GetTypeDescription() *ast_pb.TypeDescription {
	return e.TypeDescription
}

// GetReferencedDeclarationId returns the referenced declaration id of the function call statement.
func (e *FunctionCall) GetReferencedDeclarationId() int64 {
	return e.ReferencedDeclarationId
}

// GetArgumentTypes returns the argument types of the function call statement.
func (e *FunctionCall) GetArgumentTypes() []*ast_pb.TypeDescription {
	return e.ArgumentTypes
}

// GetName returns the name of the function call statement.
func (e *FunctionCall) GetName() string {
	return e.Name
}

// IsExternal returns if the function call is an external contract call.
func (e *FunctionCall) IsExternal() bool {
	return e.External
}

// GetReferenceStatementId returns the reference statement id of the function call statement.
func (e *FunctionCall) GetReferenceStatementId() int64 {
	return e.ReferenceStatementId
}

// GetReferenceStatement returns the reference statement of the function call statement.
func (e *FunctionCall) GetReferenceStatement() *Function {
	return e.referencedUnit
}

// GetExternalContractId returns the external contract id of the function call statement.
func (e *FunctionCall) GetExternalContractId() int64 {
	return e.ExternalContractId
}

// GetExternalContractName returns the external contract name of the function call statement.
func (e *FunctionCall) GetExternalContractName() string {
	return e.ExternalContractName
}

// GetExternalSourceUnit returns the external contract of the function call statement.
func (e *FunctionCall) GetExternalContract() ContractNode {
	return e.referencedContract
}

// ToProto returns the protocol buffer version of the function call statement.
func (e *FunctionCall) ToProto() *v3.TypedStruct {
	proto := &ir_pb.FunctionCall{
		Id:                      e.GetId(),
		NodeType:                e.GetNodeType(),
		Kind:                    e.GetKind(),
		Name:                    e.GetName(),
		ReferencedDeclarationId: e.GetReferencedDeclarationId(),
		ArgumentTypes:           e.GetArgumentTypes(),
		TypeDescription:         e.GetTypeDescription(),
		IsExternal:              e.IsExternal(),
		ExternalContractId:      e.GetExternalContractId(),
		ExternalContractName:    e.GetExternalContractName(),
		ReferenceStatementId:    e.GetReferenceStatementId(),
	}

	return NewTypedStruct(proto, "FunctionCall")
}

// processFunctionCall processes the function call statement and returns the FunctionCall.
func (b *Builder) processFunctionCall(fn *Function, unit *ast.FunctionCall) *FunctionCall {
	toReturn := &FunctionCall{
		Unit:                    unit,
		Id:                      unit.GetId(),
		NodeType:                unit.GetType(),
		Kind:                    unit.GetKind(),
		ArgumentTypes:           make([]*ast_pb.TypeDescription, 0),
		ReferencedDeclarationId: unit.GetReferenceDeclaration(),
		TypeDescription:         unit.GetTypeDescription().ToProto(),
	}

	for _, arg := range unit.GetArguments() {
		/*		if arg.GetTypeDescription() == nil {
				utils.DumpNodeWithExit(arg)
			}*/
		toReturn.ArgumentTypes = append(toReturn.ArgumentTypes, arg.GetTypeDescription().ToProto())
	}

	if expr, ok := unit.GetExpression().(Expression); ok {
		toReturn.Name = expr.GetName()

		// Let's search now for referenced statement id. Basically, the idea is to figure out
		// from now on if the current contract is external or not as well to be able to visualize
		// the call graph.
		// Do not be surprised if you are not seeing any reference statement id.
		// We can have calls to functions such as assert() or require() which are built-in functions.
		if node := b.byFunction(toReturn.Name); node != nil {
			toReturn.referencedUnit = node
			toReturn.ReferenceStatementId = node.GetId()

			nodeType := node.GetAST().GetTypeDescription()
			if strings.Contains(nodeType.GetIdentifier(), "t_contract") {
				toReturn.External = true

				if fn != nil {
					toReturn.ExternalContractId = fn.GetAST().GetScope()
					sourceContract := b.astBuilder.GetTree().GetById(fn.GetAST().GetScope())
					toReturn.referencedContract = GetContractByNodeType(sourceContract)
				}
			}
		}
	}

	// Alright, this is the process, we will check if the function call contains an address as one of the arguments.
	// If it does, it's for sure an external contract call.
	// Then we need to figure out where it goes to. Sneaky little one...
	for _, arg := range unit.GetArguments() {
		if arg.GetTypeDescription() != nil && arg.GetTypeDescription().GetIdentifier() == "t_address" {
			toReturn.External = true

			if fn != nil {
				toReturn.ExternalContractId = fn.GetAST().GetScope()
				sourceContract := b.astBuilder.GetTree().GetById(fn.GetAST().GetScope())
				toReturn.referencedContract = GetContractByNodeType(sourceContract)
				toReturn.ExternalContractName = toReturn.referencedContract.GetName()
			}

			break
		}
	}

	return toReturn
}
