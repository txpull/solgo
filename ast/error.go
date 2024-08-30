package ast

import (
	"fmt"
	ast_pb "github.com/unpackdev/protos/dist/go/ast"
	"github.com/unpackdev/solgo/parser"
)

// ErrorDefinition represents an error definition node in the abstract syntax tree.
type ErrorDefinition struct {
	*ASTBuilder
	SourceUnitName  string           `json:"-"`               // Source unit name.
	Id              int64            `json:"id"`              // Unique identifier of the error definition node.
	NodeType        ast_pb.NodeType  `json:"nodeType"`        // Type of the node.
	Src             SrcNode          `json:"src"`             // Source location information.
	Name            string           `json:"name"`            // Name of the error definition.
	NameLocation    SrcNode          `json:"nameLocation"`    // Source location information of the name.
	Parameters      *ParameterList   `json:"parameters"`      // List of error parameters.
	TypeDescription *TypeDescription `json:"typeDescription"` // Type description of the error definition.
}

// NewErrorDefinition creates a new instance of ErrorDefinition with the provided ASTBuilder.
func NewErrorDefinition(b *ASTBuilder) *ErrorDefinition {
	return &ErrorDefinition{
		ASTBuilder: b,
		Id:         b.GetNextID(),
		NodeType:   ast_pb.NodeType_ERROR_DEFINITION,
	}
}

// SetReferenceDescriptor sets the reference descriptors of the ErrorDefinition node.
func (e *ErrorDefinition) SetReferenceDescriptor(refId int64, refDesc *TypeDescription) bool {
	return false
}

// GetId returns the unique identifier of the error definition node.
func (e *ErrorDefinition) GetId() int64 {
	return e.Id
}

// GetType returns the type of the node.
func (e *ErrorDefinition) GetType() ast_pb.NodeType {
	return e.NodeType
}

// GetSrc returns the source location information of the error definition node.
func (e *ErrorDefinition) GetSrc() SrcNode {
	return e.Src
}

// GetNameLocation returns the source location information of the name of the error definition.
func (e *ErrorDefinition) GetNameLocation() SrcNode {
	return e.NameLocation
}

// GetName returns the name of the error definition.
func (e *ErrorDefinition) GetName() string {
	return e.Name
}

// GetTypeDescription returns the type description of the error definition.
func (e *ErrorDefinition) GetTypeDescription() *TypeDescription {
	return e.TypeDescription
}

// GetParameters returns the list of error parameters.
func (e *ErrorDefinition) GetParameters() *ParameterList {
	return e.Parameters
}

// GetSourceUnitName returns the source unit name associated with the error definition.
func (e *ErrorDefinition) GetSourceUnitName() string {
	return e.SourceUnitName
}

// GetNodes returns an empty slice of nodes associated with the error definition.
func (e *ErrorDefinition) GetNodes() []Node[NodeType] {
	return []Node[NodeType]{}
}

// ToProto converts the ErrorDefinition node to its corresponding protobuf representation.
func (e *ErrorDefinition) ToProto() NodeType {
	proto := ast_pb.Error{
		Id:              e.GetId(),
		Name:            e.GetName(),
		NodeType:        e.GetType(),
		Src:             e.GetSrc().ToProto(),
		NameLocation:    e.GetNameLocation().ToProto(),
		Parameters:      e.GetParameters().ToProto(),
		TypeDescription: e.GetTypeDescription().ToProto(),
	}

	return NewTypedStruct(&proto, "Error")
}

// Parse parses the error definition context and populates the ErrorDefinition fields.
func (e *ErrorDefinition) Parse(
	unit *SourceUnit[Node[ast_pb.SourceUnit]],
	contractNode Node[NodeType],
	bodyCtx parser.IContractBodyElementContext,
	ctx *parser.ErrorDefinitionContext,
) Node[NodeType] {
	e.Src = SrcNode{
		Line:        int64(ctx.GetStart().GetLine()),
		Column:      int64(ctx.GetStart().GetColumn()),
		Start:       int64(ctx.GetStart().GetStart()),
		End:         int64(ctx.GetStop().GetStop()),
		Length:      int64(ctx.GetStop().GetStop() - ctx.GetStart().GetStart() + 1),
		ParentIndex: contractNode.GetId(),
	}
	e.SourceUnitName = unit.GetName()
	e.Name = ctx.GetName().GetText()
	e.NameLocation = SrcNode{
		Line:        int64(ctx.GetName().GetStart().GetLine()),
		Column:      int64(ctx.GetName().GetStart().GetColumn()),
		Start:       int64(ctx.GetName().GetStart().GetStart()),
		End:         int64(ctx.GetName().GetStop().GetStop()),
		Length:      int64(ctx.GetName().GetStop().GetStop() - ctx.GetName().GetStart().GetStart() + 1),
		ParentIndex: e.Id,
	}

	e.TypeDescription = &TypeDescription{
		TypeIdentifier: fmt.Sprintf(
			"t_error$_%s_%s_$%d", e.SourceUnitName, e.GetName(), e.GetId(),
		),
		TypeString: fmt.Sprintf(
			"error %s.%s", e.SourceUnitName, e.GetName(),
		),
	}

	parameters := NewParameterList(e.ASTBuilder)
	parameters.ParseErrorParameters(unit, e, ctx.AllErrorParameter())
	e.Parameters = parameters

	e.currentErrors = append(e.currentErrors, e)
	return e
}

// ParseGlobal parses the error definition context and populates the ErrorDefinition fields.
func (e *ErrorDefinition) ParseGlobal(ctx *parser.ErrorDefinitionContext) Node[NodeType] {
	e.Src = SrcNode{
		Line:        int64(ctx.GetStart().GetLine()),
		Column:      int64(ctx.GetStart().GetColumn()),
		Start:       int64(ctx.GetStart().GetStart()),
		End:         int64(ctx.GetStop().GetStop()),
		Length:      int64(ctx.GetStop().GetStop() - ctx.GetStart().GetStart() + 1),
		ParentIndex: 0,
	}
	e.SourceUnitName = "Global"
	e.Name = ctx.GetName().GetText()
	e.NameLocation = SrcNode{
		Line:        int64(ctx.GetName().GetStart().GetLine()),
		Column:      int64(ctx.GetName().GetStart().GetColumn()),
		Start:       int64(ctx.GetName().GetStart().GetStart()),
		End:         int64(ctx.GetName().GetStop().GetStop()),
		Length:      int64(ctx.GetName().GetStop().GetStop() - ctx.GetName().GetStart().GetStart() + 1),
		ParentIndex: e.Id,
	}

	e.TypeDescription = &TypeDescription{
		TypeIdentifier: fmt.Sprintf(
			"t_error$_%s_%s_$%d", e.SourceUnitName, e.GetName(), e.GetId(),
		),
		TypeString: fmt.Sprintf(
			"error %s.%s", e.SourceUnitName, e.GetName(),
		),
	}

	parameters := NewParameterList(e.ASTBuilder)
	parameters.ParseErrorParameters(nil, e, ctx.AllErrorParameter())
	e.Parameters = parameters

	e.globalDefinitions = append(e.globalDefinitions, e)
	return e
}

// There can be global enums that are outside of the contract body, so we need to handle them here.
func (b *ASTBuilder) EnterErrorDefinition(ctx *parser.ErrorDefinitionContext) {
	enumDef := NewErrorDefinition(b)
	enumDef.ParseGlobal(ctx)
}
