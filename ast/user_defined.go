package ast

import (
	ast_pb "github.com/unpackdev/protos/dist/go/ast"
	"github.com/unpackdev/solgo/parser"
)

// UserDefinedValueTypeDefinition represents a user-defined value type in Solidity.
type UserDefinedValueTypeDefinition struct {
	*ASTBuilder // Embedding ASTBuilder for building the AST.

	Id                    int64            `json:"id"`                              // Unique identifier for this node.
	NodeType              ast_pb.NodeType  `json:"nodeType"`                        // Type of the node, representing a user-defined value type.
	Src                   SrcNode          `json:"src"`                             // Source information about the node.
	Is                    bool             `json:"is"`                              // Additional flag (needs more contextual detail).
	Type                  string           `json:"type"`                            // Type name for the user-defined value type.
	TypeLocation          SrcNode          `json:"typeLocation"`                    // Source location for the type.
	Name                  string           `json:"name"`                            // Name of the user-defined value type.
	NameLocation          SrcNode          `json:"nameLocation"`                    // Source location for the name.
	TypeName              *TypeName        `json:"typeName"`                        // AST node representing the type's name.
	ReferencedDeclaration int64            `json:"referencedDeclaration,omitempty"` // Referenced declaration (if any).
	TypeDescription       *TypeDescription `json:"typeDescription"`                 // Description of the type.
}

// NewUserDefinedValueTypeDefinition creates a new UserDefinedValueTypeDefinition instance.
func NewUserDefinedValueTypeDefinition(b *ASTBuilder) *UserDefinedValueTypeDefinition {
	return &UserDefinedValueTypeDefinition{
		ASTBuilder: b,
		Id:         b.GetNextID(),
		NodeType:   ast_pb.NodeType_USER_DEFINED_VALUE_TYPE,
	}
}

// SetReferenceDescriptor sets the reference descriptions of the UserDefinedValueTypeDefinition node.
func (b *UserDefinedValueTypeDefinition) SetReferenceDescriptor(refId int64, refDesc *TypeDescription) bool {
	b.ReferencedDeclaration = refId
	b.TypeDescription = refDesc
	panic("Here...")
	if b.TypeName != nil {
		b.TypeName.SetReferenceDescriptor(refId, refDesc)

		if b.TypeName.GetPathNode() != nil {
			b.TypeName.GetPathNode().SetReferenceDescriptor(refId, refDesc)
		}
	}
	return true
}

// GetId returns the unique identifier of the UserDefinedValueTypeDefinition node.
func (b *UserDefinedValueTypeDefinition) GetId() int64 {
	return b.Id
}

// GetType returns the type of the node, which is 'USER_DEFINED_VALUE_TYPE' for a UserDefinedValueTypeDefinition node.
func (b *UserDefinedValueTypeDefinition) GetType() ast_pb.NodeType {
	return b.NodeType
}

// GetSrc returns the source information about the node, such as its line and column numbers in the source file.
func (b *UserDefinedValueTypeDefinition) GetSrc() SrcNode {
	return b.Src
}

// GetTypeDescription returns the type description of the UserDefinedValueTypeDefinition node.
func (b *UserDefinedValueTypeDefinition) GetTypeDescription() *TypeDescription {
	return b.TypeDescription
}

// GetNodes returns the child nodes of the UserDefinedValueTypeDefinition node.
func (b *UserDefinedValueTypeDefinition) GetNodes() []Node[NodeType] {
	return []Node[NodeType]{b.TypeName}
}

// GetIs returns the additional flag of the UserDefinedValueTypeDefinition node.
func (b *UserDefinedValueTypeDefinition) GetIs() bool {
	return b.Is
}

// GetUserType returns the type name of the UserDefinedValueTypeDefinition node.
func (b *UserDefinedValueTypeDefinition) GetUserType() string {
	return b.Type
}

// GetTypeLocation returns the source location of the type name of the UserDefinedValueTypeDefinition node.
func (b *UserDefinedValueTypeDefinition) GetTypeLocation() SrcNode {
	return b.TypeLocation
}

// GetName returns the name of the UserDefinedValueTypeDefinition node.
func (b *UserDefinedValueTypeDefinition) GetName() string {
	return b.Name
}

// GetNameLocation returns the source location of the name of the UserDefinedValueTypeDefinition node.
func (b *UserDefinedValueTypeDefinition) GetNameLocation() SrcNode {
	return b.NameLocation
}

// GetTypeName returns the type name of the UserDefinedValueTypeDefinition node.
func (b *UserDefinedValueTypeDefinition) GetTypeName() *TypeName {
	return b.TypeName
}

// GetReferencedDeclaration returns the referenced declaration of the type name in the UserDefinedValueTypeDefinition node.
func (b *UserDefinedValueTypeDefinition) GetReferencedDeclaration() int64 {
	return b.ReferencedDeclaration
}

// ToProto returns the protobuf representation of the UserDefinedValueTypeDefinition node.
func (b *UserDefinedValueTypeDefinition) ToProto() NodeType {
	proto := ast_pb.UserDefinedValueTypeDefinition{
		Id:                    b.GetId(),
		NodeType:              b.GetType(),
		Src:                   b.GetSrc().ToProto(),
		Is:                    b.GetIs(),
		Type:                  b.GetUserType(),
		TypeLocation:          b.GetTypeLocation().ToProto(),
		Name:                  b.GetName(),
		NameLocation:          b.GetNameLocation().ToProto(),
		TypeName:              b.GetTypeName().ToProto().(*ast_pb.TypeName),
		ReferencedDeclaration: b.GetReferencedDeclaration(),
	}

	return NewTypedStruct(&proto, "UserDefinedValueTypeDefinition")
}

// Parse populates the UserDefinedValueTypeDefinition fields using the provided parser context.
func (b *UserDefinedValueTypeDefinition) Parse(
	unit *SourceUnit[Node[ast_pb.SourceUnit]],
	contractNode Node[NodeType],
	bodyCtx parser.IContractBodyElementContext,
	ctx *parser.UserDefinedValueTypeDefinitionContext,
) Node[NodeType] {
	b.Src = SrcNode{
		Line:        int64(ctx.GetStart().GetLine()),
		Start:       int64(ctx.GetStart().GetStart()),
		End:         int64(ctx.GetStop().GetStop()),
		Length:      int64(ctx.GetStop().GetStop() - ctx.GetStart().GetStart() + 1),
		ParentIndex: contractNode.GetId(),
	}

	b.Is = ctx.Is() != nil

	if ctx.Type() != nil {
		b.Type = ctx.Type().GetText()
		b.TypeLocation = SrcNode{
			Line:        int64(ctx.Type().GetSymbol().GetLine()),
			Start:       int64(ctx.Type().GetSymbol().GetStart()),
			End:         int64(ctx.Type().GetSymbol().GetStop()),
			Length:      int64(ctx.Type().GetSymbol().GetStop() - ctx.Type().GetSymbol().GetStart() + 1),
			ParentIndex: b.GetId(),
		}
	}

	if ctx.Identifier() != nil {
		identifier := ctx.Identifier()
		b.Name = identifier.GetText()
		b.NameLocation = SrcNode{
			Line:        int64(identifier.GetStart().GetLine()),
			Start:       int64(identifier.GetStart().GetStart()),
			End:         int64(identifier.GetStart().GetStop()),
			Length:      int64(identifier.GetStart().GetStop() - identifier.GetStart().GetStart() + 1),
			ParentIndex: b.GetId(),
		}
	} else if ctx.GetName() != nil {
		identifier := ctx.GetName()
		b.Name = identifier.GetText()
		b.NameLocation = SrcNode{
			Line:        int64(identifier.GetStart().GetLine()),
			Start:       int64(identifier.GetStart().GetStart()),
			End:         int64(identifier.GetStart().GetStop()),
			Length:      int64(identifier.GetStart().GetStop() - identifier.GetStart().GetStart() + 1),
			ParentIndex: b.GetId(),
		}
	}

	if ctx.ElementaryTypeName() != nil {
		typeName := NewTypeName(b.ASTBuilder)
		typeName.WithParentNode(contractNode)
		typeName.ParseElementaryType(unit, nil, b.GetId(), ctx.ElementaryTypeName())
		b.TypeName = typeName
		b.TypeDescription = typeName.GetTypeDescription()
	}

	b.currentUserDefinedVariables = append(b.currentUserDefinedVariables, b)

	return b
}

// ParseGlobal populates the UserDefinedValueTypeDefinition fields using the provided parser context.
func (b *UserDefinedValueTypeDefinition) ParseGlobal(
	ctx *parser.UserDefinedValueTypeDefinitionContext,
) Node[NodeType] {
	b.Src = SrcNode{
		Line:        int64(ctx.GetStart().GetLine()),
		Start:       int64(ctx.GetStart().GetStart()),
		End:         int64(ctx.GetStop().GetStop()),
		Length:      int64(ctx.GetStop().GetStop() - ctx.GetStart().GetStart() + 1),
		ParentIndex: 0,
	}

	b.Is = ctx.Is() != nil

	if ctx.Type() != nil {
		b.Type = ctx.Type().GetText()
		b.TypeLocation = SrcNode{
			Line:        int64(ctx.Type().GetSymbol().GetLine()),
			Start:       int64(ctx.Type().GetSymbol().GetStart()),
			End:         int64(ctx.Type().GetSymbol().GetStop()),
			Length:      int64(ctx.Type().GetSymbol().GetStop() - ctx.Type().GetSymbol().GetStart() + 1),
			ParentIndex: b.GetId(),
		}
	}

	if ctx.Identifier() != nil {
		identifier := ctx.Identifier()
		b.Name = identifier.GetText()
		b.NameLocation = SrcNode{
			Line:        int64(identifier.GetStart().GetLine()),
			Start:       int64(identifier.GetStart().GetStart()),
			End:         int64(identifier.GetStart().GetStop()),
			Length:      int64(identifier.GetStart().GetStop() - identifier.GetStart().GetStart() + 1),
			ParentIndex: b.GetId(),
		}
	} else if ctx.GetName() != nil {
		identifier := ctx.GetName()
		b.Name = identifier.GetText()
		b.NameLocation = SrcNode{
			Line:        int64(identifier.GetStart().GetLine()),
			Start:       int64(identifier.GetStart().GetStart()),
			End:         int64(identifier.GetStart().GetStop()),
			Length:      int64(identifier.GetStart().GetStop() - identifier.GetStart().GetStart() + 1),
			ParentIndex: b.GetId(),
		}
	}

	if ctx.ElementaryTypeName() != nil {
		typeName := NewTypeName(b.ASTBuilder)
		typeName.ParseElementaryType(nil, nil, b.GetId(), ctx.ElementaryTypeName())
		b.TypeName = typeName
		b.TypeDescription = typeName.GetTypeDescription()
	}

	b.currentUserDefinedVariables = append(b.currentUserDefinedVariables, b)

	return b
}

func (b *ASTBuilder) EnterUserDefinedValueTypeDefinition(ctx *parser.UserDefinedValueTypeDefinitionContext) {
	child := NewUserDefinedValueTypeDefinition(b)
	child.ParseGlobal(ctx)
}
