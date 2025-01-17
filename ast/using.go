package ast

import (
	ast_pb "github.com/unpackdev/protos/dist/go/ast"
	"github.com/unpackdev/solgo/parser"
)

// UsingDirective represents a Solidity using directive, which is used to import and use symbols from external libraries.
type UsingDirective struct {
	*ASTBuilder

	Id              int64            `json:"id"`
	NodeType        ast_pb.NodeType  `json:"nodeType"`
	Src             SrcNode          `json:"src"`
	TypeDescription *TypeDescription `json:"typeDescription"`
	TypeName        *TypeName        `json:"typeName"`
	LibraryName     *LibraryName     `json:"libraryName"`
}

// LibraryName represents the name of an external library referenced in a using directive.
type LibraryName struct {
	*ASTBuilder

	Id                    int64           `json:"id"`
	NodeType              ast_pb.NodeType `json:"nodeType"`
	Src                   SrcNode         `json:"src"`
	Name                  string          `json:"name"`
	ReferencedDeclaration int64           `json:"referencedDeclaration"`
}

// ToProto converts the LibraryName instance to its corresponding protocol buffer representation.
func (ln *LibraryName) ToProto() *ast_pb.LibraryName {
	return &ast_pb.LibraryName{
		Id:                    ln.Id,
		Name:                  ln.Name,
		NodeType:              ln.NodeType,
		ReferencedDeclaration: ln.ReferencedDeclaration,
		Src:                   ln.Src.ToProto(),
	}
}

// NewUsingDirective creates a new UsingDirective instance with the given ASTBuilder.
func NewUsingDirective(b *ASTBuilder) *UsingDirective {
	return &UsingDirective{
		ASTBuilder: b,
		Id:         b.GetNextID(),
		NodeType:   ast_pb.NodeType_USING_FOR_DIRECTIVE,
	}
}

// SetReferenceDescriptor sets the reference descriptions of the UsingDirective node.
func (u *UsingDirective) SetReferenceDescriptor(refId int64, refDesc *TypeDescription) bool {
	u.TypeDescription = refDesc
	u.LibraryName.ReferencedDeclaration = refId
	return false
}

// GetId returns the unique identifier of the UsingDirective.
func (u *UsingDirective) GetId() int64 {
	return u.Id
}

// GetType returns the node type of the UsingDirective.
func (u *UsingDirective) GetType() ast_pb.NodeType {
	return u.NodeType
}

// GetSrc returns the source location information of the UsingDirective.
func (u *UsingDirective) GetSrc() SrcNode {
	return u.Src
}

// GetTypeDescription returns the type description associated with the UsingDirective.
func (u *UsingDirective) GetTypeDescription() *TypeDescription {
	return u.TypeDescription
}

// GetTypeName returns the type name associated with the UsingDirective.
func (u *UsingDirective) GetTypeName() *TypeName {
	return u.TypeName
}

// GetLibraryName returns the library name associated with the UsingDirective.
func (u *UsingDirective) GetLibraryName() *LibraryName {
	return u.LibraryName
}

// GetReferencedDeclaration returns the referenced declaration of the UsingDirective.
func (u *UsingDirective) GetReferencedDeclaration() int64 {
	return u.TypeName.ReferencedDeclaration
}

// GetPathNode returns the path node associated with the UsingDirective.
func (u *UsingDirective) GetPathNode() *PathNode {
	return u.TypeName.PathNode
}

// GetNodes returns a list of child nodes for traversal within the UsingDirective.
func (u *UsingDirective) GetNodes() []Node[NodeType] {
	return []Node[NodeType]{
		u.GetTypeName(),
	}
}

// ToProto converts the UsingDirective instance to its corresponding protocol buffer representation.
func (u *UsingDirective) ToProto() NodeType {
	proto := ast_pb.Using{
		Id:          u.Id,
		Name:        u.LibraryName.Name,
		NodeType:    u.NodeType,
		Src:         u.Src.ToProto(),
		LibraryName: u.LibraryName.ToProto(),
		TypeName:    u.TypeName.ToProto().(*ast_pb.TypeName),
	}

	return NewTypedStruct(&proto, "Using")
}

// Parse populates the UsingDirective instance with information parsed from the provided contexts.
func (u *UsingDirective) Parse(
	unit *SourceUnit[Node[ast_pb.SourceUnit]],
	contractNode Node[NodeType],
	bodyCtx parser.IContractBodyElementContext,
	ctx *parser.UsingDirectiveContext,
) {
	u.Src = SrcNode{
		Line:        int64(ctx.GetStart().GetLine()),
		Start:       int64(ctx.GetStart().GetStart()),
		End:         int64(ctx.GetStop().GetStop()),
		Length:      int64(ctx.GetStop().GetStop() - ctx.GetStart().GetStart() + 1),
		ParentIndex: contractNode.GetId(),
	}

	u.LibraryName = u.getLibraryName(ctx.IdentifierPath(0))

	if ctx.TypeName() != nil {
		typeName := NewTypeName(u.ASTBuilder)
		typeName.Parse(unit, contractNode, u.GetId(), ctx.TypeName())
		u.TypeName = typeName
		u.TypeDescription = typeName.TypeDescription
	} else if ctx.Mul() != nil {
		typeName := NewTypeName(u.ASTBuilder)
		typeName.ParseMul(unit, contractNode, u.GetId(), ctx.Mul())
		u.TypeName = typeName
		u.TypeDescription = typeName.TypeDescription
	}
}

// getLibraryName extracts and returns the LibraryName instance from the provided identifier context.
func (u *UsingDirective) getLibraryName(identifierCtx parser.IIdentifierPathContext) *LibraryName {
	return &LibraryName{
		Id:       u.GetNextID(),
		NodeType: ast_pb.NodeType_IDENTIFIER_PATH,
		Src: SrcNode{
			Line:        int64(identifierCtx.GetStart().GetLine()),
			Start:       int64(identifierCtx.GetStart().GetStart()),
			End:         int64(identifierCtx.GetStop().GetStop()),
			Length:      int64(identifierCtx.GetStop().GetStop() - identifierCtx.GetStart().GetStart() + 1),
			ParentIndex: u.Id,
		},
		Name: identifierCtx.GetText(),
		ReferencedDeclaration: func() int64 {
			for _, unit := range u.sourceUnits {
				for _, symbol := range unit.ExportedSymbols {
					if symbol.Name == identifierCtx.GetText() {
						return symbol.Id
					}
				}
			}
			return 0
		}(),
	}
}
