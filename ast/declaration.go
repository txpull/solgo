package ast

import (
	ast_pb "github.com/txpull/protos/dist/go/ast"
	"github.com/txpull/solgo/parser"
)

type Declaration struct {
	*ASTBuilder

	IsConstant      bool                   `json:"is_constant"`
	Id              int64                  `json:"id"`
	Mutability      ast_pb.Mutability      `json:"mutability"`
	Name            string                 `json:"name"`
	NodeType        ast_pb.NodeType        `json:"node_type"`
	Scope           int64                  `json:"scope"`
	Src             SrcNode                `json:"src"`
	IsStateVariable bool                   `json:"is_state_variable"`
	StorageLocation ast_pb.StorageLocation `json:"storage_location"`
	TypeName        *TypeName              `json:"type_name"`
	Visibility      ast_pb.Visibility      `json:"visibility"`
}

func NewDeclaration(b *ASTBuilder) *Declaration {
	return &Declaration{
		ASTBuilder:      b,
		Id:              b.GetNextID(),
		IsStateVariable: false,
		IsConstant:      false,
	}
}

func (d *Declaration) GetId() int64 {
	return d.Id
}

func (d *Declaration) GetType() ast_pb.NodeType {
	return d.NodeType
}

func (d *Declaration) GetSrc() SrcNode {
	return d.Src
}

func (d *Declaration) GetName() string {
	return d.Name
}

func (d *Declaration) GetTypeName() *TypeName {
	return d.TypeName
}

func (d *Declaration) GetScope() int64 {
	return d.Scope
}

func (d *Declaration) GetMutability() ast_pb.Mutability {
	return d.Mutability
}

func (d *Declaration) GetVisibility() ast_pb.Visibility {
	return d.Visibility
}

func (d *Declaration) GetStorageLocation() ast_pb.StorageLocation {
	return d.StorageLocation
}

func (d *Declaration) GetIsConstant() bool {
	return d.IsConstant
}

func (d *Declaration) GetIsStateVariable() bool {
	return d.IsStateVariable
}

func (d *Declaration) GetPathNode() *PathNode {
	return nil
}

func (d *Declaration) GetReferencedDeclaration() int64 {
	return 0
}

func (d *Declaration) GetKeyType() *TypeName {
	return nil
}

func (d *Declaration) GetValueType() *TypeName {
	return nil
}

func (d *Declaration) GetTypeDescription() TypeDescription {
	return TypeDescription{}
}

func (d *Declaration) ToProto() NodeType {
	return ast_pb.Declaration{}
}

func (d *Declaration) ParseVariableDeclaration(
	unit *SourceUnit[Node[ast_pb.SourceUnit]],
	contractNode Node[NodeType],
	fnNode Node[NodeType],
	bodyNode *BodyNode,
	vDeclar *VariableDeclaration,
	ctx parser.IVariableDeclarationContext,
) {
	d.NodeType = ast_pb.NodeType_VARIABLE_DECLARATION
	d.Src = SrcNode{
		Id:          d.GetNextID(),
		Line:        int64(ctx.GetStart().GetLine()),
		Column:      int64(ctx.GetStart().GetColumn()),
		Start:       int64(ctx.GetStart().GetStart()),
		End:         int64(ctx.GetStop().GetStop()),
		Length:      int64(ctx.GetStop().GetStop() - ctx.GetStart().GetStart() + 1),
		ParentIndex: vDeclar.GetId(),
	}

	d.StorageLocation = getStorageLocationFromDataLocationCtx(ctx.DataLocation())
	d.Visibility = ast_pb.Visibility_INTERNAL
	d.Mutability = ast_pb.Mutability_MUTABLE

	if ctx.Identifier() != nil {
		d.Name = ctx.Identifier().GetText()
	}

	d.Scope = bodyNode.GetId()

	typeName := NewTypeName(d.ASTBuilder)
	typeName.Parse(unit, fnNode, d.GetId(), ctx.TypeName())
	d.TypeName = typeName
}