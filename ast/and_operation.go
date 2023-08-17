package ast

import (
	v3 "github.com/cncf/xds/go/xds/type/v3"
	ast_pb "github.com/txpull/protos/dist/go/ast"
	"github.com/txpull/solgo/parser"
)

// AndOperation represents an 'and' operation in an abstract syntax tree.
type AndOperation struct {
	*ASTBuilder

	Id               int64              `json:"id"`
	NodeType         ast_pb.NodeType    `json:"node_type"`
	Src              SrcNode            `json:"src"`
	Expressions      []Node[NodeType]   `json:"expressions"`
	TypeDescriptions []*TypeDescription `json:"type_descriptions"`
}

// NewAndOperationExpression creates a new AndOperation instance.
func NewAndOperationExpression(b *ASTBuilder) *AndOperation {
	return &AndOperation{
		ASTBuilder:       b,
		Id:               b.GetNextID(),
		NodeType:         ast_pb.NodeType_AND_OPERATION,
		TypeDescriptions: make([]*TypeDescription, 0),
	}
}

// SetReferenceDescriptor sets the reference descriptions of the AndOperation node.
// This function always returns false for now.
func (b *AndOperation) SetReferenceDescriptor(refId int64, refDesc *TypeDescription) bool {
	return false
}

// GetId returns the ID of the AndOperation.
func (f *AndOperation) GetId() int64 {
	return f.Id
}

// GetType returns the NodeType of the AndOperation.
func (f *AndOperation) GetType() ast_pb.NodeType {
	return f.NodeType
}

// GetSrc returns the source information of the AndOperation.
func (f *AndOperation) GetSrc() SrcNode {
	return f.Src
}

// GetTypeDescription returns the type description associated with the AndOperation.
func (f *AndOperation) GetTypeDescription() *TypeDescription {
	return f.TypeDescriptions[0]
}

// GetNodes returns the child nodes of the AndOperation.
func (f *AndOperation) GetNodes() []Node[NodeType] {
	toReturn := []Node[NodeType]{}
	toReturn = append(toReturn, f.Expressions...)
	return toReturn
}

// GetExpressions returns the expressions within the AndOperation.
func (f *AndOperation) GetExpressions() []Node[NodeType] {
	return f.Expressions
}

// ToProto converts the AndOperation to its corresponding protocol buffer representation.
func (f *AndOperation) ToProto() NodeType {
	proto := ast_pb.AndOperation{
		Id:               f.GetId(),
		NodeType:         f.GetType(),
		Src:              f.GetSrc().ToProto(),
		Expressions:      make([]*v3.TypedStruct, 0),
		TypeDescriptions: make([]*ast_pb.TypeDescription, 0),
	}

	for _, exp := range f.GetExpressions() {
		proto.Expressions = append(proto.Expressions, exp.ToProto().(*v3.TypedStruct))
	}

	for _, typeDesc := range f.TypeDescriptions {
		proto.TypeDescriptions = append(proto.TypeDescriptions, typeDesc.ToProto())
	}

	return NewTypedStruct(nil, "AndOperation")
}

// Parse parses the AndOperation node from the parsing context and associates it with other nodes.
func (f *AndOperation) Parse(
	unit *SourceUnit[Node[ast_pb.SourceUnit]],
	contractNode Node[NodeType],
	fnNode Node[NodeType],
	bodyNode *BodyNode,
	vDeclar *VariableDeclaration,
	expNode Node[NodeType],
	ctx *parser.AndOperationContext,
) Node[NodeType] {
	f.Id = f.GetNextID()
	f.Src = SrcNode{
		Id:     f.GetNextID(),
		Line:   int64(ctx.GetStart().GetLine()),
		Column: int64(ctx.GetStart().GetColumn()),
		Start:  int64(ctx.GetStart().GetStart()),
		End:    int64(ctx.GetStop().GetStop()),
		Length: int64(ctx.GetStop().GetStop() - ctx.GetStart().GetStart() + 1),
		ParentIndex: func() int64 {
			if vDeclar != nil {
				return vDeclar.GetId()
			}

			if expNode != nil {
				return expNode.GetId()
			}

			if bodyNode != nil {
				return bodyNode.GetId()
			}

			if fnNode != nil {
				return fnNode.GetId()
			}

			return contractNode.GetId()
		}(),
	}

	expression := NewExpression(f.ASTBuilder)

	for _, expr := range ctx.AllExpression() {
		parsedExp := expression.Parse(unit, contractNode, fnNode, bodyNode, vDeclar, f, expr)
		f.Expressions = append(
			f.Expressions,
			parsedExp,
		)
		f.TypeDescriptions = append(f.TypeDescriptions, parsedExp.GetTypeDescription())
	}

	return f
}