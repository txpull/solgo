package ast

import (
	ast_pb "github.com/txpull/protos/dist/go/ast"
	"github.com/txpull/solgo/parser"
)

type ModifierDefinition struct {
	*ASTBuilder

	Id         int64             `json:"id"`
	Name       string            `json:"name"`
	NodeType   ast_pb.NodeType   `json:"node_type"`
	Src        SrcNode           `json:"src"`
	Visibility ast_pb.Visibility `json:"visibility"`
	Virtual    bool              `json:"virtual"`
	Parameters *ParameterList    `json:"parameters"`
	Body       *BodyNode         `json:"body"`
}

func NewModifierDefinition(b *ASTBuilder) *ModifierDefinition {
	return &ModifierDefinition{
		ASTBuilder: b,
		Id:         b.GetNextID(),
		NodeType:   ast_pb.NodeType_MODIFIER_DEFINITION,
		Visibility: ast_pb.Visibility_INTERNAL,
	}
}

func (m *ModifierDefinition) GetId() int64 {
	return m.Id
}

func (m *ModifierDefinition) GetType() ast_pb.NodeType {
	return m.NodeType
}

func (m *ModifierDefinition) GetSrc() SrcNode {
	return m.Src
}

func (m *ModifierDefinition) GetName() string {
	return m.Name
}

func (m *ModifierDefinition) GetTypeDescription() *TypeDescription {
	return nil
}

func (m *ModifierDefinition) GetNodes() []Node[NodeType] {
	return nil
}

func (m *ModifierDefinition) ToProto() NodeType {
	return &ast_pb.Modifier{}
}

func (m *ModifierDefinition) ParseDefinition(
	unit *SourceUnit[Node[ast_pb.SourceUnit]],
	contractNode Node[NodeType],
	bodyCtx parser.IContractBodyElementContext,
	ctx *parser.ModifierDefinitionContext,
) Node[NodeType] {
	m.Src = SrcNode{
		Id:          m.GetNextID(),
		Line:        int64(ctx.GetStart().GetLine()),
		Column:      int64(ctx.GetStart().GetColumn()),
		Start:       int64(ctx.GetStart().GetStart()),
		End:         int64(ctx.GetStop().GetStop()),
		Length:      int64(ctx.GetStop().GetStop() - ctx.GetStart().GetStart() + 1),
		ParentIndex: contractNode.GetId(),
	}
	m.Name = ctx.Identifier().GetText()

	if ctx.AllVirtual() != nil {
		for _, virtualCtx := range ctx.AllVirtual() {
			if virtualCtx.GetText() == "virtual" {
				m.Virtual = true
			}
		}
	}

	parameters := NewParameterList(m.ASTBuilder)
	if ctx.ParameterList() != nil {
		parameters.Parse(unit, contractNode, ctx.ParameterList())
	}
	m.Parameters = parameters

	if ctx.Block() != nil && !ctx.Block().IsEmpty() {
		bodyNode := NewBodyNode(m.ASTBuilder)
		bodyNode.ParseBlock(unit, contractNode, m, ctx.Block())
		m.Body = bodyNode

		if ctx.Block().AllUncheckedBlock() != nil {
			for _, uncheckedCtx := range ctx.Block().AllUncheckedBlock() {
				bodyNode := NewBodyNode(m.ASTBuilder)
				bodyNode.ParseUncheckedBlock(unit, contractNode, m, uncheckedCtx)
				m.Body.Statements = append(m.Body.Statements, bodyNode)
			}
		}
	}

	m.currentModifiers = append(m.currentModifiers, m)
	return m
}

func (m *ModifierDefinition) Parse(unit *SourceUnit[Node[ast_pb.SourceUnit]], fnNode Node[NodeType], ctx parser.IModifierInvocationContext) {
	m.Src = SrcNode{
		Id:          m.GetNextID(),
		Line:        int64(ctx.GetStart().GetLine()),
		Column:      int64(ctx.GetStart().GetColumn()),
		Start:       int64(ctx.GetStart().GetStart()),
		End:         int64(ctx.GetStop().GetStop()),
		Length:      int64(ctx.GetStop().GetStop() - ctx.GetStart().GetStart() + 1),
		ParentIndex: fnNode.GetId(),
	}
	m.NodeType = ast_pb.NodeType_MODIFIER_INVOCATION

	/**
	modifier := &ast_pb.Modifier{
			Id: atomic.AddInt64(&b.nextID, 1) - 1,
			Src: &ast_pb.Src{
				Line:        int64(modifierCtx.GetStart().GetLine()),
				Column:      int64(modifierCtx.GetStart().GetColumn()),
				Start:       int64(modifierCtx.GetStart().GetStart()),
				End:         int64(modifierCtx.GetStop().GetStop()),
				Length:      int64(modifierCtx.GetStop().GetStop() - modifierCtx.GetStart().GetStart() + 1),
				ParentIndex: node.Id,
			},
			NodeType: ast_pb.NodeType_MODIFIER_INVOCATION,
		}

		if modifierCtx.CallArgumentList() != nil {
			for _, argumentCtx := range modifierCtx.CallArgumentList().AllExpression() {
				argument := b.parseExpression(
					sourceUnit, nil, nil, nil, modifier.Id, argumentCtx,
				)
				modifier.Arguments = append(modifier.Arguments, argument)
			}
		}

		identifierCtx := modifierCtx.IdentifierPath()
		if identifierCtx != nil {
			modifier.ModifierName = &ast_pb.ModifierName{
				Id: atomic.AddInt64(&b.nextID, 1) - 1,
				Src: &ast_pb.Src{
					Line:        int64(identifierCtx.GetStart().GetLine()),
					Column:      int64(identifierCtx.GetStart().GetColumn()),
					Start:       int64(identifierCtx.GetStart().GetStart()),
					End:         int64(identifierCtx.GetStop().GetStop()),
					Length:      int64(identifierCtx.GetStop().GetStop() - identifierCtx.GetStart().GetStart() + 1),
					ParentIndex: modifier.Id,
				},
				NodeType: ast_pb.NodeType_IDENTIFIER,
				Name:     identifierCtx.GetText(),
			}
		}
		**/
}
