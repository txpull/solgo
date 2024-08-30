package ast

import (
	"github.com/goccy/go-json"

	ast_pb "github.com/unpackdev/protos/dist/go/ast"
	"github.com/unpackdev/solgo/parser"
)

// ModifierDefinition represents a modifier definition node in the abstract syntax tree.
type ModifierDefinition struct {
	*ASTBuilder

	Id           int64             `json:"id"`           // Unique identifier of the modifier definition node.
	Name         string            `json:"name"`         // Name of the modifier.
	NodeType     ast_pb.NodeType   `json:"nodeType"`     // Type of the node.
	Src          SrcNode           `json:"src"`          // Source location information.
	NameLocation SrcNode           `json:"nameLocation"` // Source location information of the name.
	Visibility   ast_pb.Visibility `json:"visibility"`   // Visibility of the modifier.
	Virtual      bool              `json:"virtual"`      // Indicates if the modifier is virtual.
	Parameters   *ParameterList    `json:"parameters"`   // List of parameters for the modifier.
	Body         *BodyNode         `json:"body"`         // Body node of the modifier.
}

// NewModifierDefinition creates a new instance of ModifierDefinition with the provided ASTBuilder.
func NewModifierDefinition(b *ASTBuilder) *ModifierDefinition {
	return &ModifierDefinition{
		ASTBuilder: b,
		Id:         b.GetNextID(),
		NodeType:   ast_pb.NodeType_MODIFIER_DEFINITION,
		Visibility: ast_pb.Visibility_INTERNAL,
	}
}

// SetReferenceDescriptor sets the reference descriptors of the ModifierDefinition node.
func (m *ModifierDefinition) SetReferenceDescriptor(refId int64, refDesc *TypeDescription) bool {
	return false
}

// GetId returns the unique identifier of the modifier definition node.
func (m *ModifierDefinition) GetId() int64 {
	return m.Id
}

// GetType returns the type of the node.
func (m *ModifierDefinition) GetType() ast_pb.NodeType {
	return m.NodeType
}

// GetSrc returns the source location information of the modifier definition node.
func (m *ModifierDefinition) GetSrc() SrcNode {
	return m.Src
}

// GetNameLocation returns the source location information of the name of the modifier definition.
func (m *ModifierDefinition) GetNameLocation() SrcNode {
	return m.NameLocation
}

// GetName returns the name of the modifier.
func (m *ModifierDefinition) GetName() string {
	return m.Name
}

// GetTypeDescription returns the type description of the modifier definition.
func (m *ModifierDefinition) GetTypeDescription() *TypeDescription {
	return &TypeDescription{
		TypeString:     "modifier",
		TypeIdentifier: "$_t_modifier",
	}
}

// GetNodes returns a list of nodes associated with the modifier definition (body statements).
func (m *ModifierDefinition) GetNodes() []Node[NodeType] {
	return m.Body.GetNodes()
}

// IsVirtual returns true if the modifier is virtual.
func (m *ModifierDefinition) IsVirtual() bool {
	return m.Virtual
}

// GetVisibility returns the visibility of the modifier.
func (m *ModifierDefinition) GetVisibility() ast_pb.Visibility {
	return m.Visibility
}

// GetParameters returns the parameter list of the modifier.
func (m *ModifierDefinition) GetParameters() *ParameterList {
	return m.Parameters
}

// GetBody returns the body node of the modifier.
func (m *ModifierDefinition) GetBody() *BodyNode {
	return m.Body
}

func (m *ModifierDefinition) UnmarshalJSON(data []byte) error {
	var tempMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &tempMap); err != nil {
		return err
	}

	if id, ok := tempMap["id"]; ok {
		if err := json.Unmarshal(id, &m.Id); err != nil {
			return err
		}
	}

	if name, ok := tempMap["name"]; ok {
		if err := json.Unmarshal(name, &m.Name); err != nil {
			return err
		}
	}

	if nodeType, ok := tempMap["nodeType"]; ok {
		if err := json.Unmarshal(nodeType, &m.NodeType); err != nil {
			return err
		}
	}

	if src, ok := tempMap["src"]; ok {
		if err := json.Unmarshal(src, &m.Src); err != nil {
			return err
		}
	}

	if nameLocation, ok := tempMap["nameLocation"]; ok {
		if err := json.Unmarshal(nameLocation, &m.NameLocation); err != nil {
			return err
		}
	}

	if visibility, ok := tempMap["visibility"]; ok {
		if err := json.Unmarshal(visibility, &m.Visibility); err != nil {
			return err
		}
	}

	if virtual, ok := tempMap["virtual"]; ok {
		if err := json.Unmarshal(virtual, &m.Virtual); err != nil {
			return err
		}
	}

	if parameters, ok := tempMap["parameters"]; ok {
		if err := json.Unmarshal(parameters, &m.Parameters); err != nil {
			return err
		}
	}

	if body, ok := tempMap["body"]; ok {
		if err := json.Unmarshal(body, &m.Body); err != nil {
			return err
		}
	}

	return nil
}

// ToProto converts the ModifierDefinition node to its corresponding protobuf representation.
func (m *ModifierDefinition) ToProto() NodeType {
	proto := ast_pb.Modifier{
		Id:           m.GetId(),
		Name:         m.GetName(),
		NodeType:     m.GetType(),
		Src:          m.GetSrc().ToProto(),
		NameLocation: m.GetNameLocation().ToProto(),
		Virtual:      m.IsVirtual(),
		Visibility:   m.GetVisibility(),
		Parameters:   m.GetParameters().ToProto(),
		Body:         m.GetBody().ToProto().(*ast_pb.Body),
	}

	return NewTypedStruct(&proto, "Modifier")
}

// ParseDefinition parses the modifier definition context and populates the ModifierDefinition fields.
func (m *ModifierDefinition) ParseDefinition(
	unit *SourceUnit[Node[ast_pb.SourceUnit]],
	contractNode Node[NodeType],
	bodyCtx parser.IContractBodyElementContext,
	ctx *parser.ModifierDefinitionContext,
) Node[NodeType] {
	m.Src = SrcNode{
		Line:        int64(ctx.GetStart().GetLine()),
		Column:      int64(ctx.GetStart().GetColumn()),
		Start:       int64(ctx.GetStart().GetStart()),
		End:         int64(ctx.GetStop().GetStop()),
		Length:      int64(ctx.GetStop().GetStop() - ctx.GetStart().GetStart() + 1),
		ParentIndex: contractNode.GetId(),
	}
	m.Name = ctx.Identifier().GetText()
	m.NameLocation = SrcNode{
		Line:        int64(ctx.Identifier().GetStart().GetLine()),
		Column:      int64(ctx.Identifier().GetStart().GetColumn()),
		Start:       int64(ctx.Identifier().GetStart().GetStart()),
		End:         int64(ctx.Identifier().GetStop().GetStop()),
		Length:      int64(ctx.Identifier().GetStop().GetStop() - ctx.Identifier().GetStart().GetStart() + 1),
		ParentIndex: m.GetId(),
	}

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
	} else {
		parameters.Src = m.Src
	}
	m.Parameters = parameters
	bodyNode := NewBodyNode(m.ASTBuilder, false)
	if ctx.Block() != nil && !ctx.Block().IsEmpty() {
		bodyNode.ParseBlock(unit, contractNode, m, ctx.Block())

		if ctx.Block().AllUncheckedBlock() != nil {
			for _, uncheckedCtx := range ctx.Block().AllUncheckedBlock() {
				bodyNode := NewBodyNode(m.ASTBuilder, false)
				bodyNode.ParseUncheckedBlock(unit, contractNode, m, uncheckedCtx)
				m.Body.Statements = append(m.Body.Statements, bodyNode)
			}
		}
	}
	m.Body = bodyNode

	m.currentModifiers = append(m.currentModifiers, m)
	return m
}
