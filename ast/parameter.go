package ast

import (
	"github.com/goccy/go-json"
	ast_pb "github.com/unpackdev/protos/dist/go/ast"
	"github.com/unpackdev/solgo/parser"
)

// Parameter represents a parameter node in the abstract syntax tree.
type Parameter struct {
	*ASTBuilder

	Id              int64                  `json:"id"`                        // Unique identifier of the parameter node.
	NodeType        ast_pb.NodeType        `json:"nodeType"`                  // Type of the node.
	Src             SrcNode                `json:"src"`                       // Source location information.
	NameLocation    *SrcNode               `json:"nameLocation,omitempty"`    // Source location information of the name.
	Scope           int64                  `json:"scope,omitempty"`           // Scope of the parameter.
	Name            string                 `json:"name"`                      // Name of the parameter.
	TypeName        *TypeName              `json:"typeName,omitempty"`        // Type name of the parameter.
	StorageLocation ast_pb.StorageLocation `json:"storageLocation,omitempty"` // Storage location of the parameter.
	Visibility      ast_pb.Visibility      `json:"visibility,omitempty"`      // Visibility of the parameter.
	StateMutability ast_pb.Mutability      `json:"stateMutability,omitempty"` // State mutability of the parameter.
	Constant        bool                   `json:"constant,omitempty"`        // Whether the parameter is constant.
	StateVariable   bool                   `json:"stateVariable,omitempty"`   // Whether the parameter is a state variable.
	TypeDescription *TypeDescription       `json:"typeDescription,omitempty"` // Type description of the parameter.
	Indexed         bool                   `json:"indexed,omitempty"`         // Whether the parameter is indexed.
}

// NewParameter creates a new instance of Parameter with the provided ASTBuilder.
func NewParameter(b *ASTBuilder) *Parameter {
	return &Parameter{
		ASTBuilder:      b,
		NodeType:        ast_pb.NodeType_VARIABLE_DECLARATION,
		Visibility:      ast_pb.Visibility_INTERNAL,
		StateMutability: ast_pb.Mutability_MUTABLE,
	}
}

// SetReferenceDescriptor sets the reference descriptors of the Parameter node.
func (p *Parameter) SetReferenceDescriptor(refId int64, refDesc *TypeDescription) bool {
	return false
}

// GetId returns the unique identifier of the parameter node.
func (p *Parameter) GetId() int64 {
	return p.Id
}

// GetType returns the type of the node.
func (p *Parameter) GetType() ast_pb.NodeType {
	return p.NodeType
}

// GetSrc returns the source location information of the parameter node.
func (p *Parameter) GetSrc() SrcNode {
	return p.Src
}

// GetNameLocation returns the source location information of the name of the parameter.
func (p *Parameter) GetNameLocation() *SrcNode {
	return p.NameLocation
}

// GetName returns the name of the parameter.
func (p *Parameter) GetName() string {
	return p.Name
}

// GetScope returns the scope of the parameter.
func (p *Parameter) GetScope() int64 {
	return p.Id
}

// GetTypeDescription returns the type description of the parameter.
func (p *Parameter) GetTypeDescription() *TypeDescription {
	if p.TypeName != nil {
		return p.TypeName.TypeDescription
	}
	return p.TypeDescription
}

// GetVisibility returns the visibility of the parameter.
func (p *Parameter) GetVisibility() ast_pb.Visibility {
	return p.Visibility
}

// GetStateMutability returns the state mutability of the parameter.
func (p *Parameter) GetStateMutability() ast_pb.Mutability {
	return p.StateMutability
}

// GetStorageLocation returns the storage location of the parameter.
func (p *Parameter) GetStorageLocation() ast_pb.StorageLocation {
	return p.StorageLocation
}

// IsConstant returns whether the parameter is constant.
func (p *Parameter) IsConstant() bool {
	return p.Constant
}

// IsStateVariable returns whether the parameter is a state variable.
func (p *Parameter) IsStateVariable() bool {
	return p.StateVariable
}

// GetTypeName returns the type name of the parameter.
func (p *Parameter) GetTypeName() *TypeName {
	return p.TypeName
}

// IsIndexed returns whether the parameter is indexed.
func (p *Parameter) IsIndexed() bool {
	return p.Indexed
}

// GetNodes returns a slice of nodes associated with the parameter.
func (p *Parameter) GetNodes() []Node[NodeType] {
	toReturn := []Node[NodeType]{}

	if p.TypeName != nil {
		toReturn = append(toReturn, p.TypeName)
	}

	return toReturn
}

func (p *Parameter) UnmarshalJSON(data []byte) error {
	var tempMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &tempMap); err != nil {
		return err
	}

	if id, ok := tempMap["id"]; ok {
		if err := json.Unmarshal(id, &p.Id); err != nil {
			return err
		}
	}

	if nodeType, ok := tempMap["nodeType"]; ok {
		if err := json.Unmarshal(nodeType, &p.NodeType); err != nil {
			return err
		}
	}

	if src, ok := tempMap["src"]; ok {
		if err := json.Unmarshal(src, &p.Src); err != nil {
			return err
		}
	}

	if typeDescription, ok := tempMap["typeDescription"]; ok {
		if err := json.Unmarshal(typeDescription, &p.TypeDescription); err != nil {
			return err
		}
	}

	if nameLocation, ok := tempMap["nameLocation"]; ok {
		if err := json.Unmarshal(nameLocation, &p.NameLocation); err != nil {
			return err
		}
	}

	if scope, ok := tempMap["scope"]; ok {
		if err := json.Unmarshal(scope, &p.Scope); err != nil {
			return err
		}
	}

	if name, ok := tempMap["name"]; ok {
		if err := json.Unmarshal(name, &p.Name); err != nil {
			return err
		}
	}

	if typeName, ok := tempMap["typeName"]; ok {
		if err := json.Unmarshal(typeName, &p.TypeName); err != nil {
			return err
		}
	}

	if storageLocation, ok := tempMap["storageLocation"]; ok {
		if err := json.Unmarshal(storageLocation, &p.StorageLocation); err != nil {
			return err
		}
	}

	if visibility, ok := tempMap["visibility"]; ok {
		if err := json.Unmarshal(visibility, &p.Visibility); err != nil {
			return err
		}
	}

	if stateMutability, ok := tempMap["stateMutability"]; ok {
		if err := json.Unmarshal(stateMutability, &p.StateMutability); err != nil {
			return err
		}
	}

	if constant, ok := tempMap["constant"]; ok {
		if err := json.Unmarshal(constant, &p.Constant); err != nil {
			return err
		}
	}

	if stateVariable, ok := tempMap["stateVariable"]; ok {
		if err := json.Unmarshal(stateVariable, &p.StateVariable); err != nil {
			return err
		}
	}

	if indexed, ok := tempMap["indexed"]; ok {
		if err := json.Unmarshal(indexed, &p.Indexed); err != nil {
			return err
		}
	}

	return nil
}

// ToProto converts the Parameter node to its corresponding protobuf representation.
func (p *Parameter) ToProto() NodeType {
	toReturn := &ast_pb.Parameter{
		Id:              p.GetId(),
		Name:            p.GetName(),
		NodeType:        p.GetType(),
		Src:             p.GetSrc().ToProto(),
		Scope:           p.GetScope(),
		Constant:        p.IsConstant(),
		StateVariable:   p.IsStateVariable(),
		StateMutability: p.GetStateMutability(),
		Visibility:      p.GetVisibility(),
		StorageLocation: p.GetStorageLocation(),
		Indexed:         p.IsIndexed(),
	}

	if p.GetTypeName() != nil {
		toReturn.TypeName = p.GetTypeName().ToProto().(*ast_pb.TypeName)
	}

	if p.GetTypeDescription() != nil {
		toReturn.TypeDescription = p.GetTypeDescription().ToProto()
	}

	if p.GetNameLocation() != nil {
		toReturn.NameLocation = p.GetNameLocation().ToProto()
	}

	return toReturn
}

// Parse parses the parameter declaration context and populates the Parameter fields.
func (p *Parameter) Parse(unit *SourceUnit[Node[ast_pb.SourceUnit]], fnNode Node[NodeType], plNode Node[*ast_pb.ParameterList], ctx *parser.ParameterDeclarationContext) {
	p.Id = p.GetNextID()
	p.Src = SrcNode{
		Line:        int64(ctx.GetStart().GetLine()),
		Column:      int64(ctx.GetStart().GetColumn()),
		Start:       int64(ctx.GetStart().GetStart()),
		End:         int64(ctx.GetStop().GetStop()),
		Length:      int64(ctx.GetStop().GetStop() - ctx.GetStart().GetStart() + 1),
		ParentIndex: plNode.GetId(),
	}
	p.Scope = fnNode.GetId()

	if ctx.Identifier() != nil {
		p.Name = ctx.Identifier().GetText()
	}

	p.StorageLocation = p.getStorageLocationFromCtx(ctx)

	typeName := NewTypeName(p.ASTBuilder)
	typeName.WithParameterList(plNode)
	typeName.Parse(unit, fnNode, p.GetId(), ctx.TypeName())

	if typeName.TypeDescription != nil {
		switch typeName.TypeDescription.TypeIdentifier {
		case "t_address":
			p.StateMutability = ast_pb.Mutability_NONPAYABLE
		case "t_address_payable":
			p.StateMutability = ast_pb.Mutability_PAYABLE
		}
	}

	p.TypeName = typeName
	p.TypeDescription = typeName.GetTypeDescription()
	p.currentVariables = append(p.currentVariables, p)

	if p.TypeDescription == nil {
		if refId, refTypeDescription := p.GetResolver().ResolveByNode(typeName, typeName.Name); refTypeDescription != nil {
			typeName.ReferencedDeclaration = refId
			typeName.TypeDescription = refTypeDescription
			p.TypeDescription = typeName.GetTypeDescription()
		}
	}

	if p.Name == "" && p.TypeName != nil && p.TypeName.Name != "" {
		p.Name = p.TypeName.Name
	}

	/*	if p.Id == 4253 {
		utils.DumpNodeWithExit(p)
	}*/
}

// ParseEventParameter parses the event parameter context and populates the Parameter fields for event parameters.
func (p *Parameter) ParseEventParameter(unit *SourceUnit[Node[ast_pb.SourceUnit]], fnNode Node[NodeType], plNode Node[*ast_pb.ParameterList], ctx parser.IEventParameterContext) {
	p.Id = p.GetNextID()
	p.Src = SrcNode{
		Line:        int64(ctx.GetStart().GetLine()),
		Column:      int64(ctx.GetStart().GetColumn()),
		Start:       int64(ctx.GetStart().GetStart()),
		End:         int64(ctx.GetStop().GetStop()),
		Length:      int64(ctx.GetStop().GetStop() - ctx.GetStart().GetStart() + 1),
		ParentIndex: plNode.GetId(),
	}
	p.Scope = fnNode.GetId()
	p.Indexed = ctx.Indexed() != nil

	if ctx.Identifier() != nil {
		p.Name = ctx.Identifier().GetText()
	}

	p.StorageLocation = ast_pb.StorageLocation_MEMORY

	typeName := NewTypeName(p.ASTBuilder)
	typeName.WithParameterList(plNode)
	typeName.Parse(unit, fnNode, p.GetId(), ctx.TypeName())

	if typeName.TypeDescription != nil {
		switch typeName.TypeDescription.TypeIdentifier {
		case "t_address":
			p.StateMutability = ast_pb.Mutability_NONPAYABLE
		case "t_address_payable":
			p.StateMutability = ast_pb.Mutability_PAYABLE
		}
	}

	p.TypeName = typeName
	p.TypeDescription = typeName.GetTypeDescription()
	p.currentVariables = append(p.currentVariables, p)

	if p.TypeDescription == nil {
		if refId, refTypeDescription := p.GetResolver().ResolveByNode(typeName, typeName.Name); refTypeDescription != nil {
			typeName.ReferencedDeclaration = refId
			typeName.TypeDescription = refTypeDescription
			p.TypeDescription = typeName.GetTypeDescription()
		}
	}
}

// ParseStructParameter parses the struct parameter context and populates the Parameter fields for struct members.
func (p *Parameter) ParseStructParameter(unit *SourceUnit[Node[ast_pb.SourceUnit]], contractNode Node[NodeType], structNode *StructDefinition, ctx parser.IStructMemberContext) {
	p.Id = p.GetNextID()
	p.Src = SrcNode{
		Line:        int64(ctx.GetStart().GetLine()),
		Column:      int64(ctx.GetStart().GetColumn()),
		Start:       int64(ctx.GetStart().GetStart()),
		End:         int64(ctx.GetStop().GetStop()),
		Length:      int64(ctx.GetStop().GetStop() - ctx.GetStart().GetStart() + 1),
		ParentIndex: structNode.GetId(),
	}

	if contractNode != nil {
		p.Scope = contractNode.GetId()
	}

	if ctx.Identifier() != nil {
		p.Name = ctx.Identifier().GetText()
	}

	typeName := NewTypeName(p.ASTBuilder)
	typeName.WithParentNode(structNode)
	typeName.Parse(unit, contractNode, p.GetId(), ctx.TypeName())

	if typeName.TypeDescription != nil {
		switch typeName.TypeDescription.TypeIdentifier {
		case "t_address":
			p.StateMutability = ast_pb.Mutability_NONPAYABLE
		case "t_address_payable":
			p.StateMutability = ast_pb.Mutability_PAYABLE
		}
	}

	p.TypeName = typeName
	p.TypeDescription = typeName.GetTypeDescription()
	p.currentVariables = append(p.currentVariables, p)

	if p.TypeDescription == nil {
		if refId, refTypeDescription := p.GetResolver().ResolveByNode(typeName, typeName.Name); refTypeDescription != nil {
			typeName.ReferencedDeclaration = refId
			typeName.TypeDescription = refTypeDescription
			p.TypeDescription = typeName.GetTypeDescription()
		}
	}
}

// ParseErrorParameter parses the error parameter context and populates the Parameter fields for error definitions.
func (p *Parameter) ParseErrorParameter(unit *SourceUnit[Node[ast_pb.SourceUnit]], fnNode Node[NodeType], plNode Node[*ast_pb.ParameterList], ctx parser.IErrorParameterContext) {
	p.Id = p.GetNextID()
	p.Src = SrcNode{
		Line:        int64(ctx.GetStart().GetLine()),
		Column:      int64(ctx.GetStart().GetColumn()),
		Start:       int64(ctx.GetStart().GetStart()),
		End:         int64(ctx.GetStop().GetStop()),
		Length:      int64(ctx.GetStop().GetStop() - ctx.GetStart().GetStart() + 1),
		ParentIndex: plNode.GetId(),
	}
	p.Scope = fnNode.GetId()

	if ctx.Identifier() != nil {
		p.Name = ctx.Identifier().GetText()
	}

	p.StorageLocation = ast_pb.StorageLocation_MEMORY

	typeName := NewTypeName(p.ASTBuilder)
	typeName.WithParameterList(plNode)
	typeName.Parse(unit, fnNode, p.GetId(), ctx.TypeName())

	if typeName.TypeDescription != nil {
		switch typeName.TypeDescription.TypeIdentifier {
		case "t_address":
			p.StateMutability = ast_pb.Mutability_NONPAYABLE
		case "t_address_payable":
			p.StateMutability = ast_pb.Mutability_PAYABLE
		}
	}

	p.TypeName = typeName
	p.TypeDescription = typeName.GetTypeDescription()
	p.currentVariables = append(p.currentVariables, p)

	if p.TypeDescription == nil {
		if refId, refTypeDescription := p.GetResolver().ResolveByNode(typeName, typeName.Name); refTypeDescription != nil {
			typeName.ReferencedDeclaration = refId
			typeName.TypeDescription = refTypeDescription
			p.TypeDescription = typeName.GetTypeDescription()
		}
	}
}

// getStorageLocationFromCtx extracts the storage location information from the parameter declaration context.
func (p *Parameter) getStorageLocationFromCtx(ctx *parser.ParameterDeclarationContext) ast_pb.StorageLocation {
	storageLocationMap := map[string]ast_pb.StorageLocation{
		"memory":   ast_pb.StorageLocation_MEMORY,
		"storage":  ast_pb.StorageLocation_STORAGE,
		"calldata": ast_pb.StorageLocation_CALLDATA,
	}

	if ctx.DataLocation() != nil {
		if s, ok := storageLocationMap[ctx.DataLocation().GetText()]; ok {
			return s
		}
	}

	return ast_pb.StorageLocation_MEMORY
}
