package ast

import (
	"fmt"
	"github.com/goccy/go-json"
	ast_pb "github.com/unpackdev/protos/dist/go/ast"
	"github.com/unpackdev/solgo/parser"
)

// StructDefinition represents a struct definition in the Solidity abstract syntax tree (AST).
type StructDefinition struct {
	*ASTBuilder                                  // Embedding the ASTBuilder for common functionality
	SourceUnitName        string                 `json:"-"` // Name of the source unit
	Id                    int64                  `json:"id"` // Unique identifier for the struct definition
	NodeType              ast_pb.NodeType        `json:"nodeType"` // Type of the node (STRUCT_DEFINITION for struct definition)
	Src                   SrcNode                `json:"src"` // Source information about the struct definition
	Name                  string                 `json:"name"` // Name of the struct
	NameLocation          SrcNode                `json:"nameLocation"` // Source information about the name of the struct
	CanonicalName         string                 `json:"canonicalName"` // Canonical name of the struct
	ReferencedDeclaration int64                  `json:"referencedDeclaration,omitempty"` // Referenced declaration of the struct definition
	TypeDescription       *TypeDescription       `json:"typeDescription"` // Type description of the struct definition
	Members               []Node[NodeType]       `json:"members"` // Members of the struct definition
	Visibility            ast_pb.Visibility      `json:"visibility"` // Visibility of the struct definition
	StorageLocation       ast_pb.StorageLocation `json:"storageLocation"` // Storage location of the struct definition
}

// NewStructDefinition creates a new StructDefinition instance.
func NewStructDefinition(b *ASTBuilder) *StructDefinition {
	return &StructDefinition{
		ASTBuilder:      b,
		Id:              b.GetNextID(),
		NodeType:        ast_pb.NodeType_STRUCT_DEFINITION,
		Visibility:      ast_pb.Visibility_PUBLIC,
		StorageLocation: ast_pb.StorageLocation_DEFAULT,
	}
}

// SetReferenceDescriptor sets the reference descriptions of the StructDefinition node.
func (s *StructDefinition) SetReferenceDescriptor(refId int64, refDesc *TypeDescription) bool {
	s.ReferencedDeclaration = refId
	s.TypeDescription = refDesc
	return false
}

// GetId returns the unique identifier of the struct definition.
func (s *StructDefinition) GetId() int64 {
	return s.Id
}

// GetType returns the type of the node, which is 'STRUCT_DEFINITION' for a struct definition.
func (s *StructDefinition) GetType() ast_pb.NodeType {
	return s.NodeType
}

// GetSrc returns the source information about the struct definition.
func (s *StructDefinition) GetSrc() SrcNode {
	return s.Src
}

// GetNameLocation returns the source information about the name of the struct definition.
func (s *StructDefinition) GetNameLocation() SrcNode {
	return s.NameLocation
}

// GetName returns the name of the struct definition.
func (s *StructDefinition) GetName() string {
	return s.Name
}

// GetTypeDescription returns the type description of the struct definition.
func (s *StructDefinition) GetTypeDescription() *TypeDescription {
	return s.TypeDescription
}

// GetCanonicalName returns the canonical name of the struct definition.
func (s *StructDefinition) GetCanonicalName() string {
	return s.CanonicalName
}

// GetMembers returns the members of the struct definition.
func (s *StructDefinition) GetMembers() []*Parameter {
	toReturn := make([]*Parameter, 0)

	for _, member := range s.Members {
		if param, ok := member.(*Parameter); ok {
			toReturn = append(toReturn, param)
		}
	}
	return toReturn
}

// GetSourceUnitName returns the name of the source unit.
func (s *StructDefinition) GetSourceUnitName() string {
	return s.SourceUnitName
}

// GetVisibility returns the visibility of the struct definition.
func (s *StructDefinition) GetVisibility() ast_pb.Visibility {
	return s.Visibility
}

// GetStorageLocation returns the storage location of the struct definition.
func (s *StructDefinition) GetStorageLocation() ast_pb.StorageLocation {
	return s.StorageLocation
}

// GetNodes returns the members of the struct definition.
func (s *StructDefinition) GetNodes() []Node[NodeType] {
	return s.Members
}

// GetReferencedDeclaration returns the referenced declaration of the struct definition.
func (s *StructDefinition) GetReferencedDeclaration() int64 {
	return s.ReferencedDeclaration
}

func (s *StructDefinition) UnmarshalJSON(data []byte) error {
	var tempMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &tempMap); err != nil {
		return err
	}

	if id, ok := tempMap["id"]; ok {
		if err := json.Unmarshal(id, &s.Id); err != nil {
			return err
		}
	}

	if name, ok := tempMap["name"]; ok {
		if err := json.Unmarshal(name, &s.Name); err != nil {
			return err
		}
	}

	if canonicalName, ok := tempMap["canonicalName"]; ok {
		if err := json.Unmarshal(canonicalName, &s.CanonicalName); err != nil {
			return err
		}
	}

	if nodeType, ok := tempMap["nodeType"]; ok {
		if err := json.Unmarshal(nodeType, &s.NodeType); err != nil {
			return err
		}
	}

	if visibility, ok := tempMap["visibility"]; ok {
		if err := json.Unmarshal(visibility, &s.Visibility); err != nil {
			return err
		}
	}

	if src, ok := tempMap["src"]; ok {
		if err := json.Unmarshal(src, &s.Src); err != nil {
			return err
		}
	}

	if nameLocation, ok := tempMap["nameLocation"]; ok {
		if err := json.Unmarshal(nameLocation, &s.NameLocation); err != nil {
			return err
		}
	}

	if storageLocation, ok := tempMap["storageLocation"]; ok {
		if err := json.Unmarshal(storageLocation, &s.StorageLocation); err != nil {
			return err
		}
	}

	if referencedDeclaration, ok := tempMap["referencedDeclaration"]; ok {
		if err := json.Unmarshal(referencedDeclaration, &s.ReferencedDeclaration); err != nil {
			return err
		}
	}

	if typeDescription, ok := tempMap["typeDescription"]; ok {
		if err := json.Unmarshal(typeDescription, &s.TypeDescription); err != nil {
			return err
		}
	}

	if members, ok := tempMap["members"]; ok {
		var nodes []json.RawMessage
		if err := json.Unmarshal(members, &nodes); err != nil {
			return err
		}

		for _, tempNode := range nodes {
			var tempNodeMap map[string]json.RawMessage
			if err := json.Unmarshal(tempNode, &tempNodeMap); err != nil {
				return err
			}

			var tempNodeType ast_pb.NodeType
			if err := json.Unmarshal(tempNodeMap["nodeType"], &tempNodeType); err != nil {
				return err
			}

			node, err := unmarshalNode(tempNode, tempNodeType)
			if err != nil {
				return err
			}
			s.Members = append(s.Members, node)
		}
	}

	return nil
}

// ToProto returns the protobuf representation of the struct definition.
func (s *StructDefinition) ToProto() NodeType {
	proto := ast_pb.Struct{
		Id:                    s.GetId(),
		Name:                  s.GetName(),
		CanonicalName:         s.GetCanonicalName(),
		NodeType:              s.GetType(),
		Visibility:            s.GetVisibility(),
		StorageLocation:       s.GetStorageLocation(),
		ReferencedDeclaration: s.GetReferencedDeclaration(),
		Src:                   s.GetSrc().ToProto(),
		NameLocation:          s.GetNameLocation().ToProto(),
		Members:               make([]*ast_pb.Parameter, 0, len(s.GetMembers())),
		TypeDescription:       s.GetTypeDescription().ToProto(),
	}

	for _, member := range s.GetMembers() {
		proto.Members = append(proto.Members, member.ToProto().(*ast_pb.Parameter))
	}

	return NewTypedStruct(&proto, "Struct")
}

// Parse parses a struct definition from the provided parser.StructDefinitionContext and returns the corresponding StructDefinition.
func (s *StructDefinition) Parse(
	unit *SourceUnit[Node[ast_pb.SourceUnit]],
	contractNode Node[NodeType],
	bodyCtx parser.IContractBodyElementContext,
	ctx *parser.StructDefinitionContext,
) Node[NodeType] {
	s.Src = SrcNode{
		Line:        int64(ctx.GetStart().GetLine()),
		Column:      int64(ctx.GetStart().GetColumn()),
		Start:       int64(ctx.GetStart().GetStart()),
		End:         int64(ctx.GetStop().GetStop()),
		Length:      int64(ctx.GetStop().GetStop() - ctx.GetStart().GetStart() + 1),
		ParentIndex: unit.GetId(),
	}
	s.SourceUnitName = unit.GetName()

	s.Name = ctx.GetName().GetText()
	s.CanonicalName = fmt.Sprintf("%s.%s", s.SourceUnitName, s.Name)
	s.NameLocation = SrcNode{
		Line:        int64(ctx.GetName().GetStart().GetLine()),
		Column:      int64(ctx.GetName().GetStart().GetColumn()),
		Start:       int64(ctx.GetName().GetStart().GetStart()),
		End:         int64(ctx.GetName().GetStop().GetStop()),
		Length:      int64(ctx.GetName().GetStop().GetStop() - ctx.GetName().GetStart().GetStart() + 1),
		ParentIndex: s.GetId(),
	}

	s.TypeDescription = &TypeDescription{
		TypeIdentifier: fmt.Sprintf(
			"t_struct$_%s_%s_$%d", s.SourceUnitName, s.GetName(), s.GetId(),
		),
		TypeString: fmt.Sprintf(
			"struct %s.%s", s.SourceUnitName, s.GetName(),
		),
	}

	for _, memberCtx := range ctx.AllStructMember() {
		parameter := NewParameter(s.ASTBuilder)
		parameter.ParseStructParameter(unit, contractNode, s, memberCtx)
		s.Members = append(s.Members, parameter)
	}

	s.currentStructs = append(s.currentStructs, s)
	return s
}

// ParseGlobal parses a struct definition from the provided parser.StructDefinitionContext and returns the corresponding StructDefinition.
func (s *StructDefinition) ParseGlobal(
	ctx *parser.StructDefinitionContext,
) Node[NodeType] {
	s.Src = SrcNode{
		Line:        int64(ctx.GetStart().GetLine()),
		Column:      int64(ctx.GetStart().GetColumn()),
		Start:       int64(ctx.GetStart().GetStart()),
		End:         int64(ctx.GetStop().GetStop()),
		Length:      int64(ctx.GetStop().GetStop() - ctx.GetStart().GetStart() + 1),
		ParentIndex: 0,
	}
	s.SourceUnitName = "Global"

	s.Name = ctx.GetName().GetText()
	s.CanonicalName = fmt.Sprintf("%s.%s", s.SourceUnitName, s.Name)
	s.NameLocation = SrcNode{
		Line:        int64(ctx.GetName().GetStart().GetLine()),
		Column:      int64(ctx.GetName().GetStart().GetColumn()),
		Start:       int64(ctx.GetName().GetStart().GetStart()),
		End:         int64(ctx.GetName().GetStop().GetStop()),
		Length:      int64(ctx.GetName().GetStop().GetStop() - ctx.GetName().GetStart().GetStart() + 1),
		ParentIndex: s.GetId(),
	}

	s.TypeDescription = &TypeDescription{
		TypeIdentifier: fmt.Sprintf(
			"t_struct$_%s_%s_$%d", s.SourceUnitName, s.GetName(), s.GetId(),
		),
		TypeString: fmt.Sprintf(
			"struct %s.%s", s.SourceUnitName, s.GetName(),
		),
	}

	for _, memberCtx := range ctx.AllStructMember() {
		parameter := NewParameter(s.ASTBuilder)
		parameter.ParseStructParameter(nil, nil, s, memberCtx)
		s.Members = append(s.Members, parameter)
	}

	s.globalDefinitions = append(s.globalDefinitions, s)
	return s
}

func (b *ASTBuilder) EnterStructDefinition(ctx *parser.StructDefinitionContext) {
	s := NewStructDefinition(b)
	s.ParseGlobal(ctx)
}
