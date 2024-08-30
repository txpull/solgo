package ast

import (
	"fmt"
	"github.com/goccy/go-json"
	"strings"

	"github.com/antlr4-go/antlr/v4"
	v3 "github.com/cncf/xds/go/xds/type/v3"
	ast_pb "github.com/unpackdev/protos/dist/go/ast"
	"github.com/unpackdev/solgo/parser"
)

// TypeName represents a type name used in Solidity code.
type TypeName struct {
	*ASTBuilder

	Id                    int64             `json:"id"`
	NodeType              ast_pb.NodeType   `json:"nodeType"`
	Src                   SrcNode           `json:"src"`
	Name                  string            `json:"name,omitempty"`
	KeyType               *TypeName         `json:"keyType,omitempty"`
	KeyNameLocation       *SrcNode          `json:"keyNameLocation,omitempty"`
	ValueType             *TypeName         `json:"valueType,omitempty"`
	ValueNameLocation     *SrcNode          `json:"valueNameLocation,omitempty"`
	PathNode              *PathNode         `json:"pathNode,omitempty"`
	StateMutability       ast_pb.Mutability `json:"stateMutability,omitempty"`
	ReferencedDeclaration int64             `json:"referencedDeclaration"`
	Expression            Node[NodeType]    `json:"expression,omitempty"`
	TypeDescription       *TypeDescription  `json:"typeDescription,omitempty"`

	// Helper parents so we can efficiently extract references if needed without
	// having to traverse whole AST.
	ParentNode          []Node[NodeType]            `json:"-"`
	ParentBody          *BodyNode                   `json:"-"`
	ParentParameterList Node[*ast_pb.ParameterList] `json:"-"`
}

// NewTypeName creates a new TypeName instance with the given ASTBuilder.
func NewTypeName(b *ASTBuilder) *TypeName {
	return &TypeName{
		ASTBuilder: b,
		Id:         b.GetNextID(),
		ParentNode: make([]Node[NodeType], 0),
	}
}

// WithBodyNode sets the body node associated with TypeName.
func (t *TypeName) WithBodyNode(b *BodyNode) {
	t.ParentBody = b
}

// WithParameterList sets the parameter list associated with TypeName.
func (t *TypeName) WithParameterList(p Node[*ast_pb.ParameterList]) {
	t.ParentParameterList = p
}

// WithParentNode sets the parent node associated with TypeName.
func (t *TypeName) WithParentNode(p Node[NodeType]) {
	t.ParentNode = append(t.ParentNode, p)
}

// SetReferenceDescriptor sets the reference descriptions of the TypeName node.
func (t *TypeName) SetReferenceDescriptor(refId int64, refDesc *TypeDescription) bool {
	if t.TypeDescription != nil {
		return true
	}

	t.ReferencedDeclaration = refId
	t.TypeDescription = refDesc

	// Well this is a mother-fiasco...
	// This whole TypeName needs to be revisited in the future entirely...
	// Prototype that's now used on production...
	if strings.HasSuffix(t.Name, "[]") && refDesc != nil {
		if !strings.HasSuffix(refDesc.TypeString, "[]") {
			t.TypeDescription.TypeString += "[]"
			return true
		}
	}

	return true
}

// GetId returns the unique identifier of the TypeName.
func (t *TypeName) GetId() int64 {
	return t.Id
}

// GetType returns the node type of the TypeName.
func (t *TypeName) GetType() ast_pb.NodeType {
	return t.NodeType
}

// GetSrc returns the source location information of the TypeName.
func (t *TypeName) GetSrc() SrcNode {
	return t.Src
}

// GetKeyNameLocation returns the key name location of the KeyTypeName.
func (t *TypeName) GetKeyNameLocation() *SrcNode {
	return t.KeyNameLocation
}

// GetValueNameLocation returns the value name location of the ValueTypeName.
func (t *TypeName) GetValueNameLocation() *SrcNode {
	return t.ValueNameLocation
}

// GetName returns the name of the type.
func (t *TypeName) GetName() string {
	return t.Name
}

// GetTypeDescription returns the type description associated with the TypeName.
func (t *TypeName) GetTypeDescription() *TypeDescription {
	return t.TypeDescription
}

// GetPathNode returns the path node associated with the TypeName.
func (t *TypeName) GetPathNode() *PathNode {
	return t.PathNode
}

// GetReferencedDeclaration returns the referenced declaration of the TypeName.
func (t *TypeName) GetReferencedDeclaration() int64 {
	return t.ReferencedDeclaration
}

// GetKeyType returns the key type for mapping types.
func (t *TypeName) GetKeyType() *TypeName {
	return t.KeyType
}

// GetValueType returns the value type for mapping types.
func (t *TypeName) GetValueType() *TypeName {
	return t.ValueType
}

// GetExpression returns the expression associated with the TypeName.
func (t *TypeName) GetExpression() Node[NodeType] {
	return t.Expression
}

// GetStateMutability returns the state mutability of the TypeName.
func (t *TypeName) GetStateMutability() ast_pb.Mutability {
	return t.StateMutability
}

// GetNodes returns a list of child nodes for traversal within the TypeName.
func (t *TypeName) GetNodes() []Node[NodeType] {
	toReturn := []Node[NodeType]{}

	if t.KeyType != nil {
		toReturn = append(toReturn, t.KeyType)
	}

	if t.ValueType != nil {
		toReturn = append(toReturn, t.ValueType)
	}

	if t.PathNode != nil {
		toReturn = append(toReturn, t.PathNode)
	}

	if t.Expression != nil {
		toReturn = append(toReturn, t.Expression)
	}

	return toReturn
}

func (t *TypeName) UnmarshalJSON(data []byte) error {
	var tempMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &tempMap); err != nil {
		return err
	}

	if id, ok := tempMap["id"]; ok {
		if err := json.Unmarshal(id, &t.Id); err != nil {
			return err
		}
	}

	if nodeType, ok := tempMap["nodeType"]; ok {
		if err := json.Unmarshal(nodeType, &t.NodeType); err != nil {
			return err
		}
	}

	if src, ok := tempMap["src"]; ok {
		if err := json.Unmarshal(src, &t.Src); err != nil {
			return err
		}
	}

	if referencedDeclaration, ok := tempMap["referencedDeclaration"]; ok {
		if err := json.Unmarshal(referencedDeclaration, &t.ReferencedDeclaration); err != nil {
			return err
		}
	}

	if typeDescription, ok := tempMap["typeDescription"]; ok {
		if err := json.Unmarshal(typeDescription, &t.TypeDescription); err != nil {
			return err
		}
	}

	if name, ok := tempMap["name"]; ok {
		if err := json.Unmarshal(name, &t.Name); err != nil {
			return err
		}
	}

	if keyType, ok := tempMap["keyType"]; ok {
		if err := json.Unmarshal(keyType, &t.KeyType); err != nil {
			return err
		}
	}

	if keyNameLocation, ok := tempMap["keyNameLocation"]; ok {
		if err := json.Unmarshal(keyNameLocation, &t.KeyNameLocation); err != nil {
			return err
		}
	}

	if valueType, ok := tempMap["valueType"]; ok {
		if err := json.Unmarshal(valueType, &t.ValueType); err != nil {
			return err
		}
	}

	if valueNameLocation, ok := tempMap["valueNameLocation"]; ok {
		if err := json.Unmarshal(valueNameLocation, &t.ValueNameLocation); err != nil {
			return err
		}
	}

	if pathNode, ok := tempMap["pathNode"]; ok {
		if err := json.Unmarshal(pathNode, &t.PathNode); err != nil {
			return err
		}
	}

	if stateMutability, ok := tempMap["stateMutability"]; ok {
		if err := json.Unmarshal(stateMutability, &t.StateMutability); err != nil {
			return err
		}
	}

	if expression, ok := tempMap["expression"]; ok {
		if err := json.Unmarshal(expression, &t.Expression); err != nil {
			var tempNodeMap map[string]json.RawMessage
			if err := json.Unmarshal(expression, &tempNodeMap); err != nil {
				return err
			}

			var tempNodeType ast_pb.NodeType
			if err := json.Unmarshal(tempNodeMap["nodeType"], &tempNodeType); err != nil {
				return err
			}

			node, err := unmarshalNode(expression, tempNodeType)
			if err != nil {
				return err
			}
			t.Expression = node
		}
	}

	return nil
}

// ToProto converts the TypeName instance to its corresponding protocol buffer representation.
func (t *TypeName) ToProto() NodeType {
	toReturn := &ast_pb.TypeName{
		Id:                    t.GetId(),
		Name:                  t.GetName(),
		NodeType:              t.GetType(),
		Src:                   t.GetSrc().ToProto(),
		ReferencedDeclaration: t.ReferencedDeclaration,
		StateMutability:       t.StateMutability,
	}

	// In case it's nil, we'll do our best to resolve it later on in
	// the final resolver pass.
	// This usually means that contract A is not yet processed while
	// contract B is referencing it.
	if t.GetTypeDescription() != nil {
		toReturn.TypeDescription = t.GetTypeDescription().ToProto()
	}

	if t.GetPathNode() != nil {
		toReturn.PathNode = t.GetPathNode().ToProto().(*ast_pb.PathNode)
	}

	if t.GetKeyType() != nil {
		toReturn.KeyType = t.GetKeyType().ToProto().(*ast_pb.TypeName)
		if t.GetKeyNameLocation() != nil {
			toReturn.KeyTypeLocation = t.GetKeyNameLocation().ToProto()
		}
	}

	if t.GetValueType() != nil {
		toReturn.ValueType = t.GetValueType().ToProto().(*ast_pb.TypeName)
		if t.GetValueNameLocation() != nil {
			toReturn.ValueTypeLocation = t.GetValueNameLocation().ToProto()
		}
	}

	if t.GetExpression() != nil {
		toReturn.Expression = t.GetExpression().ToProto().(*v3.TypedStruct)
	}

	return toReturn
}

// parseTypeName parses the TypeName from the given TypeNameContext.
func (t *TypeName) parseTypeName(unit *SourceUnit[Node[ast_pb.SourceUnit]], parentNodeId int64, ctx *parser.TypeNameContext) {
	t.Name = ctx.GetText()
	t.Src = SrcNode{
		Line:        int64(ctx.GetStart().GetLine()),
		Column:      int64(ctx.GetStart().GetColumn()),
		Start:       int64(ctx.GetStart().GetStart()),
		End:         int64(ctx.GetStop().GetStop()),
		Length:      int64(ctx.GetStop().GetStop() - ctx.GetStart().GetStart() + 1),
		ParentIndex: parentNodeId,
	}

	if t.GetType() == ast_pb.NodeType_NT_DEFAULT {
		t.NodeType = ast_pb.NodeType_IDENTIFIER
	}

	if ctx.ElementaryTypeName() != nil {
		normalizedTypeName, normalizedTypeIdentifier := normalizeTypeDescription(
			ctx.ElementaryTypeName().GetText(),
		)

		t.TypeDescription = &TypeDescription{
			TypeString:     normalizedTypeName,
			TypeIdentifier: normalizedTypeIdentifier,
		}
	} else if ctx.MappingType() != nil {
		t.NodeType = ast_pb.NodeType_MAPPING_TYPE_NAME
		t.generateTypeName(unit, ctx.MappingType(), t, t)
	} else if ctx.FunctionTypeName() != nil {
		t.parseFunctionTypeName(unit, parentNodeId, ctx.FunctionTypeName().(*parser.FunctionTypeNameContext))
	} else if ctx.Expression() != nil {
		expression := NewExpression(t.ASTBuilder)
		t.Expression = expression.Parse(unit, nil, nil, nil, nil, nil, parentNodeId, ctx.Expression())
		t.TypeDescription = t.Expression.GetTypeDescription()
	} else if ctx.IdentifierPath() != nil {
		pathCtx := ctx.IdentifierPath()

		if strings.Contains(pathCtx.GetText(), ".") {
			identifierParts := strings.Split(pathCtx.GetText(), ".")
			if len(identifierParts) > 1 {
				t.Name = identifierParts[len(identifierParts)-1]
			}
		}

		// It seems to be a user-defined type but that does not exist as a type in the parser...
		t.NodeType = ast_pb.NodeType_USER_DEFINED_PATH_NAME

		t.PathNode = &PathNode{
			Id:   t.GetNextID(),
			Name: pathCtx.GetText(),
			Src: SrcNode{
				Line:        int64(pathCtx.GetStart().GetLine()),
				Column:      int64(pathCtx.GetStart().GetColumn()),
				Start:       int64(pathCtx.GetStart().GetStart()),
				End:         int64(pathCtx.GetStop().GetStop()),
				Length:      int64(pathCtx.GetStop().GetStop() - pathCtx.GetStart().GetStart() + 1),
				ParentIndex: t.GetId(),
			},
			NodeType: ast_pb.NodeType_IDENTIFIER_PATH,
		}

		normalizedTypeName, normalizedTypeIdentifier, found := normalizeTypeDescriptionWithStatus(
			t.Name,
		)

		switch normalizedTypeIdentifier {
		case "t_address":
			t.StateMutability = ast_pb.Mutability_NONPAYABLE
		case "t_address_payable":
			t.StateMutability = ast_pb.Mutability_PAYABLE
		}

		if found {
			t.PathNode.TypeDescription = &TypeDescription{
				TypeIdentifier: normalizedTypeIdentifier,
				TypeString:     normalizedTypeName,
			}
		} else {
			if refId, refTypeDescription := t.GetResolver().ResolveByNode(t, t.Name); refTypeDescription != nil {
				if t.PathNode != nil {
					t.PathNode.ReferencedDeclaration = refId
				}
				t.ReferencedDeclaration = refId
				t.TypeDescription = refTypeDescription
			}
		}

		// Alright lets now figure out main type description as it can be different such as
		// PathNode vs PathNode[]
		if refId, refTypeDescription := t.GetResolver().ResolveByNode(t, t.Name); refTypeDescription != nil {
			t.ReferencedDeclaration = refId
			t.TypeDescription = refTypeDescription
		}

	} else if ctx.TypeName() != nil {
		t.generateTypeName(unit, ctx.TypeName(), t, t)
	} else {
		normalizedTypeName, normalizedTypeIdentifier, found := normalizeTypeDescriptionWithStatus(
			t.Name,
		)

		switch normalizedTypeIdentifier {
		case "t_address":
			t.StateMutability = ast_pb.Mutability_NONPAYABLE
		case "t_address_payable":
			t.StateMutability = ast_pb.Mutability_PAYABLE
		}

		if found {
			if len(normalizedTypeName) > 0 {
				t.TypeDescription = &TypeDescription{
					TypeIdentifier: normalizedTypeIdentifier,
					TypeString:     normalizedTypeName,
				}
			} else {
				if refId, refTypeDescription := t.GetResolver().ResolveByNode(t, t.Name); refTypeDescription != nil {
					if t.PathNode != nil {
						t.PathNode.ReferencedDeclaration = refId
					}
					t.ReferencedDeclaration = refId
					t.TypeDescription = refTypeDescription
				}
			}
		} else {
			if refId, refTypeDescription := t.GetResolver().ResolveByNode(t, t.Name); refTypeDescription != nil {
				if t.PathNode != nil {
					t.PathNode.ReferencedDeclaration = refId
				}
				t.ReferencedDeclaration = refId
				t.TypeDescription = refTypeDescription
			}
		}
	}
}

// parseElementaryTypeName parses the ElementaryTypeName from the given ElementaryTypeNameContext.
func (t *TypeName) parseElementaryTypeName(unit *SourceUnit[Node[ast_pb.SourceUnit]], parentNodeId int64, ctx *parser.ElementaryTypeNameContext) {
	t.Name = ctx.GetText()
	t.NodeType = ast_pb.NodeType_ELEMENTARY_TYPE_NAME

	normalizedTypeName, normalizedTypeIdentifier, found := normalizeTypeDescriptionWithStatus(
		ctx.GetText(),
	)

	switch normalizedTypeIdentifier {
	case "t_address":
		t.StateMutability = ast_pb.Mutability_NONPAYABLE
	case "t_address_payable":
		t.StateMutability = ast_pb.Mutability_PAYABLE
	}

	if found {
		t.TypeDescription = &TypeDescription{
			TypeIdentifier: normalizedTypeIdentifier,
			TypeString:     normalizedTypeName,
		}
	} else {
		if refId, refTypeDescription := t.GetResolver().ResolveByNode(t, t.Name); refTypeDescription != nil {
			if t.PathNode != nil {
				t.PathNode.ReferencedDeclaration = refId
			}
			t.ReferencedDeclaration = refId
			t.TypeDescription = refTypeDescription
		}
	}
}

// parseIdentifierPath parses the IdentifierPath from the given IdentifierPathContext.
func (t *TypeName) parseIdentifierPath(unit *SourceUnit[Node[ast_pb.SourceUnit]], parentNodeId int64, ctx *parser.IdentifierPathContext) {
	t.NodeType = ast_pb.NodeType_USER_DEFINED_PATH_NAME

	if len(ctx.AllIdentifier()) > 0 {
		identifierCtx := ctx.Identifier(0)
		t.PathNode = &PathNode{
			Id: t.GetNextID(),
			Name: func() string {
				if len(ctx.AllIdentifier()) == 1 {
					if t.Name == "" {
						t.Name = identifierCtx.GetText()
					}
					return identifierCtx.GetText()
				} else if len(ctx.AllIdentifier()) == 2 {
					if t.Name == "" {
						t.Name = identifierCtx.GetText()
					}
					return ctx.Identifier(1).GetText()
				}
				return ""
			}(),
			Src: SrcNode{
				Line:        int64(ctx.GetStart().GetLine()),
				Column:      int64(ctx.GetStart().GetColumn()),
				Start:       int64(ctx.GetStart().GetStart()),
				End:         int64(ctx.GetStop().GetStop()),
				Length:      int64(ctx.GetStop().GetStop() - ctx.GetStart().GetStart() + 1),
				ParentIndex: t.Id,
			},
			NameLocation: &SrcNode{
				Line:        int64(identifierCtx.GetStart().GetLine()),
				Column:      int64(identifierCtx.GetStart().GetColumn()),
				Start:       int64(identifierCtx.GetStart().GetStart()),
				End:         int64(identifierCtx.GetStop().GetStop()),
				Length:      int64(identifierCtx.GetStop().GetStop() - identifierCtx.GetStart().GetStart() + 1),
				ParentIndex: t.Id,
			},
			NodeType: ast_pb.NodeType_IDENTIFIER_PATH,
		}

		normalizedTypeName, normalizedTypeIdentifier, found := normalizeTypeDescriptionWithStatus(
			identifierCtx.GetText(),
		)

		switch normalizedTypeIdentifier {
		case "t_address":
			t.StateMutability = ast_pb.Mutability_NONPAYABLE
		case "t_address_payable":
			t.StateMutability = ast_pb.Mutability_PAYABLE
		}

		if found {
			t.PathNode.TypeDescription = &TypeDescription{
				TypeIdentifier: normalizedTypeIdentifier,
				TypeString:     normalizedTypeName,
			}
		} else {
			if len(ctx.AllIdentifier()) == 2 {
				if refId, refTypeDescription := t.GetResolver().ResolveByNode(t.PathNode, ctx.Identifier(1).GetText()); refTypeDescription != nil {
					t.PathNode.ReferencedDeclaration = refId
					t.PathNode.TypeDescription = refTypeDescription
				}
			} else {
				if refId, refTypeDescription := t.GetResolver().ResolveByNode(t.PathNode, identifierCtx.GetText()); refTypeDescription != nil {
					t.PathNode.ReferencedDeclaration = refId
					t.PathNode.TypeDescription = refTypeDescription
				}
			}
		}

		// There can be messages that are basically special...
		if strings.Contains(ctx.GetText(), "msg.") {
			t.TypeDescription = &TypeDescription{
				TypeIdentifier: "t_magic_message",
				TypeString:     "msg",
			}
		}

		if strings.Contains(ctx.GetText(), "block.") {
			t.TypeDescription = &TypeDescription{
				TypeIdentifier: "t_magic_block",
				TypeString:     "block",
			}
		}

		if strings.Contains(ctx.GetText(), "abi") {
			t.TypeDescription = &TypeDescription{
				TypeIdentifier: "t_magic_abi",
				TypeString:     "abi",
			}
		}

		// For now just like this but in the future we should look into figuring out which contract
		// is being referenced here...
		// We would need to search for function declarations and match them accordingly...
		if strings.Contains(ctx.GetText(), "super") {
			t.TypeDescription = &TypeDescription{
				TypeIdentifier: "t_magic_super",
				TypeString:     "super",
			}
		}

		// This is a magic this type and should be treated by setting type description to the contract type
		if strings.Contains(ctx.GetText(), "this") {
			if unit == nil {
				t.TypeDescription = &TypeDescription{
					TypeIdentifier: "t_magic_this",
					TypeString:     "this",
				}
			} else {
				t.TypeDescription = unit.GetTypeDescription()
			}
		}

		if ctx.GetText() == "now" {
			t.TypeDescription = &TypeDescription{
				TypeIdentifier: "t_magic_now",
				TypeString:     "now",
			}
		}

		if strings.Contains(ctx.GetText(), "tx.") {
			t.TypeDescription = &TypeDescription{
				TypeIdentifier: "t_magic_transaction",
				TypeString:     "tx",
			}
		}

		if ctx.GetText() == "origin" {
			t.TypeDescription = &TypeDescription{
				TypeIdentifier: "t_address",
				TypeString:     "address",
			}
		}

		if t.TypeDescription == nil {
			bNormalizedTypeName, bNormalizedTypeIdentifier, bFound := normalizeTypeDescriptionWithStatus(
				identifierCtx.GetText(),
			)

			// Alright lets now figure out main type description as it can be different such as
			// PathNode vs PathNode[]
			if bFound {
				t.TypeDescription = &TypeDescription{
					TypeIdentifier: bNormalizedTypeIdentifier,
					TypeString:     bNormalizedTypeName,
				}
			} else {
				if refId, refTypeDescription := t.GetResolver().ResolveByNode(t, t.Name); refTypeDescription != nil {
					t.ReferencedDeclaration = refId
					t.TypeDescription = refTypeDescription
				}
			}
		}

		/*		if t.Id == 2404 {
				fmt.Println(ctx.GetText())
				utils.DumpNodeWithExit(t)
			}*/
	}

}

// parseMappingTypeName parses the MappingTypeName from the given MappingTypeContext.
func (t *TypeName) parseMappingTypeName(unit *SourceUnit[Node[ast_pb.SourceUnit]], parentNodeId int64, ctx *parser.MappingTypeContext) {
	keyCtx := ctx.GetKey()
	valueCtx := ctx.GetValue()
	t.NodeType = ast_pb.NodeType_MAPPING_TYPE_NAME

	t.KeyType = t.generateTypeName(unit, keyCtx, t, t)
	if keyCtx.GetStart().GetLine() > 0 {
		t.KeyNameLocation = &SrcNode{
			Line:        int64(keyCtx.GetStart().GetLine()),
			Column:      int64(keyCtx.GetStart().GetColumn()),
			Start:       int64(keyCtx.GetStart().GetStart()),
			End:         int64(keyCtx.GetStop().GetStop()),
			Length:      int64(keyCtx.GetStop().GetStop() - keyCtx.GetStart().GetStart() + 1),
			ParentIndex: t.GetId(),
		}
	}

	t.ValueType = t.generateTypeName(unit, valueCtx, t, t)
	if valueCtx.GetStart().GetLine() > 0 {
		t.ValueNameLocation = &SrcNode{
			Line:        int64(valueCtx.GetStart().GetLine()),
			Column:      int64(valueCtx.GetStart().GetColumn()),
			Start:       int64(valueCtx.GetStart().GetStart()),
			End:         int64(valueCtx.GetStop().GetStop()),
			Length:      int64(valueCtx.GetStop().GetStop() - valueCtx.GetStart().GetStart() + 1),
			ParentIndex: t.GetId(),
		}
	}

	if t.KeyType.TypeDescription == nil {
		if refId, refTypeDescription := t.GetResolver().ResolveByNode(t.KeyType, t.KeyType.Name); refTypeDescription != nil {
			t.KeyType.ReferencedDeclaration = refId
			t.KeyType.TypeDescription = refTypeDescription
		} else {
			t.KeyType.TypeDescription = &TypeDescription{
				TypeString:     fmt.Sprintf("unknown_%d", t.KeyType.GetId()),
				TypeIdentifier: fmt.Sprintf("t_unknown_%d", t.KeyType.GetId()),
			}
		}
	}

	if t.ValueType.TypeDescription == nil {
		if refId, refTypeDescription := t.GetResolver().ResolveByNode(t.ValueType, t.ValueType.Name); refTypeDescription != nil {
			t.ValueType.ReferencedDeclaration = refId
			t.ValueType.TypeDescription = refTypeDescription
		} else {
			t.ValueType.TypeDescription = &TypeDescription{
				TypeString:     fmt.Sprintf("unknown_%d", t.ValueType.GetId()),
				TypeIdentifier: fmt.Sprintf("t_unknown_%d", t.ValueType.GetId()),
			}
		}
	}

	t.TypeDescription = &TypeDescription{
		TypeString: fmt.Sprintf("mapping(%s=>%s)", t.KeyType.Name, t.ValueType.Name),
		TypeIdentifier: fmt.Sprintf(
			"t_mapping_$%s_$%s$",
			t.KeyType.TypeDescription.TypeIdentifier,
			t.ValueType.TypeDescription.TypeIdentifier,
		),
	}
}

// generateTypeName generates the TypeName based on the given context.
func (t *TypeName) generateTypeName(sourceUnit *SourceUnit[Node[ast_pb.SourceUnit]], ctx any, parentNode *TypeName, typeNameNode *TypeName) *TypeName {
	typeName := &TypeName{
		ASTBuilder: t.ASTBuilder,
		Id:         t.GetId(),
		NodeType:   ast_pb.NodeType_ELEMENTARY_TYPE_NAME,
	}

	t.NodeType = ast_pb.NodeType_ELEMENTARY_TYPE_NAME

	switch specificCtx := ctx.(type) {
	case parser.IMappingKeyTypeContext:
		typeName.Name = specificCtx.GetText()
		typeName.Src = SrcNode{
			Line:        int64(specificCtx.GetStart().GetLine()),
			Column:      int64(specificCtx.GetStart().GetColumn()),
			Start:       int64(specificCtx.GetStart().GetStart()),
			End:         int64(specificCtx.GetStop().GetStop()),
			Length:      int64(specificCtx.GetStop().GetStop() - specificCtx.GetStart().GetStart() + 1),
			ParentIndex: parentNode.GetId(),
		}

		if specificCtx.ElementaryTypeName() != nil {
			normalizedTypeName, normalizedTypeIdentifier := normalizeTypeDescription(
				specificCtx.ElementaryTypeName().GetText(),
			)

			typeName.TypeDescription = &TypeDescription{
				TypeString:     normalizedTypeName,
				TypeIdentifier: normalizedTypeIdentifier,
			}
		}

	case parser.IMappingTypeContext:
		typeNameNode.NodeType = ast_pb.NodeType_MAPPING_TYPE_NAME
		keyCtx := specificCtx.GetKey()
		valueCtx := specificCtx.GetValue()
		typeNameNode.KeyType = t.generateTypeName(sourceUnit, keyCtx, parentNode, typeNameNode)
		typeNameNode.ValueType = t.generateTypeName(sourceUnit, valueCtx, parentNode, typeNameNode)

		if keyCtx.GetStart().GetLine() > 0 {
			typeNameNode.KeyNameLocation = &SrcNode{
				Line:        int64(keyCtx.GetStart().GetLine()),
				Column:      int64(keyCtx.GetStart().GetColumn()),
				Start:       int64(keyCtx.GetStart().GetStart()),
				End:         int64(keyCtx.GetStop().GetStop()),
				Length:      int64(keyCtx.GetStop().GetStop() - keyCtx.GetStart().GetStart() + 1),
				ParentIndex: typeNameNode.GetId(),
			}
		}

		if valueCtx.GetStart().GetLine() > 0 {
			typeNameNode.ValueNameLocation = &SrcNode{
				Line:        int64(valueCtx.GetStart().GetLine()),
				Column:      int64(valueCtx.GetStart().GetColumn()),
				Start:       int64(valueCtx.GetStart().GetStart()),
				End:         int64(valueCtx.GetStop().GetStop()),
				Length:      int64(valueCtx.GetStop().GetStop() - valueCtx.GetStart().GetStart() + 1),
				ParentIndex: typeNameNode.GetId(),
			}
		}

		var keyTypeDescriptionName string
		var valueTypeDescriptionName string

		if typeNameNode.KeyType.TypeDescription == nil {
			keyTypeDescriptionName = fmt.Sprintf("unknown_%d", typeNameNode.KeyType.GetId())
		} else {
			keyTypeDescriptionName = typeNameNode.KeyType.TypeDescription.TypeIdentifier
		}

		if typeNameNode.ValueType.TypeDescription == nil {
			valueTypeDescriptionName = fmt.Sprintf("unknown_%d", typeNameNode.ValueType.GetId())
		} else {
			valueTypeDescriptionName = typeNameNode.ValueType.TypeDescription.TypeIdentifier
		}

		typeNameNode.TypeDescription = &TypeDescription{
			TypeString:     fmt.Sprintf("mapping(%s=>%s)", typeNameNode.KeyType.Name, typeNameNode.ValueType.Name),
			TypeIdentifier: fmt.Sprintf("t_mapping_$%s_$%s", keyTypeDescriptionName, valueTypeDescriptionName),
		}
		parentNode.TypeDescription = t.TypeDescription
		typeName = typeNameNode

	case parser.ITypeNameContext:
		typeName.Name = specificCtx.GetText()
		typeName.Src = SrcNode{
			Line:        int64(specificCtx.GetStart().GetLine()),
			Column:      int64(specificCtx.GetStart().GetColumn()),
			Start:       int64(specificCtx.GetStart().GetStart()),
			End:         int64(specificCtx.GetStop().GetStop()),
			Length:      int64(specificCtx.GetStop().GetStop() - specificCtx.GetStart().GetStart() + 1),
			ParentIndex: parentNode.GetId(),
		}

		if specificCtx.ElementaryTypeName() != nil {
			normalizedTypeName, normalizedTypeIdentifier := normalizeTypeDescription(
				specificCtx.ElementaryTypeName().GetText(),
			)

			typeName.TypeDescription = &TypeDescription{
				TypeString:     normalizedTypeName,
				TypeIdentifier: normalizedTypeIdentifier,
			}
		} else if specificCtx.MappingType() != nil {
			typeName.NodeType = ast_pb.NodeType_MAPPING_TYPE_NAME
			t.generateTypeName(sourceUnit, specificCtx.MappingType(), parentNode, typeName)
		} else if specificCtx.FunctionTypeName() != nil {
			t.parseFunctionTypeName(sourceUnit, parentNode.GetId(), specificCtx.FunctionTypeName().(*parser.FunctionTypeNameContext))
		} else if specificCtx.IdentifierPath() != nil {
			typeName.NodeType = ast_pb.NodeType_USER_DEFINED_PATH_NAME
			t.parseIdentifierPath(sourceUnit, parentNode.GetId(), specificCtx.IdentifierPath().(*parser.IdentifierPathContext))

		} else {
			normalizedTypeName, normalizedTypeIdentifier := normalizeTypeDescription(
				typeName.Name,
			)

			typeName.TypeDescription = &TypeDescription{
				TypeString:     normalizedTypeName,
				TypeIdentifier: normalizedTypeIdentifier,
			}
		}

	}

	// We're still not able to discover reference, so what we're going to do now is look for the references...
	if typeName.TypeDescription == nil {
		if refId, refTypeDescription := t.GetResolver().ResolveByNode(typeName, typeName.Name); refTypeDescription != nil {
			typeName.ReferencedDeclaration = refId
			typeName.TypeDescription = refTypeDescription
		}
	}

	return typeName
}

// parseFunctionTypeName parses the ElementaryTypeName from the given ElementaryTypeNameContext.
func (t *TypeName) parseFunctionTypeName(unit *SourceUnit[Node[ast_pb.SourceUnit]], parentNodeId int64, ctx *parser.FunctionTypeNameContext) {
	t.Name = "function"
	t.NodeType = ast_pb.NodeType_FUNCTION_TYPE_NAME
	statement := NewFunction(t.ASTBuilder)
	t.Expression = statement.ParseTypeName(unit, parentNodeId, ctx)
	t.TypeDescription = t.Expression.GetTypeDescription()
}

func (t *TypeName) parsePrimaryExpression(unit *SourceUnit[Node[ast_pb.SourceUnit]], fnNode Node[NodeType], parentNodeId int64, ctx *parser.PrimaryExpressionContext) {
	t.Name = "function"
	t.NodeType = ast_pb.NodeType_IDENTIFIER
	statement := NewPrimaryExpression(t.ASTBuilder)
	t.Expression = statement.Parse(unit, nil, fnNode, nil, nil, nil, parentNodeId, ctx)
	t.TypeDescription = t.Expression.GetTypeDescription()
}

// Parse parses the TypeName from the given TypeNameContext.
func (t *TypeName) Parse(unit *SourceUnit[Node[ast_pb.SourceUnit]], fnNode Node[NodeType], parentNodeId int64, ctx parser.ITypeNameContext) {
	t.Src = SrcNode{
		Line:        int64(ctx.GetStart().GetLine()),
		Column:      int64(ctx.GetStart().GetColumn()),
		Start:       int64(ctx.GetStart().GetStart()),
		End:         int64(ctx.GetStop().GetStop()),
		Length:      int64(ctx.GetStop().GetStop() - ctx.GetStart().GetStart() + 1),
		ParentIndex: parentNodeId,
	}

	for _, child := range ctx.GetChildren() {
		switch childCtx := child.(type) {
		case *parser.ElementaryTypeNameContext:
			t.parseElementaryTypeName(unit, parentNodeId, childCtx)
		case *parser.MappingTypeContext:
			t.parseMappingTypeName(unit, parentNodeId, childCtx)
		case *parser.IdentifierPathContext:
			t.parseIdentifierPath(unit, parentNodeId, childCtx)
		case *parser.TypeNameContext:
			// We cannot pass only the child as it may be broken to the core...
			// For example for address[] if we pass childCtx, we are going to get address only!
			t.parseTypeName(unit, parentNodeId, ctx.(*parser.TypeNameContext))
		case *parser.FunctionTypeNameContext:
			t.parseFunctionTypeName(unit, parentNodeId, childCtx)
		case *parser.PrimaryExpressionContext:
			t.parsePrimaryExpression(unit, fnNode, parentNodeId, childCtx)
		case *antlr.TerminalNodeImpl:
			continue
		default:

			expression := NewExpression(t.ASTBuilder)
			if expr := expression.ParseInterface(unit, fnNode, t.GetId(), ctx.Expression()); expr != nil {
				t.Expression = expr
				t.TypeDescription = t.Expression.GetTypeDescription()
			}
		}
	}

	if ctx.Expression() != nil {
		expression := NewExpression(t.ASTBuilder)
		t.Expression = expression.Parse(unit, nil, fnNode, nil, nil, nil, t.GetId(), ctx.Expression())
		t.TypeDescription = t.Expression.GetTypeDescription()
	}

	if t.GetTypeDescription() == nil {
		normalizedTypeName, normalizedTypeIdentifier, found := normalizeTypeDescriptionWithStatus(
			t.Name,
		)

		if found {
			t.TypeDescription = &TypeDescription{
				TypeString:     normalizedTypeName,
				TypeIdentifier: normalizedTypeIdentifier,
			}
		}
	}

}

// ParseMul parses the TypeName from the given TermalNode.
func (t *TypeName) ParseMul(unit *SourceUnit[Node[ast_pb.SourceUnit]], fnNode Node[NodeType], parentNodeId int64, ctx antlr.TerminalNode) {
	t.NodeType = ast_pb.NodeType_ELEMENTARY_TYPE_NAME
	t.Name = ctx.GetText()

	t.Src = SrcNode{
		Line:        int64(ctx.GetSymbol().GetLine()),
		Column:      int64(ctx.GetSymbol().GetColumn()),
		Start:       int64(ctx.GetSymbol().GetStart()),
		End:         int64(ctx.GetSymbol().GetStop()),
		Length:      int64(ctx.GetSymbol().GetStop() - ctx.GetSymbol().GetStart() + 1),
		ParentIndex: parentNodeId,
	}

	t.TypeDescription = &TypeDescription{
		TypeString:     "string",
		TypeIdentifier: "t_string_literal",
	}
}

// ParseElementaryType parses the ElementaryTypeName from the given ElementaryTypeNameContext.
func (t *TypeName) ParseElementaryType(unit *SourceUnit[Node[ast_pb.SourceUnit]], fnNode Node[NodeType], parentNodeId int64, ctx parser.IElementaryTypeNameContext) {
	t.Src = SrcNode{
		Line:        int64(ctx.GetStart().GetLine()),
		Column:      int64(ctx.GetStart().GetColumn()),
		Start:       int64(ctx.GetStart().GetStart()),
		End:         int64(ctx.GetStop().GetStop()),
		Length:      int64(ctx.GetStop().GetStop() - ctx.GetStart().GetStart() + 1),
		ParentIndex: parentNodeId,
	}

	t.Name = ctx.GetText()
	t.NodeType = ast_pb.NodeType_ELEMENTARY_TYPE_NAME

	normalizedTypeName, normalizedTypeIdentifier := normalizeTypeDescription(
		ctx.GetText(),
	)

	switch normalizedTypeIdentifier {
	case "t_address":
		t.StateMutability = ast_pb.Mutability_NONPAYABLE
	case "t_address_payable":
		t.StateMutability = ast_pb.Mutability_PAYABLE
	}

	if ctx.Payable() != nil {
		t.StateMutability = ast_pb.Mutability_PAYABLE
	}

	t.TypeDescription = &TypeDescription{
		TypeIdentifier: normalizedTypeIdentifier,
		TypeString:     normalizedTypeName,
	}

}

// PathNode represents a path node within a TypeName.
type PathNode struct {
	Id                    int64            `json:"id"`
	Name                  string           `json:"name"`
	NodeType              ast_pb.NodeType  `json:"nodeType"`
	ReferencedDeclaration int64            `json:"referencedDeclaration"`
	Src                   SrcNode          `json:"src"`
	NameLocation          *SrcNode         `json:"nameLocation,omitempty"`
	TypeDescription       *TypeDescription `json:"typeDescription,omitempty"`
}

// GetId returns the unique identifier of the PathNode.
func (pn *PathNode) GetId() int64 {
	return pn.Id
}

// GetType returns the node type of the PathNode.
func (pn *PathNode) GetType() ast_pb.NodeType {
	return pn.NodeType
}

// GetSrc returns the source location information of the PathNode.
func (pn *PathNode) GetSrc() SrcNode {
	return pn.Src
}

// GetName returns the name of the PathNode.
func (pn *PathNode) GetName() string {
	return pn.Name
}

// GetNameLocation returns the name location of the PathNode.
func (pn *PathNode) GetNameLocation() *SrcNode {
	return pn.NameLocation
}

// GetTypeDescription returns the type description associated with the PathNode.
func (pn *PathNode) GetTypeDescription() *TypeDescription {
	if pn.TypeDescription == nil {
		return &TypeDescription{
			TypeString:     "not_in_use",
			TypeIdentifier: "t_not_in_use",
		}
	}

	return pn.TypeDescription
}

// GetReferencedDeclaration returns the referenced declaration of the PathNode.
func (pn *PathNode) GetReferencedDeclaration() int64 {
	return pn.ReferencedDeclaration
}

// GetNodes returns a list of child nodes for traversal within the PathNode.
func (pn *PathNode) GetNodes() []Node[NodeType] {
	return []Node[NodeType]{}
}

// SetReferenceDescriptor sets the reference descriptions of the PathNode node.
func (pn *PathNode) SetReferenceDescriptor(refId int64, refDesc *TypeDescription) bool {
	pn.ReferencedDeclaration = refId
	pn.TypeDescription = refDesc
	return true
}

// ToProto converts the PathNode instance to its corresponding protocol buffer representation.
func (pn *PathNode) ToProto() NodeType {
	toReturn := &ast_pb.PathNode{
		Id:                    pn.GetId(),
		Name:                  pn.GetName(),
		NodeType:              pn.GetType(),
		ReferencedDeclaration: pn.GetReferencedDeclaration(),
		Src:                   pn.GetSrc().ToProto(),
	}
	if pn.GetNameLocation() != nil {
		toReturn.NameLocation = pn.GetNameLocation().ToProto()
	}

	return toReturn
}

// TypeDescription represents a description of a type.
type TypeDescription struct {
	TypeIdentifier string `json:"typeIdentifier"`
	TypeString     string `json:"typeString"`
}

// GetIdentifier returns the type identifier of the TypeDescription.
func (td *TypeDescription) GetIdentifier() string {
	return td.TypeIdentifier
}

// GetString returns the type string of the TypeDescription.
func (td *TypeDescription) GetString() string {
	return td.TypeString
}

// ToProto converts the TypeDescription instance to its corresponding protocol buffer representation.
func (td *TypeDescription) ToProto() *ast_pb.TypeDescription {
	return &ast_pb.TypeDescription{
		TypeString:     td.TypeString,
		TypeIdentifier: td.TypeIdentifier,
	}
}
