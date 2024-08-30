package ast

import (
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"

	ast_pb "github.com/unpackdev/protos/dist/go/ast"
	"github.com/unpackdev/solgo/parser"
)

// PrimaryExpression represents a primary expression node in the AST.
type PrimaryExpression struct {
	*ASTBuilder

	Id                     int64              `json:"id"`                        // Unique identifier for the node.
	NodeType               ast_pb.NodeType    `json:"nodeType"`                  // Type of the node.
	Kind                   ast_pb.NodeType    `json:"kind,omitempty"`            // Kind of the node.
	Value                  string             `json:"value,omitempty"`           // Value of the node.
	HexValue               string             `json:"hexValue,omitempty"`        // Hexadecimal value of the node.
	Src                    SrcNode            `json:"src"`                       // Source location of the node.
	Name                   string             `json:"name,omitempty"`            // Name of the node.
	TypeName               *TypeName          `json:"typeName,omitempty"`        // Type name of the node.
	TypeDescription        *TypeDescription   `json:"typeDescription,omitempty"` // Type description of the node.
	OverloadedDeclarations []int64            `json:"overloadedDeclarations"`    // Overloaded declarations of the node.
	ReferencedDeclaration  int64              `json:"referencedDeclaration"`     // Referenced declaration of the node.
	Pure                   bool               `json:"isPure"`                    // Indicates if the node is pure.
	ArgumentTypes          []*TypeDescription `json:"argumentTypes,omitempty"`   // Argument types of the node.
	Text                   string             `json:"text,omitempty"`            // Text of the node.
}

// NewPrimaryExpression creates a new PrimaryExpression node with a given ASTBuilder.
// It initializes the OverloadedDeclarations slice and sets the NodeType to IDENTIFIER.
func NewPrimaryExpression(b *ASTBuilder) *PrimaryExpression {
	return &PrimaryExpression{
		ASTBuilder:             b,
		Id:                     b.GetNextID(),
		OverloadedDeclarations: make([]int64, 0),
		NodeType:               ast_pb.NodeType_IDENTIFIER,
		ArgumentTypes:          make([]*TypeDescription, 0),
	}
}

// SetReferenceDescriptor sets the reference descriptions of the PrimaryExpression node.
func (p *PrimaryExpression) SetReferenceDescriptor(refId int64, refDesc *TypeDescription) bool {
	p.ReferencedDeclaration = refId
	p.TypeDescription = refDesc

	// In case it's a function call, we need to rebuild the type descriptions from the parent node.
	// It is a hack, but working one. One day we'll figure out better solution for all of this referencing mess...
	if parentNode := p.ASTBuilder.GetTree().GetById(p.GetSrc().GetParentIndex()); parentNode != nil {
		switch node := parentNode.(type) {
		case *FunctionCall:
			node.RebuildDescriptions()
		default:
			if parentNode.GetTypeDescription() == nil {
				parentNode.SetReferenceDescriptor(refId, refDesc)
			}
		}
	}

	// There are cases where we need to rebuild node from updated descriptions.
	// For example if it's int_const we need to ensure it's set to pure...
	p.Rebuild()

	return true
}

// GetId returns the unique identifier of the PrimaryExpression node.
func (p *PrimaryExpression) GetId() int64 {
	return p.Id
}

// GetType returns the type of the PrimaryExpression node.
func (p *PrimaryExpression) GetType() ast_pb.NodeType {
	return p.NodeType
}

// GetSrc returns the source location of the PrimaryExpression node.
func (p *PrimaryExpression) GetSrc() SrcNode {
	return p.Src
}

// GetName returns the name of the PrimaryExpression node.
func (p *PrimaryExpression) GetName() string {
	return p.Name
}

// GetTypeDescription returns the type description of the PrimaryExpression node.
func (p *PrimaryExpression) GetTypeDescription() *TypeDescription {
	return p.TypeDescription
}

// GetArgumentTypes returns the argument types of the PrimaryExpression node.
func (p *PrimaryExpression) GetArgumentTypes() []*TypeDescription {
	return p.ArgumentTypes
}

// GetReferencedDeclaration returns the referenced declaration of the PrimaryExpression node.
func (p *PrimaryExpression) GetReferencedDeclaration() int64 {
	return p.ReferencedDeclaration
}

// GetNodes returns a slice of nodes that includes the expression of the PrimaryExpression node.
func (p *PrimaryExpression) GetNodes() []Node[NodeType] {
	if p.TypeName != nil {
		return []Node[NodeType]{p.TypeName}
	}

	return []Node[NodeType]{}
}

// GetKind returns the kind of the PrimaryExpression node.
func (p *PrimaryExpression) GetKind() ast_pb.NodeType {
	return p.Kind
}

// GetValue returns the value of the PrimaryExpression node.
func (p *PrimaryExpression) GetValue() string {
	return p.Value
}

// GetHexValue returns the hexadecimal value of the PrimaryExpression node.
func (p *PrimaryExpression) GetHexValue() string {
	return p.HexValue
}

// IsPure returns true if the PrimaryExpression node is pure.
func (p *PrimaryExpression) IsPure() bool {
	return p.Pure
}

// GetOverloadedDeclarations returns the overloaded declarations of the PrimaryExpression node.
func (p *PrimaryExpression) GetOverloadedDeclarations() []int64 {
	return p.OverloadedDeclarations
}

// GetTypeName returns the type name of the PrimaryExpression node.
func (p *PrimaryExpression) GetTypeName() *TypeName {
	return p.TypeName
}

// Rebuild rebuilds the PrimaryExpression node after referenced declaration is set.
func (p *PrimaryExpression) Rebuild() {
	if p.TypeDescription != nil {
		if strings.Contains(p.TypeDescription.TypeString, "int_const") {
			p.Pure = true
		}
	}
}

// ToProto returns a protobuf representation of the PrimaryExpression node.
// Currently, it returns an empty PrimaryExpression and needs to be implemented.
func (p *PrimaryExpression) ToProto() NodeType {
	proto := ast_pb.PrimaryExpression{
		Id:                     p.GetId(),
		Name:                   p.GetName(),
		Value:                  p.GetValue(),
		HexValue:               p.GetHexValue(),
		NodeType:               p.GetType(),
		Kind:                   p.GetKind(),
		Src:                    p.GetSrc().ToProto(),
		ReferencedDeclaration:  p.GetReferencedDeclaration(),
		IsPure:                 p.IsPure(),
		OverloadedDeclarations: p.GetOverloadedDeclarations(),
		ArgumentTypes:          make([]*ast_pb.TypeDescription, 0),
	}

	if p.GetTypeName() != nil {
		proto.TypeName = p.GetTypeName().ToProto().(*ast_pb.TypeName)
	}

	if p.GetTypeDescription() != nil {
		proto.TypeDescription = p.GetTypeDescription().ToProto()
	}

	for _, arg := range p.GetArgumentTypes() {
		proto.ArgumentTypes = append(proto.ArgumentTypes, arg.ToProto())
	}

	return NewTypedStruct(&proto, "PrimaryExpression")
}

// Parse takes a parser.PrimaryExpressionContext and parses it into a PrimaryExpression node.
// It sets the Src, Name, NodeType, Kind, Value, HexValue, TypeDescription, and other properties of the PrimaryExpression node.
// It returns the created PrimaryExpression node.
func (p *PrimaryExpression) Parse(
	unit *SourceUnit[Node[ast_pb.SourceUnit]],
	contractNode Node[NodeType],
	fnNode Node[NodeType],
	bodyNode *BodyNode,
	vDeclar *VariableDeclaration,
	expNode Node[NodeType],
	parentNodeId int64,
	ctx *parser.PrimaryExpressionContext,
) Node[NodeType] {
	p.Text = ctx.GetText()
	p.Src = SrcNode{
		Line:        int64(ctx.GetStart().GetLine()),
		Column:      int64(ctx.GetStart().GetColumn()),
		Start:       int64(ctx.GetStart().GetStart()),
		End:         int64(ctx.GetStop().GetStop()),
		Length:      int64(ctx.GetStop().GetStop() - ctx.GetStart().GetStart() + 1),
		ParentIndex: parentNodeId,
	}

	if ctx.Identifier() != nil {
		p.Name = ctx.Identifier().GetText()
	}

	if ctx.GetText() == "msg" {
		p.TypeDescription = &TypeDescription{
			TypeIdentifier: "t_magic_message",
			TypeString:     "msg",
		}
	}

	if ctx.GetText() == "throw" {
		p.TypeDescription = &TypeDescription{
			TypeIdentifier: "t_magic_throw",
			TypeString:     "throw",
		}
	}

	if ctx.GetText() == "block" {
		p.TypeDescription = &TypeDescription{
			TypeIdentifier: "t_magic_block",
			TypeString:     "block",
		}
	}

	if ctx.GetText() == "abi" {
		p.TypeDescription = &TypeDescription{
			TypeIdentifier: "t_magic_abi",
			TypeString:     "abi",
		}
	}

	// For now just like this but in the future we should look into figuring out which contract
	// is being referenced here...
	// We would need to search for function declarations and match them accordingly...
	if ctx.GetText() == "super" {
		p.TypeDescription = &TypeDescription{
			TypeIdentifier: "t_magic_super",
			TypeString:     "super",
		}
	}

	// This is a magic this type and should be treated by setting type description to the contract type
	if ctx.GetText() == "this" {
		if unit == nil {
			p.TypeDescription = &TypeDescription{
				TypeIdentifier: "t_magic_this",
				TypeString:     "this",
			}
		} else {
			p.TypeDescription = unit.GetTypeDescription()
		}
	}

	if ctx.GetText() == "now" {
		p.TypeDescription = &TypeDescription{
			TypeIdentifier: "t_magic_now",
			TypeString:     "now",
		}
	}

	if ctx.GetText() == "assert" {
		p.TypeDescription = &TypeDescription{
			TypeIdentifier: "t_function_assert_pure$_t_bool_$returns$__$",
			TypeString:     "function (bool) pure",
		}
	}

	if ctx.GetText() == "tx" {
		p.TypeDescription = &TypeDescription{
			TypeIdentifier: "t_magic_transaction",
			TypeString:     "tx",
		}
	}

	if ctx.GetText() == "origin" {
		p.TypeDescription = &TypeDescription{
			TypeIdentifier: "t_address",
			TypeString:     "address",
		}
	}

	if ctx.GetText() == "require" {
		p.TypeDescription = &TypeDescription{
			TypeIdentifier: "t_function_require_pure",
			TypeString:     "function () pure",
		}
		p.Pure = true
	}

	// There is a case where we get PlaceholderStatement as a PrimaryExpression and this one does nothing really...
	// So we are going to do some hack here to make it work properly...
	if p.Name == "_" {
		p.NodeType = ast_pb.NodeType_PLACEHOLDER_STATEMENT
		p.TypeDescription = &TypeDescription{
			TypeIdentifier: "t_placeholder_literal",
			TypeString:     "t_placeholder",
		}
		return p
	}

	if ctx.ElementaryTypeName() != nil {
		typeName := NewTypeName(p.ASTBuilder)
		typeName.WithParentNode(contractNode)
		typeName.WithBodyNode(bodyNode)
		typeName.WithParentNode(expNode)
		typeName.ParseElementaryType(unit, fnNode, p.GetId(), ctx.ElementaryTypeName())
		p.TypeName = typeName
		p.TypeDescription = typeName.GetTypeDescription()
		p.Name = ctx.GetText()
	}

	if expNode != nil {
		switch expNodeCtx := expNode.(type) {
		case *FunctionCall:
			for _, argument := range expNodeCtx.GetArguments() {
				if argument.GetTypeDescription() != nil {
					p.ArgumentTypes = append(p.ArgumentTypes, argument.GetTypeDescription())
				}
			}

			if p.TypeName != nil {
				p.ArgumentTypes = append(p.ArgumentTypes, p.TypeName.GetTypeDescription())
			}

			p.TypeDescription = p.buildFunctionArgumentTypeDescription()
		}
	}

	if ctx.Identifier() != nil {
		// We cannot reach all of the parameter type description by simply discoveryReference
		// as some of the nodes such as this one is not yet written and is not accessible by
		// the discoverReferenceByCtxName()
		if fnNode != nil {
			switch fnNodeCtx := fnNode.(type) {
			case *Constructor:
				for _, param := range fnNodeCtx.GetParameters().GetParameters() {
					if param.GetName() == p.Name {
						if param.GetTypeName() != nil {
							p.TypeDescription = param.GetTypeName().GetTypeDescription()
							p.ReferencedDeclaration = p.GetId()
						}
						break
					}
				}
			case *Function:
				if fnNodeCtx.GetParameters() != nil {
					for _, param := range fnNodeCtx.GetParameters().GetParameters() {
						if param.GetName() == p.Name {
							if param.GetTypeName() != nil {
								p.TypeDescription = param.GetTypeName().GetTypeDescription()
								p.ReferencedDeclaration = p.GetId()
							}
							break
						}
					}
				}
			}
		}

		if bodyNode != nil {
			for _, statement := range bodyNode.GetStatements() {
				if statement != nil && statement.GetType() == ast_pb.NodeType_VARIABLE_DECLARATION {
					vDeclar := statement.(*VariableDeclaration)
					for _, declaration := range vDeclar.GetDeclarations() {
						if declaration.GetName() == p.Name {
							p.TypeDescription = declaration.GetTypeName().GetTypeDescription()
							p.ReferencedDeclaration = vDeclar.GetId()
							break
						}
					}
				}
			}
		}

		if p.TypeDescription == nil {
			if refId, refTypeDescription := p.GetResolver().ResolveByNode(p, p.Name); refTypeDescription != nil {
				p.ReferencedDeclaration = refId
				p.TypeDescription = refTypeDescription
			}
		}
	}

	literalCtx := ctx.Literal()
	if literalCtx != nil {
		p.NodeType = ast_pb.NodeType_LITERAL
		p.Pure = true

		if literalCtx.BooleanLiteral() != nil {
			if p.Name == "true" || p.Name == "false" {
				p.Name = ""
			}

			p.Kind = ast_pb.NodeType_BOOLEAN
			p.Value = strings.TrimSpace(
				// There can be hex 22 at beginning and end of literal.
				// We should drop it as that's ASCII for double quote.
				strings.ReplaceAll(literalCtx.BooleanLiteral().GetText(), "\"", ""),
			)
			p.HexValue = hex.EncodeToString([]byte(p.Value))

			p.TypeDescription = &TypeDescription{
				TypeIdentifier: "t_bool",
				TypeString:     "bool",
			}
		} else if literalCtx.StringLiteral() != nil {
			p.Name = ""
			p.Kind = ast_pb.NodeType_STRING

			p.Value = strings.TrimSpace(
				// There can be hex 22 at beginning and end of literal.
				// We should drop it as that's ASCII for double quote.
				strings.ReplaceAll(literalCtx.StringLiteral().GetText(), "\"", ""),
			)
			p.HexValue = hex.EncodeToString([]byte(p.Value))

			p.TypeDescription = &TypeDescription{
				TypeIdentifier: "t_string_literal",
				TypeString: fmt.Sprintf(
					"literal_string %s",
					literalCtx.StringLiteral().GetText(),
				),
			}
		} else if literalCtx.NumberLiteral() != nil {
			p.Kind = ast_pb.NodeType_NUMBER

			p.Value = strings.TrimSpace(
				// There can be hex 22 at beginning and end of literal.
				// We should drop it as that's ASCII for double quote.
				strings.ReplaceAll(literalCtx.NumberLiteral().GetText(), "\"", ""),
			)
			p.HexValue = hex.EncodeToString([]byte(p.Value))

			// Check if the number is a floating-point number
			if strings.Contains(p.Value, ".") {
				parts := strings.Split(p.Value, ".")

				// The numerator is the number without the decimal point
				numerator, _ := strconv.Atoi(parts[0] + parts[1])

				// The denominator is a power of 10 equal to the number of digits in the fractional part
				denominator := int(math.Pow(10, float64(len(parts[1]))))

				p.TypeDescription = &TypeDescription{
					TypeIdentifier: fmt.Sprintf("t_rational_%d_by_%d", numerator, denominator),
					TypeString: fmt.Sprintf(
						"fixed_const %s",
						literalCtx.NumberLiteral().GetText(),
					),
				}
			} else {
				numerator, _ := strconv.Atoi(p.Value)
				denominator := 1
				p.TypeDescription = &TypeDescription{
					TypeIdentifier: fmt.Sprintf("t_rational_%d_by_%d", numerator, denominator),
					TypeString: fmt.Sprintf(
						"int_const %s",
						literalCtx.NumberLiteral().GetText(),
					),
				}
			}
		} else if literalCtx.HexStringLiteral() != nil {
			p.Kind = ast_pb.NodeType_HEX_STRING

			p.Value = strings.TrimSpace(
				// There can be hex 22 at beginning and end of literal.
				// We should drop it as that's ASCII for double quote.
				strings.ReplaceAll(literalCtx.HexStringLiteral().GetText(), "\"", ""),
			)
			p.HexValue = hex.EncodeToString([]byte(p.Value))

			p.TypeDescription = &TypeDescription{
				TypeIdentifier: "t_string_hex_literal",
				TypeString: fmt.Sprintf(
					"literal_hex_string %s",
					literalCtx.HexStringLiteral().GetText(),
				),
			}
		} else if ctx.Literal().UnicodeStringLiteral() != nil {
			p.Kind = ast_pb.NodeType_UNICODE_STRING_LITERAL

			p.Value = strings.TrimSpace(
				// There can be hex 22 at beginning and end of literal.
				// We should drop it as that's ASCII for double quote.
				strings.ReplaceAll(
					strings.ReplaceAll(literalCtx.UnicodeStringLiteral().GetText(), "\"", ""),
					"unicode",
					"",
				),
			)

			p.TypeDescription = &TypeDescription{
				TypeIdentifier: "t_string_unicode_literal",
				TypeString: fmt.Sprintf(
					"literal_unicode_string \"%s\"",
					literalCtx.UnicodeStringLiteral().GetText(),
				),
			}
		} else {
			if ctx.GetText() == "msg" {
				p.TypeDescription = &TypeDescription{
					TypeIdentifier: "t_magic_message",
					TypeString:     "msg",
				}
			}

			if p.TypeDescription.TypeString == "" {
				if expNode != nil {
					p.TypeDescription = expNode.GetTypeDescription()
				}
			}
		}
	}

	if fnNode != nil && p.TypeDescription == nil {
		if fn, ok := fnNode.(*Function); ok {
			if fn.GetParameters() != nil {
				for _, param := range fn.GetParameters().GetParameters() {
					if param.GetName() == p.Name {
						p.TypeDescription = param.GetTypeName().GetTypeDescription()
						p.ReferencedDeclaration = fn.GetId()
						break
					}
				}
			}
		}

		if fn, ok := fnNode.(*ForStatement); ok {
			found := false
			if varD, ok := fn.GetInitialiser().(*VariableDeclaration); ok {
				for _, declar := range varD.GetDeclarations() {
					if declar.GetName() == p.Name {
						p.TypeDescription = declar.GetTypeName().GetTypeDescription()
						p.ReferencedDeclaration = varD.GetId()
						found = true
						break
					}
				}
			}

			// Seek the condition...
			if !found {
				if binOp, ok := fn.GetCondition().(*BinaryOperation); ok {
					if left, ok := binOp.GetLeftExpression().(*PrimaryExpression); ok {
						if left.GetName() == p.Name {
							p.TypeDescription = left.GetTypeDescription()
							p.ReferencedDeclaration = left.GetId()
							found = true
						}
					}

					if p.TypeDescription == nil {
						if right, ok := binOp.GetRightExpression().(*BinaryOperation); ok {
							if left, ok := right.GetLeftExpression().(*MemberAccessExpression); ok {
								if left.GetMemberName() == p.Name {
									p.TypeDescription = left.GetTypeDescription()
									p.ReferencedDeclaration = left.GetId()
									found = true
								}

								if p.TypeDescription == nil {
									if left, ok := left.GetExpression().(*PrimaryExpression); ok {
										if left.GetName() == p.Name {
											p.TypeDescription = left.GetTypeDescription()
											p.ReferencedDeclaration = left.GetId()
											found = true
										}
									}
								}
							}

							if p.TypeDescription == nil {
								if left, ok := right.GetRightExpression().(*PrimaryExpression); ok {
									if left.GetName() == p.Name {
										p.TypeDescription = left.GetTypeDescription()
										p.ReferencedDeclaration = left.GetId()
										found = true
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// If we still do not have type description set... Let's do one hack to search body node...
	// @TODO: Improve this in the future to search recursively...
	if bodyNode != nil && p.TypeDescription == nil {
		for _, statement := range bodyNode.GetStatements() {
			if expr, ok := statement.(*Assignment); ok {
				for _, node := range expr.GetNodes() {
					if pExpr, ok := node.(*PrimaryExpression); ok {
						if pExpr.GetName() == p.Name {
							p.TypeDescription = pExpr.GetTypeDescription()
							p.ReferencedDeclaration = pExpr.GetId()
							break
						}
					}

					for _, subnode := range node.GetNodes() {
						if pExpr, ok := subnode.(*PrimaryExpression); ok {
							if pExpr.GetName() == p.Name {
								p.TypeDescription = pExpr.GetTypeDescription()
								p.ReferencedDeclaration = pExpr.GetId()
								break
							}
						}
					}
				}
			} else if expr, ok := statement.(*VariableDeclaration); ok {
				for _, declar := range expr.GetDeclarations() {
					if declar.GetName() == p.Name {
						p.TypeDescription = declar.GetTypeName().GetTypeDescription()
						p.ReferencedDeclaration = expr.GetId()
						break
					}
				}

				for _, node := range expr.GetNodes() {
					if pExpr, ok := node.(*PrimaryExpression); ok {
						if pExpr.GetName() == p.Name {
							p.TypeDescription = pExpr.GetTypeDescription()
							p.ReferencedDeclaration = pExpr.GetId()
							break
						}
					}
				}
			}
		}
	}

	if p.TypeDescription == nil {
		if refId, refTypeDescription := p.GetResolver().ResolveByNode(p, p.GetName()); refTypeDescription != nil {
			p.ReferencedDeclaration = refId
			p.TypeDescription = refTypeDescription
		}
	}

	return p
}

// buildFunctionArgumentTypeDescription constructs and returns a TypeDescription for the PrimaryExpression's function argument types.
func (p *PrimaryExpression) buildFunctionArgumentTypeDescription() *TypeDescription {
	typeString := "function("
	typeIdentifier := "t_function_"
	typeStrings := make([]string, 0)
	typeIdentifiers := make([]string, 0)

	// If the PrimaryExpression is referring to "this", return the already set type description of the current expression scope.
	if p.GetName() == "this" {
		return p.GetTypeDescription()
	}

	// Loop through the argument types and construct type strings and identifiers.
	for _, paramType := range p.GetArgumentTypes() {
		if paramType == nil {
			typeStrings = append(typeStrings, "unknown")
			typeIdentifiers = append(typeIdentifiers, "$_t_unknown")
			continue
		}

		typeStrings = append(typeStrings, paramType.TypeString)
		typeIdentifiers = append(typeIdentifiers, "$_"+paramType.TypeIdentifier)
	}
	typeString += strings.Join(typeStrings, ",") + ")"
	typeIdentifier += strings.Join(typeIdentifiers, "$") + "$"

	return &TypeDescription{
		TypeString:     typeString,
		TypeIdentifier: typeIdentifier,
	}
}
