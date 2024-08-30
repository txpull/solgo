package ast

import (
	"fmt"
	"github.com/goccy/go-json"
	"regexp"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	ast_pb "github.com/unpackdev/protos/dist/go/ast"
	"github.com/unpackdev/solgo/parser"
	"github.com/unpackdev/solgo/utils"
)

// Function represents a Solidity function definition within an abstract syntax tree.
type Function struct {
	*ASTBuilder // Embedded ASTBuilder for creating the AST.

	// Core properties of a function node.
	Id                    int64                 `json:"id"`
	Name                  string                `json:"name"`
	NodeType              ast_pb.NodeType       `json:"nodeType"`
	Kind                  ast_pb.NodeType       `json:"kind"`
	Src                   SrcNode               `json:"src"`
	NameLocation          SrcNode               `json:"nameLocation"`
	Body                  *BodyNode             `json:"body"`
	Implemented           bool                  `json:"implemented"`
	Visibility            ast_pb.Visibility     `json:"visibility"`
	StateMutability       ast_pb.Mutability     `json:"stateMutability"`
	Virtual               bool                  `json:"virtual"`
	Modifiers             []*ModifierInvocation `json:"modifiers"`
	Overrides             []*OverrideSpecifier  `json:"overrides"`
	Parameters            *ParameterList        `json:"parameters"`
	ReturnParameters      *ParameterList        `json:"returnParameters"`
	SignatureRaw          string                `json:"signatureRaw"`
	SignatureBytes        []byte                `json:"-"`
	Signature             string                `json:"signature"`
	Scope                 int64                 `json:"scope"`
	ReferencedDeclaration int64                 `json:"referencedDeclaration,omitempty"`
	TypeDescription       *TypeDescription      `json:"typeDescription"`
	Text                  string                `json:"text,omitempty"`
}

// NewFunction creates and initializes a new Function node.
func NewFunction(b *ASTBuilder) *Function {
	return &Function{
		ASTBuilder:  b,
		NodeType:    ast_pb.NodeType_FUNCTION_DEFINITION,
		Kind:        ast_pb.NodeType_KIND_FUNCTION,
		Modifiers:   make([]*ModifierInvocation, 0),
		Overrides:   make([]*OverrideSpecifier, 0),
		Implemented: true,
	}
}

// SetReferenceDescriptor sets the reference descriptions of the Function node.
func (f *Function) SetReferenceDescriptor(refId int64, refDesc *TypeDescription) bool {
	f.ReferencedDeclaration = refId
	f.TypeDescription = refDesc
	return false
}

// GetId returns the unique identifier of the Function node.
func (f *Function) GetId() int64 {
	return f.Id
}

// GetType returns the type of the Function node.
func (f *Function) GetType() ast_pb.NodeType {
	return f.NodeType
}

// GetSrc returns the source location information of the Function node.
func (f *Function) GetSrc() SrcNode {
	return f.Src
}

// GetNameLocation returns the source location information of the name of the Function node.
func (f *Function) GetNameLocation() SrcNode {
	return f.NameLocation
}

// GetParameters returns the list of parameters of the Function node.
func (f *Function) GetParameters() *ParameterList {
	return f.Parameters
}

// GetReturnParameters returns the list of return parameters of the Function node.
func (f *Function) GetReturnParameters() *ParameterList {
	return f.ReturnParameters
}

// GetBody returns the body of the Function node.
func (f *Function) GetBody() *BodyNode {
	return f.Body
}

// GetKind returns the kind of the Function node.
func (f *Function) GetKind() ast_pb.NodeType {
	return f.Kind
}

// IsImplemented returns true if the Function node is implemented, false otherwise.
func (f *Function) IsImplemented() bool {
	return f.Implemented
}

// GetModifiers returns the list of modifier invocations applied to the Function node.
func (f *Function) GetModifiers() []*ModifierInvocation {
	return f.Modifiers
}

// GetOverrides returns the list of override specifiers associated with the Function node.
func (f *Function) GetOverrides() []*OverrideSpecifier {
	return f.Overrides
}

// GetVisibility returns the visibility of the Function node.
func (f *Function) GetVisibility() ast_pb.Visibility {
	return f.Visibility
}

// GetStateMutability returns the state mutability of the Function node.
func (f *Function) GetStateMutability() ast_pb.Mutability {
	return f.StateMutability
}

// IsVirtual returns true if the Function node is declared as virtual, false otherwise.
func (f *Function) IsVirtual() bool {
	return f.Virtual
}

// GetScope returns the scope of the Function node.
func (f *Function) GetScope() int64 {
	return f.Scope
}

// GetName returns the name of the Function node.
func (f *Function) GetName() string {
	return f.Name
}

// GetTypeDescription returns the type description of the Function node.
func (f *Function) GetTypeDescription() *TypeDescription {
	return f.TypeDescription
}

// ComputeSignature computes the signature of the Function node.
func (f *Function) ComputeSignature() {
	params := make([]string, 0)

	if f.GetParameters() != nil {
		for _, param := range f.GetParameters().GetParameters() {
			/*			if param.TypeName.TypeDescription == nil {
						utils.DumpNodeWithExit(param)
					}*/
			typeString := param.TypeName.TypeDescription.TypeString
			actualParam := param.TypeName.Name

			if strings.Contains(typeString, "contract") {
				if strings.Contains(typeString, "[]") {
					actualParam = "address[]"
				} else {
					actualParam = "address"
				}
			} else if strings.Contains(typeString, "struct") {
				structParams := make([]string, 0)
				if iNode := f.resolver.GetTree().GetById(param.TypeName.GetReferencedDeclaration()); iNode != nil {
					switch node := iNode.(type) {
					case *Parameter:
						if piNode := f.resolver.GetTree().GetById(node.GetTypeName().GetReferencedDeclaration()); piNode != nil {
							switch pNode := piNode.(type) {
							case *StructDefinition:
								for _, member := range pNode.GetMembers() {
									if strings.Contains(member.GetTypeDescription().GetString(), "contract") {
										if strings.Contains(member.GetTypeDescription().GetString(), "[]") {
											structParams = append(structParams, "address[]")
										} else {
											structParams = append(structParams, "address")
										}
									} else if strings.Contains(member.GetTypeDescription().GetString(), "enum") {
										if strings.Contains(member.GetTypeDescription().GetString(), "[]") {
											structParams = append(structParams, "uint8[]")
										} else {
											structParams = append(structParams, "uint8")
										}
									} else {
										structParams = append(structParams, member.GetTypeDescription().GetString())
									}
								}
							}
						}
					case *StructDefinition:
						for _, member := range node.GetMembers() {
							if strings.Contains(member.GetTypeDescription().GetString(), "contract") {
								if strings.Contains(member.GetTypeDescription().GetString(), "[]") {
									structParams = append(structParams, "address[]")
								} else {
									structParams = append(structParams, "address")
								}
							} else if strings.Contains(member.GetTypeDescription().GetString(), "enum") {
								if strings.Contains(member.GetTypeDescription().GetString(), "[]") {
									structParams = append(structParams, "uint8[]")
								} else {
									structParams = append(structParams, "uint8")
								}
							} else {
								structParams = append(structParams, member.GetTypeDescription().GetString())
							}
						}
					}
				}
				actualParam = "(" + strings.Join(structParams, ",") + ")"
			} else if strings.Contains(typeString, "enum") {
				if strings.Contains(typeString, "[]") {
					actualParam = "uint8[]"
				} else {
					actualParam = "uint8"
				}
			} else if strings.Contains(typeString, "mapping") {
				actualParam = strings.Join(translateMapping(typeString), ",")
			}

			params = append(params, actualParam)
		}
	}
	f.SignatureRaw = strings.Join(
		[]string{
			f.GetName(),
			"(",
			strings.Join(params, ","),
			")",
		}, "",
	)
	f.SignatureBytes = utils.Keccak256([]byte(f.SignatureRaw))
	f.Signature = common.Bytes2Hex(f.SignatureBytes[:4])
}

// GetSignatureRaw returns the raw signature of the Function node.
func (f *Function) GetSignatureRaw() string {
	return f.SignatureRaw
}

// GetSignatureBytes returns the keccak signature full bytes of the Function node.
func (f *Function) GetSignatureBytes() []byte {
	return f.SignatureBytes
}

// GetSignature computes the keccak signature of the Function node.
func (f *Function) GetSignature() string {
	return f.Signature
}

// GetNodes returns a list of child nodes within the Function node.
func (f *Function) GetNodes() []Node[NodeType] {
	toReturn := []Node[NodeType]{}
	toReturn = append(toReturn, f.GetBody().GetNodes()...)
	toReturn = append(toReturn, f.GetParameters().GetNodes()...)
	toReturn = append(toReturn, f.GetReturnParameters().GetNodes()...)

	for _, override := range f.GetOverrides() {
		toReturn = append(toReturn, override)
	}

	for _, modifier := range f.GetModifiers() {
		toReturn = append(toReturn, modifier)
	}

	return toReturn
}

func (f *Function) ToString() string {
	return f.Text
}

// GetReferencedDeclaration returns the referenced declaration identifier associated with the Function node.
func (f *Function) GetReferencedDeclaration() int64 {
	return f.ReferencedDeclaration
}

func (f *Function) UnmarshalJSON(data []byte) error {
	var tempMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &tempMap); err != nil {
		return err
	}

	if id, ok := tempMap["id"]; ok {
		if err := json.Unmarshal(id, &f.Id); err != nil {
			return err
		}
	}

	if name, ok := tempMap["name"]; ok {
		if err := json.Unmarshal(name, &f.Name); err != nil {
			return err
		}
	}

	if nodeType, ok := tempMap["nodeType"]; ok {
		if err := json.Unmarshal(nodeType, &f.NodeType); err != nil {
			return err
		}
	}

	if kind, ok := tempMap["kind"]; ok {
		if err := json.Unmarshal(kind, &f.Kind); err != nil {
			return err
		}
	}

	if src, ok := tempMap["src"]; ok {
		if err := json.Unmarshal(src, &f.Src); err != nil {
			return err
		}
	}

	if nameLocation, ok := tempMap["nameLocation"]; ok {
		if err := json.Unmarshal(nameLocation, &f.NameLocation); err != nil {
			return err
		}
	}

	if implemented, ok := tempMap["implemented"]; ok {
		if err := json.Unmarshal(implemented, &f.Implemented); err != nil {
			return err
		}
	}

	if visibility, ok := tempMap["visibility"]; ok {
		if err := json.Unmarshal(visibility, &f.Visibility); err != nil {
			return err
		}
	}

	if sm, ok := tempMap["stateMutability"]; ok {
		if err := json.Unmarshal(sm, &f.StateMutability); err != nil {
			return err
		}
	}

	if virtual, ok := tempMap["virtual"]; ok {
		if err := json.Unmarshal(virtual, &f.Virtual); err != nil {
			return err
		}
	}

	if modifiers, ok := tempMap["modifiers"]; ok {
		if err := json.Unmarshal(modifiers, &f.Modifiers); err != nil {
			return err
		}
	}

	if overrides, ok := tempMap["overrides"]; ok {
		if err := json.Unmarshal(overrides, &f.Overrides); err != nil {
			return err
		}
	}

	if params, ok := tempMap["parameters"]; ok {
		if err := json.Unmarshal(params, &f.Parameters); err != nil {
			return err
		}
	}

	if retParams, ok := tempMap["returnParameters"]; ok {
		if err := json.Unmarshal(retParams, &f.ReturnParameters); err != nil {
			return err
		}
	}

	if scope, ok := tempMap["scope"]; ok {
		if err := json.Unmarshal(scope, &f.Scope); err != nil {
			return err
		}
	}

	if refD, ok := tempMap["referencedDeclaration"]; ok {
		if err := json.Unmarshal(refD, &f.ReferencedDeclaration); err != nil {
			return err
		}
	}

	if td, ok := tempMap["typeDescription"]; ok {
		if err := json.Unmarshal(td, &f.TypeDescription); err != nil {
			return err
		}
	}

	if sigRaw, ok := tempMap["signatureRaw"]; ok {
		if err := json.Unmarshal(sigRaw, &f.SignatureRaw); err != nil {
			return err
		}
	}

	if sigBytes, ok := tempMap["signatureBytes"]; ok {
		if err := json.Unmarshal(sigBytes, &f.SignatureBytes); err != nil {
			return err
		}
	}

	if sig, ok := tempMap["signature"]; ok {
		if err := json.Unmarshal(sig, &f.Signature); err != nil {
			return err
		}
	}

	if body, ok := tempMap["body"]; ok {
		if err := json.Unmarshal(body, &f.Body); err != nil {
			return err
		}
	}

	return nil
}

// ToProto converts the Function node to its corresponding protobuf representation.
func (f *Function) ToProto() NodeType {
	proto := ast_pb.Function{
		Id:                    f.GetId(),
		Name:                  f.GetName(),
		NodeType:              f.GetType(),
		Kind:                  f.GetKind(),
		Src:                   f.GetSrc().ToProto(),
		NameLocation:          f.GetNameLocation().ToProto(),
		ReferencedDeclaration: f.GetReferencedDeclaration(),
		Implemented:           f.IsImplemented(),
		Virtual:               f.IsVirtual(),
		Scope:                 f.GetScope(),
		Visibility:            f.GetVisibility(),
		StateMutability:       f.GetStateMutability(),
		Modifiers:             make([]*ast_pb.ModifierInvocation, 0),
		Overrides:             make([]*ast_pb.OverrideSpecifier, 0),
		Parameters:            f.GetParameters().ToProto(),
		ReturnParameters:      f.GetReturnParameters().ToProto(),
		Body:                  f.GetBody().ToProto().(*ast_pb.Body),
		Signature:             f.GetSignature(),
	}

	if f.GetTypeDescription() != nil {
		proto.TypeDescription = f.GetTypeDescription().ToProto()
	}

	for _, modifier := range f.GetModifiers() {
		proto.Modifiers = append(proto.Modifiers, modifier.ToProto().(*ast_pb.ModifierInvocation))
	}

	for _, override := range f.GetOverrides() {
		proto.Overrides = append(proto.Overrides, override.ToProto().(*ast_pb.OverrideSpecifier))
	}

	return NewTypedStruct(&proto, "Function")
}

// Parse parses the source code and constructs the Function node.
func (f *Function) Parse(
	unit *SourceUnit[Node[ast_pb.SourceUnit]],
	contractNode Node[NodeType],
	bodyCtx parser.IContractBodyElementContext,
	ctx *parser.FunctionDefinitionContext,
) Node[NodeType] {
	// Initialize basic properties.
	f.Text = ctx.GetText()
	f.Id = f.GetNextID()
	f.Scope = contractNode.GetId()
	if ctx.Identifier() != nil {
		f.Name = ctx.Identifier().GetText()
		f.NameLocation = SrcNode{
			Line:        int64(ctx.Identifier().GetStart().GetLine()),
			Column:      int64(ctx.Identifier().GetStart().GetColumn()),
			Start:       int64(ctx.Identifier().GetStart().GetStart()),
			End:         int64(ctx.Identifier().GetStop().GetStop()),
			Length:      int64(ctx.Identifier().GetStop().GetStop() - ctx.Identifier().GetStart().GetStart() + 1),
			ParentIndex: f.Id,
		}
	}
	f.Implemented = ctx.Block() != nil && !ctx.Block().IsEmpty()
	f.Src = SrcNode{
		Line:        int64(ctx.GetStart().GetLine()),
		Column:      int64(ctx.GetStart().GetColumn()),
		Start:       int64(ctx.GetStart().GetStart()),
		End:         int64(ctx.GetStop().GetStop()),
		Length:      int64(ctx.GetStop().GetStop() - ctx.GetStart().GetStart() + 1),
		ParentIndex: contractNode.GetId(),
	}

	// Set function visibility state.
	f.Visibility = f.getVisibilityFromCtx(ctx)

	// Set function state mutability.
	f.StateMutability = f.getStateMutabilityFromCtx(ctx)

	// Set if function is virtual.
	f.Virtual = f.getVirtualState(ctx)

	// Set function parameters if they exist.
	params := NewParameterList(f.ASTBuilder)

	if ctx.GetArguments() != nil {
		params.Parse(unit, f, ctx.GetArguments())
	} else {
		params.Src = f.Src
		params.Src.ParentIndex = f.Id
	}
	f.Parameters = params

	// Set function modifiers.
	for _, modifierCtx := range ctx.AllModifierInvocation() {
		modifier := NewModifierInvocation(f.ASTBuilder)
		modifier.Parse(unit, contractNode, f, nil, modifierCtx)
		f.Modifiers = append(f.Modifiers, modifier)
	}

	// Set function override specifier.
	for _, overrideCtx := range ctx.AllOverrideSpecifier() {
		overrideSpecifier := NewOverrideSpecifier(f.ASTBuilder)
		overrideSpecifier.Parse(unit, f, overrideCtx)
		f.Overrides = append(f.Overrides, overrideSpecifier)
	}

	// Set function return parameters if they exist.
	// @TODO: Consider traversing through body to discover name of the return parameters even
	// if they are not defined in (name uint) format.
	returnParams := NewParameterList(f.ASTBuilder)
	if ctx.GetReturnParameters() != nil {
		returnParams.Parse(unit, f, ctx.GetReturnParameters())
	} else {
		returnParams.Src = f.Src
		returnParams.Src.ParentIndex = f.Id
	}
	f.ReturnParameters = returnParams

	if ctx.Block() != nil && !ctx.Block().IsEmpty() {
		bodyNode := NewBodyNode(f.ASTBuilder, false)
		bodyNode.ParseBlock(unit, contractNode, f, ctx.Block())
		f.Body = bodyNode

		// In case at any point we discover that the function is not implemented, we set the
		// implemented flag to false.
		if !bodyNode.Implemented {
			f.Implemented = false
		}

		if ctx.Block().AllUncheckedBlock() != nil {
			for _, uncheckedCtx := range ctx.Block().AllUncheckedBlock() {
				bodyNode := NewBodyNode(f.ASTBuilder, false)
				bodyNode.ParseUncheckedBlock(unit, contractNode, f, uncheckedCtx)
				f.Body.Statements = append(f.Body.Statements, bodyNode)

				// In case at any point we discover that the function is not implemented, we set the
				// implemented flag to false.
				if !bodyNode.Implemented {
					f.Implemented = false
				}
			}
		}
	} else {
		bodyNode := NewBodyNode(f.ASTBuilder, false)
		bodyNode.Src = f.Src
		bodyNode.Src.ParentIndex = f.Id
		f.Body = bodyNode
	}

	f.TypeDescription = f.buildTypeDescription()

	f.currentFunctions = append(f.currentFunctions, f)

	return f
}

// ParseTypeName parses the source code and constructs the Function node for TypeName.
func (f *Function) ParseTypeName(
	unit *SourceUnit[Node[ast_pb.SourceUnit]],
	parentNodeId int64,
	ctx *parser.FunctionTypeNameContext,
) Node[NodeType] {
	// Initialize basic properties.
	f.Id = f.GetNextID()

	if unit != nil {
		f.Scope = unit.GetId()
	}

	f.Src = SrcNode{
		Line:        int64(ctx.GetStart().GetLine()),
		Column:      int64(ctx.GetStart().GetColumn()),
		Start:       int64(ctx.GetStart().GetStart()),
		End:         int64(ctx.GetStop().GetStop()),
		Length:      int64(ctx.GetStop().GetStop() - ctx.GetStart().GetStart() + 1),
		ParentIndex: parentNodeId,
	}

	// Set function visibility state.
	f.Visibility = f.getVisibilityFromTypeNameCtx(ctx)

	// Set function state mutability.
	f.StateMutability = f.getStateMutabilityFromTypeNameCtx(ctx)

	// Set function parameters if they exist.
	params := NewParameterList(f.ASTBuilder)
	if len(ctx.AllParameterList()) > 0 {
		params.Parse(unit, f, ctx.AllParameterList()[0])
	} else {
		params.Src = f.Src
		params.Src.ParentIndex = f.Id
	}
	f.Parameters = params

	// Set function return parameters if they exist.
	// @TODO: Consider traversing through body to discover name of the return parameters even
	// if they are not defined in (name uint) format.
	returnParams := NewParameterList(f.ASTBuilder)
	if ctx.GetReturnParameters() != nil {
		returnParams.Parse(unit, f, ctx.GetReturnParameters())
	} else {
		returnParams.Src = f.Src
		returnParams.Src.ParentIndex = f.Id
	}
	f.ReturnParameters = returnParams

	bodyNode := NewBodyNode(f.ASTBuilder, false)
	bodyNode.Src = f.Src
	bodyNode.Src.ParentIndex = f.Id
	f.Body = bodyNode

	f.TypeDescription = f.buildTypeDescription()

	f.currentFunctions = append(f.currentFunctions, f)

	return f
}

// buildTypeDescription constructs the type description of the Function node.
func (f *Function) buildTypeDescription() *TypeDescription {
	typeString := "function("
	typeIdentifier := "t_function_"
	typeStrings := make([]string, 0)
	typeIdentifiers := make([]string, 0)

	for _, paramType := range f.GetParameters().GetParameterTypes() {
		if paramType == nil {
			typeStrings = append(typeStrings, fmt.Sprintf("unknown_%d", f.GetId()))
			typeIdentifiers = append(typeIdentifiers, fmt.Sprintf("$_t_unknown_%d", f.GetId()))
			continue
		}

		typeStrings = append(typeStrings, paramType.TypeString)
		typeIdentifiers = append(typeIdentifiers, "$_"+paramType.TypeIdentifier)
	}
	typeString += strings.Join(typeStrings, ",") + ")"
	typeIdentifier += strings.Join(typeIdentifiers, "$")

	if !strings.HasSuffix(typeIdentifier, "$") {
		typeIdentifier += "$"
	}

	re := regexp.MustCompile(`\${2,}`)
	typeIdentifier = re.ReplaceAllString(typeIdentifier, "$")

	return &TypeDescription{
		TypeString:     typeString,
		TypeIdentifier: typeIdentifier,
	}
}

// getVisibilityFromCtx extracts the visibility of the Function node from the parser context.
func (f *Function) getVisibilityFromCtx(ctx *parser.FunctionDefinitionContext) ast_pb.Visibility {
	visibilityMap := map[string]ast_pb.Visibility{
		"public":   ast_pb.Visibility_PUBLIC,
		"private":  ast_pb.Visibility_PRIVATE,
		"internal": ast_pb.Visibility_INTERNAL,
		"external": ast_pb.Visibility_EXTERNAL,
	}

	for _, visibility := range ctx.AllVisibility() {
		if v, ok := visibilityMap[visibility.GetText()]; ok {
			return v
		}
	}

	return ast_pb.Visibility_INTERNAL
}

// getVisibilityFromTypeNameCtx extracts the visibility of the Function node from the parser context.
func (f *Function) getVisibilityFromTypeNameCtx(ctx *parser.FunctionTypeNameContext) ast_pb.Visibility {
	visibilityMap := map[string]ast_pb.Visibility{
		"public":   ast_pb.Visibility_PUBLIC,
		"private":  ast_pb.Visibility_PRIVATE,
		"internal": ast_pb.Visibility_INTERNAL,
		"external": ast_pb.Visibility_EXTERNAL,
	}

	for _, visibility := range ctx.AllVisibility() {
		if v, ok := visibilityMap[visibility.GetText()]; ok {
			return v
		}
	}

	return ast_pb.Visibility_INTERNAL
}

// getStateMutabilityFromCtx extracts the state mutability of the Function node from the parser context.
func (f *Function) getStateMutabilityFromCtx(ctx *parser.FunctionDefinitionContext) ast_pb.Mutability {
	mutabilityMap := map[string]ast_pb.Mutability{
		"payable": ast_pb.Mutability_PAYABLE,
		"pure":    ast_pb.Mutability_PURE,
		"view":    ast_pb.Mutability_VIEW,
	}

	for _, stateMutability := range ctx.AllStateMutability() {
		if m, ok := mutabilityMap[stateMutability.GetText()]; ok {
			return m
		}
	}

	return ast_pb.Mutability_NONPAYABLE
}

// getStateMutabilityFromTypeNameCtx extracts the state mutability of the Function node from the parser context.
func (f *Function) getStateMutabilityFromTypeNameCtx(ctx *parser.FunctionTypeNameContext) ast_pb.Mutability {
	mutabilityMap := map[string]ast_pb.Mutability{
		"payable": ast_pb.Mutability_PAYABLE,
		"pure":    ast_pb.Mutability_PURE,
		"view":    ast_pb.Mutability_VIEW,
	}

	for _, stateMutability := range ctx.AllStateMutability() {
		if m, ok := mutabilityMap[stateMutability.GetText()]; ok {
			return m
		}
	}

	return ast_pb.Mutability_NONPAYABLE
}

// getVirtualState determines if the Function node is declared as virtual from the parser context.
func (f *Function) getVirtualState(ctx *parser.FunctionDefinitionContext) bool {
	for _, virtual := range ctx.AllVirtual() {
		if virtual.GetText() == "virtual" {
			return true
		}
	}

	return false
}

// translateMapping translates a Solidity mapping type string into a slice of data types.
func translateMapping(mappingType string) []string {
	var result []string

	// Check if the input string starts with "mapping("
	if !strings.HasPrefix(mappingType, "mapping(") {
		return result
	}

	// Remove the "mapping(" prefix and the closing ")" at the end
	mappingType = strings.TrimPrefix(mappingType, "mapping(")
	mappingType = strings.TrimSuffix(mappingType, ")")

	// Split the string by "=>"
	parts := strings.Split(mappingType, "=>")
	for _, part := range parts {
		// Remove any leading and trailing spaces
		part = strings.TrimSpace(part)
		result = append(result, part)
	}

	return result
}
