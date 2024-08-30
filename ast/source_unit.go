package ast

import (
	"fmt"
	"github.com/goccy/go-json"
	"path/filepath"
	"regexp"

	v3 "github.com/cncf/xds/go/xds/type/v3"
	ast_pb "github.com/unpackdev/protos/dist/go/ast"
	"github.com/unpackdev/solgo"
	"github.com/unpackdev/solgo/parser"
	"go.uber.org/zap"
)

// SourceUnit represents a source unit in the abstract syntax tree.
// It includes various attributes like id, license, exported symbols, absolute path, name, node type, nodes, and source node.
type SourceUnit[T NodeType] struct {
	Id              int64            `json:"id"`              // Id is the unique identifier of the source unit.
	Contract        Node[NodeType]   `json:"-"`               // Contract is the contract associated with the source unit.
	BaseContracts   []*BaseContract  `json:"baseContracts"`   // BaseContracts are the base contracts of the source unit.
	License         string           `json:"license"`         // License is the license of the source unit.
	ExportedSymbols []Symbol         `json:"exportedSymbols"` // ExportedSymbols is the list of source units, including its names and node tree ids used by current source unit.
	AbsolutePath    string           `json:"absolutePath"`    // AbsolutePath is the absolute path of the source unit.
	Name            string           `json:"name"`            // Name is the name of the source unit. This is going to be one of the following: contract, interface or library name. It's here for convenience.
	NodeType        ast_pb.NodeType  `json:"nodeType"`        // NodeType is the type of the AST node.
	Kind            ast_pb.NodeType  `json:"kind"`            // Kind is the type of the AST node (contract, library, interface).
	Nodes           []Node[NodeType] `json:"nodes"`           // Nodes is the list of AST nodes.
	Src             SrcNode          `json:"src"`             // Src is the source code location.
}

// NewSourceUnit creates a new SourceUnit with the provided ASTBuilder, name, and license.
// It returns a pointer to the created SourceUnit.
func NewSourceUnit[T any](builder *ASTBuilder, name string, license string) *SourceUnit[T] {
	return &SourceUnit[T]{
		Id:              builder.GetNextID(),
		Name:            name,
		License:         license,
		Nodes:           make([]Node[NodeType], 0),
		NodeType:        ast_pb.NodeType_SOURCE_UNIT,
		ExportedSymbols: make([]Symbol, 0),
		BaseContracts:   make([]*BaseContract, 0),
	}
}

// SetAbsolutePathFromSources sets the absolute path of the source unit from the provided sources.
func (s *SourceUnit[T]) SetAbsolutePathFromSources(sources *solgo.Sources) {
	// Compile the regex outside the loop to improve efficiency.
	pattern := fmt.Sprintf(`(?m)^\s*(abstract\s+)?(library|interface|contract)\s+%s\s*(is\s+[\w\s,]+)?\s*{?`, regexp.QuoteMeta(s.Name))
	regex, err := regexp.Compile(pattern)
	if err != nil {
		zap.L().Error("Regex compilation error", zap.Error(err))
		return
	}

	found := false
	for _, unit := range sources.SourceUnits {
		if unit.Name == s.Name {
			s.AbsolutePath = filepath.Base(filepath.Clean(unit.Path))
			found = true
			break
		}

		// Use the compiled regex for matching.
		if regex.MatchString(unit.GetContent()) {
			s.AbsolutePath = filepath.Base(filepath.Clean(unit.Path))
			found = true
			break
		}
	}

	if !found {
		zap.L().Debug(
			"Could not set absolute path from sources as source unit was not found in sources",
			zap.String("name", s.Name),
			zap.String("pattern", pattern),
		)
	}
}

// SetReferenceDescriptor sets the reference descriptions of the SourceUnit node.
func (s *SourceUnit[T]) SetReferenceDescriptor(refId int64, refDesc *TypeDescription) bool {
	return false
}

// GetLicense returns the license of the source unit.
func (s *SourceUnit[T]) GetLicense() string {
	return s.License
}

// GetNodes returns the nodes associated with the source unit.
func (s *SourceUnit[T]) GetNodes() []Node[NodeType] {
	return s.Nodes
}

// GetName returns the name of the source unit.
func (s *SourceUnit[T]) GetName() string {
	return s.Name
}

// GetId returns the unique identifier of the source unit.
func (s *SourceUnit[T]) GetId() int64 {
	return s.Id
}

// GetType returns the type of the source unit.
func (s *SourceUnit[T]) GetType() ast_pb.NodeType {
	return s.NodeType
}

// GetKind returns the type of the source unit.
func (s *SourceUnit[T]) GetKind() ast_pb.NodeType {
	return s.Kind
}

// GetSrc returns the source code location of the source unit.
func (s *SourceUnit[T]) GetSrc() SrcNode {
	return s.Src
}

// GetExportedSymbols returns the exported symbols of the source unit.
func (s *SourceUnit[T]) GetExportedSymbols() []Symbol {
	return s.ExportedSymbols
}

// GetAbsolutePath returns the absolute path of the source unit.
func (s *SourceUnit[T]) GetAbsolutePath() string {
	toReturn := filepath.Clean(s.AbsolutePath)
	toReturn = filepath.Base(toReturn)
	return toReturn
}

// GetContract returns the contract associated with the source unit.
func (s *SourceUnit[T]) GetContract() Node[NodeType] {
	return s.Contract
}

// SetContract sets the contract associated with the source unit.
func (s *SourceUnit[T]) SetContract(contract Node[NodeType]) {
	s.Contract = contract
}

// GetBaseContracts returns the base contracts of the source unit.
func (s *SourceUnit[T]) GetBaseContracts() []*BaseContract {
	return s.BaseContracts
}

// GetTypeDescription returns the type description of the source unit.
func (s *SourceUnit[T]) GetTypeDescription() *TypeDescription {
	return &TypeDescription{
		TypeIdentifier: fmt.Sprintf("t_contract$_%s_$%d", s.Name, s.Id),
		TypeString:     fmt.Sprintf("contract %s", s.Name),
	}
}

func (s *SourceUnit[T]) GetImports() []*Import {
	toReturn := make([]*Import, 0)

	for _, node := range s.Nodes {
		if node.GetType() == ast_pb.NodeType_IMPORT_DIRECTIVE {
			toReturn = append(toReturn, node.(*Import))
		}
	}

	return toReturn
}

func (s *SourceUnit[T]) GetPragmas() []*Pragma {
	toReturn := make([]*Pragma, 0)

	for _, node := range s.Nodes {
		if node.GetType() == ast_pb.NodeType_PRAGMA_DIRECTIVE {
			toReturn = append(toReturn, node.(*Pragma))
		}
	}

	return toReturn
}

// ToProto converts the SourceUnit to a protocol buffer representation.
func (s *SourceUnit[T]) ToProto() NodeType {
	exportedSymbols := []*ast_pb.ExportedSymbol{}

	for _, symbol := range s.ExportedSymbols {
		exportedSymbols = append(
			exportedSymbols,
			&ast_pb.ExportedSymbol{
				Id:           symbol.GetId(),
				Name:         symbol.GetName(),
				AbsolutePath: symbol.GetAbsolutePath(),
			},
		)
	}

	nodes := []*v3.TypedStruct{}

	for _, node := range s.Nodes {
		nodes = append(nodes, node.ToProto().(*v3.TypedStruct))
	}

	return &ast_pb.SourceUnit{
		Id:              s.Id,
		License:         s.License,
		AbsolutePath:    s.AbsolutePath,
		Name:            s.Name,
		NodeType:        s.NodeType,
		Src:             s.GetSrc().ToProto(),
		ExportedSymbols: exportedSymbols,
		Root: &ast_pb.RootNode{
			Nodes: nodes,
		},
	}
}

func (s *SourceUnit[T]) UnmarshalJSON(data []byte) error {
	var tempMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &tempMap); err != nil {
		return err
	}

	if id, ok := tempMap["id"]; ok {
		if err := json.Unmarshal(id, &s.Id); err != nil {
			return err
		}
	}

	if nodeType, ok := tempMap["nodeType"]; ok {
		if err := json.Unmarshal(nodeType, &s.NodeType); err != nil {
			return err
		}
	}

	if license, ok := tempMap["license"]; ok {
		if err := json.Unmarshal(license, &s.License); err != nil {
			return err
		}
	}

	if absPath, ok := tempMap["absolutePath"]; ok {
		if err := json.Unmarshal(absPath, &s.AbsolutePath); err != nil {
			return err
		}
	}

	if name, ok := tempMap["name"]; ok {
		if err := json.Unmarshal(name, &s.Name); err != nil {
			return err
		}
	}

	if src, ok := tempMap["src"]; ok {
		if err := json.Unmarshal(src, &s.Src); err != nil {
			return err
		}
	}

	if expSym, ok := tempMap["exportedSymbols"]; ok {
		if err := json.Unmarshal(expSym, &s.ExportedSymbols); err != nil {
			return err
		}
	}

	if base, ok := tempMap["baseContracts"]; ok {
		if err := json.Unmarshal(base, &s.BaseContracts); err != nil {
			return err
		}
	}

	if members, ok := tempMap["nodes"]; ok {
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
			s.Nodes = append(s.Nodes, node)

			if node.GetType() == ast_pb.NodeType_CONTRACT_DEFINITION {
				s.Contract = node
			}
		}
	}

	return nil
}

// EnterSourceUnit is called when the ASTBuilder enters a source unit context.
// It initializes a new root node and source units based on the context.
func (b *ASTBuilder) EnterSourceUnit(ctx *parser.SourceUnitContext) {
	rootNode := NewRootNode(b, 0, b.sourceUnits, b.comments)
	b.tree.SetRoot(rootNode)

	for _, child := range ctx.GetChildren() {
		if interfaceCtx, ok := child.(*parser.InterfaceDefinitionContext); ok {
			license := getLicenseFromSources(b.sources, b.comments, interfaceCtx.Identifier().GetText())
			sourceUnit := NewSourceUnit[Node[ast_pb.SourceUnit]](b, interfaceCtx.Identifier().GetText(), license)
			sourceUnit.Kind = ast_pb.NodeType_KIND_INTERFACE
			interfaceNode := NewInterfaceDefinition(b)
			interfaceNode.Parse(ctx, interfaceCtx, rootNode, sourceUnit)
			//fmt.Println("Interface found...", interfaceCtx.Identifier().GetText())
			b.sourceUnits = append(b.sourceUnits, sourceUnit)
		}

		if libraryCtx, ok := child.(*parser.LibraryDefinitionContext); ok {
			license := getLicenseFromSources(b.sources, b.comments, libraryCtx.Identifier().GetText())
			sourceUnit := NewSourceUnit[Node[ast_pb.SourceUnit]](b, libraryCtx.Identifier().GetText(), license)
			sourceUnit.Kind = ast_pb.NodeType_KIND_LIBRARY
			libraryNode := NewLibraryDefinition(b)
			libraryNode.Parse(ctx, libraryCtx, rootNode, sourceUnit)
			//fmt.Println("Library found...", libraryCtx.Identifier().GetText())
			b.sourceUnits = append(b.sourceUnits, sourceUnit)
		}

		if contractCtx, ok := child.(*parser.ContractDefinitionContext); ok {
			license := getLicenseFromSources(b.sources, b.comments, contractCtx.Identifier().GetText())
			sourceUnit := NewSourceUnit[Node[ast_pb.SourceUnit]](b, contractCtx.Identifier().GetText(), license)
			sourceUnit.Kind = ast_pb.NodeType_KIND_CONTRACT
			contractNode := NewContractDefinition(b)
			contractNode.Parse(ctx, contractCtx, rootNode, sourceUnit)
			//fmt.Println("Contract found...", contractCtx.Identifier().GetText())
			b.sourceUnits = append(b.sourceUnits, sourceUnit)
		}
	}

	// Idea here is to basically set the source unit entry name as soon as we have parsed all of the classes.
	// Now this won't be possible always but nevertheless. (In rest of the cases, resolver will take care of it)
	if b.sources.EntrySourceUnitName != "" {
		for _, sourceUnit := range b.sourceUnits {
			if b.sources.EntrySourceUnitName == sourceUnit.GetName() {
				rootNode.SetEntrySourceUnit(sourceUnit.GetId())
				return
			}
		}
	}
}

// ExitSourceUnit is called when the ASTBuilder exits a source unit context.
// It appends the source units to the root node.
func (b *ASTBuilder) ExitSourceUnit(ctx *parser.SourceUnitContext) {
	b.tree.AppendRootNodes(b.sourceUnits...)
	b.tree.AppendGlobalNodes(b.globalDefinitions...)
}
