package ast

import (
	"fmt"
	"path/filepath"
	"strings"

	ast_pb "github.com/unpackdev/protos/dist/go/ast"
	"github.com/unpackdev/solgo/parser"
)

// Import represents an import node in the abstract syntax tree.
type Import struct {
	Id           int64           `json:"id"`                     // Unique identifier of the import node.
	NodeType     ast_pb.NodeType `json:"nodeType"`               // Type of the node.
	Src          SrcNode         `json:"src"`                    // Source location information.
	NameLocation *SrcNode        `json:"nameLocation,omitempty"` // Source location information of the name.
	AbsolutePath string          `json:"absolutePath"`           // Absolute path of the imported file.
	File         string          `json:"file"`                   // Filepath of the import statement.
	Scope        int64           `json:"scope"`                  // Scope of the import.
	UnitAlias    string          `json:"unitAlias"`              // Alias of the imported unit.
	As           string          `json:"as"`                     // Alias of the imported unit.
	UnitAliases  []string        `json:"unitAliases"`            // Alias of the imported unit.
	SourceUnit   int64           `json:"sourceUnit"`             // Source unit identifier.
}

// SetReferenceDescriptor sets the reference descriptions of the Import node.
func (i *Import) SetReferenceDescriptor(refId int64, refDesc *TypeDescription) bool {
	// This function sets the source unit of the import in the resolver as a forward declaration hack.
	if refId > 0 && refDesc == nil {
		i.SourceUnit = refId
		return true
	}
	return false
}

// GetId returns the unique identifier of the import node.
func (i *Import) GetId() int64 {
	return i.Id
}

// GetType returns the type of the node.
func (i *Import) GetType() ast_pb.NodeType {
	return i.NodeType
}

// GetSrc returns the source location information of the import node.
func (i *Import) GetSrc() SrcNode {
	return i.Src
}

// GetNameLocation returns the source location information of the name of the import node.
func (i *Import) GetNameLocation() *SrcNode {
	return i.NameLocation
}

// GetTypeDescription returns the type description of the import node.
func (i *Import) GetTypeDescription() *TypeDescription {
	return &TypeDescription{
		TypeString:     "import",
		TypeIdentifier: fmt.Sprintf("$_t_import_%s_%d", i.AbsolutePath, i.Id),
	}
}

// GetAbsolutePath returns the absolute path of the imported file.
func (i *Import) GetAbsolutePath() string {
	return i.AbsolutePath
}

// GetFile returns the filepath of the import statement.
func (i *Import) GetFile() string {
	return i.File
}

// GetScope returns the scope of the import.
func (i *Import) GetScope() int64 {
	return i.Scope
}

// GetUnitAlias returns the alias of the imported unit.
func (i *Import) GetUnitAlias() string {
	return i.UnitAlias
}

// GetSourceUnit returns the source unit identifier of the import.
func (i *Import) GetSourceUnit() int64 {
	return i.SourceUnit
}

// GetNodes returns an empty slice of nodes associated with the import.
func (i *Import) GetNodes() []Node[NodeType] {
	return []Node[NodeType]{}
}

// GetName returns the name of the imported file (excluding extension).
func (i *Import) GetName() string {
	base := filepath.Base(i.AbsolutePath)
	ext := filepath.Ext(base)
	return strings.TrimSuffix(base, ext)
}

// GetUnitAliases returns the aliases of the imported unit.
func (i *Import) GetUnitAliases() []string {
	return i.UnitAliases
}

// GetAs returns the alias of the imported unit.
func (i *Import) GetAs() string {
	return i.As
}

// ToProto converts the Import node to its corresponding protobuf representation.
func (i *Import) ToProto() NodeType {
	proto := ast_pb.Import{
		Id:           i.GetId(),
		NodeType:     i.GetType(),
		Src:          i.GetSrc().ToProto(),
		AbsolutePath: i.GetAbsolutePath(),
		File:         i.GetFile(),
		Scope:        i.GetScope(),
		UnitAlias:    i.GetUnitAlias(),
		SourceUnit:   i.GetSourceUnit(),
		As:           i.GetAs(),
		UnitAliases:  i.GetUnitAliases(),
	}

	if i.GetNameLocation() != nil {
		proto.NameLocation = i.GetNameLocation().ToProto()
	}

	return NewTypedStruct(&proto, "Import")
}

// parseImportPathsForSourceUnit is a utility function for parsing import paths within a source unit.
// It returns a slice of Import nodes corresponding to the imported paths.
func parseImportPathsForSourceUnit(
	b *ASTBuilder,
	unitCtx *parser.SourceUnitContext,
	unit *SourceUnit[Node[ast_pb.SourceUnit]],
	libraryCtx *parser.LibraryDefinitionContext,
	contractCtx *parser.ContractDefinitionContext,
	interfaceCtx *parser.InterfaceDefinitionContext,
) []Node[NodeType] {
	imports := make([]*Import, 0)

	contractLine := func() int64 {
		if libraryCtx != nil {
			return int64(libraryCtx.GetStart().GetLine())
		} else if contractCtx != nil {
			return int64(contractCtx.GetStart().GetLine())
		} else if interfaceCtx != nil {
			return int64(interfaceCtx.GetStart().GetLine())
		}
		return 0
	}()

	// Traverse the children of the source unit until the contract definition is found
	for _, child := range unitCtx.GetChildren() {
		if libraryCtx != nil && child == libraryCtx {
			// Found the library definition, stop traversing
			break
		}

		if contractCtx != nil && child == contractCtx {
			// Found the contract definition, stop traversing
			break
		}

		if importCtx, ok := child.(*parser.ImportDirectiveContext); ok {
			importNodeId := b.GetNextID()
			importNode := &Import{
				Id:       importNodeId,
				NodeType: ast_pb.NodeType_IMPORT_DIRECTIVE,
				Src: SrcNode{
					Line:        int64(importCtx.GetStart().GetLine()),
					Column:      int64(importCtx.GetStart().GetColumn()),
					Start:       int64(importCtx.GetStart().GetStart()),
					End:         int64(importCtx.GetStop().GetStop()),
					Length:      int64(importCtx.GetStop().GetStop() - importCtx.GetStart().GetStart() + 1),
					ParentIndex: unit.Id,
				},
				AbsolutePath: func() string {
					path := filepath.Clean(importCtx.Path().GetText())
					toReturn := filepath.Base(path)
					toReturn = strings.ReplaceAll(toReturn, "\"", "")
					toReturn = strings.ReplaceAll(toReturn, "'", "")
					return toReturn
				}(),
				File: func() string {
					toReturn := filepath.Clean(importCtx.Path().GetText())
					toReturn = strings.ReplaceAll(toReturn, "\"", "")
					toReturn = strings.ReplaceAll(toReturn, "'", "")
					return toReturn
				}(),
				Scope:       unit.Id,
				UnitAliases: make([]string, 0),
			}

			if importCtx.Identifier() != nil {
				importNode.NameLocation = &SrcNode{
					Line:        int64(importCtx.Identifier().GetStart().GetLine()),
					Column:      int64(importCtx.Identifier().GetStart().GetColumn()),
					Start:       int64(importCtx.Identifier().GetStart().GetStart()),
					End:         int64(importCtx.Identifier().GetStop().GetStop()),
					Length:      int64(importCtx.Identifier().GetStop().GetStop() - importCtx.Identifier().GetStart().GetStart() + 1),
					ParentIndex: importNodeId,
				}
			}

			if importCtx.GetUnitAlias() != nil {
				importNode.UnitAlias = importCtx.GetUnitAlias().GetText()
			}

			if importCtx.As() != nil {
				importNode.As = importCtx.As().GetText()
			}

			if importCtx.SymbolAliases() != nil {
				for _, aliasCtx := range importCtx.SymbolAliases().AllImportAliases() {
					if aliasCtx.GetAlias() != nil {
						importNode.UnitAliases = append(importNode.UnitAliases, aliasCtx.GetAlias().GetText())
					}
				}
			}

			imports = append(imports, importNode)
		}
	}

	filteredImports := make([]Node[NodeType], 0)
	exportedSymbolMap := make(map[string]struct{}) // To track already added symbols

	for i := len(imports) - 1; i >= 0; i-- {
		importNode := imports[i]
		if contractLine-importNode.Src.Line <= 50 && contractLine-importNode.Src.Line >= -1 {
			importNode.Src.ParentIndex = unit.Id
			for _, unitCtx := range b.sourceUnits {
				for _, symbol := range unitCtx.ExportedSymbols {
					if symbol.AbsolutePath == importNode.AbsolutePath {
						if _, exists := exportedSymbolMap[symbol.AbsolutePath]; !exists {
							unit.ExportedSymbols = append(
								unit.ExportedSymbols,
								NewSymbol(symbol.Id, symbol.Name, symbol.AbsolutePath),
							)
							exportedSymbolMap[symbol.AbsolutePath] = struct{}{}
						}
					}
				}
			}
			filteredImports = append([]Node[NodeType]{importNode}, filteredImports...)
		}
	}

	b.currentImports = append(b.currentImports, filteredImports...)
	return filteredImports
}
