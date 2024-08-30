package abi

import (
	ast_pb "github.com/unpackdev/protos/dist/go/ast"
	"strings"

	"github.com/unpackdev/solgo/ast"
	"github.com/unpackdev/solgo/ir"
	"github.com/unpackdev/solgo/utils"
)

// Type represents a type within the Ethereum ABI.
type Type struct {
	Name         string
	Type         string
	InternalType string
	Outputs      []Type
	Components   []MethodIO
}

// TypeResolver provides methods to resolve and discover types within the ABI.
type TypeResolver struct {
	parser         *ir.Builder
	processedTypes map[string]bool
}

// ResolveType determines the type of a given typeName based on its identifier.
// It returns a string representation of the type.
func (t *TypeResolver) ResolveType(typeName *ast.TypeDescription) string {
	if strings.HasPrefix(typeName.GetIdentifier(), "t_mapping") {
		return "mapping"
	}

	if strings.HasPrefix(typeName.GetIdentifier(), "t_struct") {
		return "struct"
	}

	if strings.HasPrefix(typeName.GetIdentifier(), "t_contract") {
		return "contract"
	}

	if strings.HasPrefix(typeName.GetIdentifier(), "t_enum") {
		return "enum"
	}

	if strings.HasPrefix(typeName.GetIdentifier(), "t_error") {
		return "error"
	}

	return normalizeTypeName(typeName.GetString())
}

// ResolveMappingType resolves the input and output types for a given mapping type.
// It returns slices of MethodIO for inputs and outputs respectively.
func (t *TypeResolver) ResolveMappingType(typeName *ast.TypeDescription) ([]MethodIO, []MethodIO) {
	inputs := make([]MethodIO, 0)
	outputs := make([]MethodIO, 0)
	matched, inputList, outputList := parseMappingType(typeName.GetString())

	if matched {
		for _, input := range inputList {
			dType := t.discoverType(input)
			inputs = append(inputs, MethodIO{
				Name:         dType.Name,
				Type:         dType.Type,
				InternalType: dType.InternalType,
			})
		}

		for _, output := range outputList {
			dType := t.discoverType(output)
			if len(dType.Outputs) > 0 {
				for _, out := range dType.Outputs {
					outputs = append(outputs, MethodIO{
						Name:         out.Name,
						Type:         out.Type,
						InternalType: out.InternalType,
					})
				}
			} else {
				outputs = append(outputs, MethodIO{
					Name:         dType.Name,
					Type:         dType.Type,
					InternalType: dType.InternalType,
				})
			}
		}
	}

	return inputs, outputs
}

// ResolveStructType resolves the type of a given struct and returns its MethodIO representation.
func (t *TypeResolver) ResolveStructType(typeName *ast.TypeDescription) MethodIO {
	nameCleaned := strings.Replace(typeName.GetString(), "struct ", "", -1)
	nameCleaned = strings.TrimLeft(nameCleaned, "[]")
	nameCleaned = strings.TrimRight(nameCleaned, "[]")
	nameParts := strings.Split(nameCleaned, ".")

	methodType := "tuple"
	if strings.Contains(typeName.GetString(), "[]") {
		methodType = "tuple[]"
	}

	toReturn := MethodIO{
		Name:         nameParts[1],
		Components:   make([]MethodIO, 0),
		Type:         methodType,
		InternalType: typeName.GetString(),
	}

	for _, contract := range t.parser.GetRoot().GetContracts() {
		for _, structVar := range contract.GetStructs() {
			if structVar.GetName() == toReturn.Name {
				for _, member := range structVar.GetMembers() {
					// Mapping types are not supported in structs
					if isMappingType(member.GetTypeDescription().GetString()) {
						continue
					}

					if isContractType(member.GetTypeDescription().GetString()) {
						toReturn.Outputs = append(toReturn.Outputs, MethodIO{
							Name:         member.GetName(),
							Type:         "address",
							InternalType: member.GetTypeDescription().GetString(),
						})

						continue
					}

					dType := t.discoverType(member.GetTypeDescription().GetString())
					if len(dType.Outputs) > 0 {
						for _, out := range dType.Outputs {
							toReturn.Components = append(toReturn.Components, MethodIO{
								Name:         out.Name,
								Type:         out.Type,
								InternalType: member.GetTypeDescription().GetString(),
							})
						}
					} else {
						toReturn.Components = append(toReturn.Components, MethodIO{
							Name:         member.GetName(),
							Type:         dType.Type,
							InternalType: member.GetTypeDescription().GetString(),
						})
					}
				}
			}
		}
	}

	// We did not discover any structs in the contracts themselves... Apparently this is a global
	// struct definition...
	if len(toReturn.Components) == 0 {
		for _, node := range t.parser.GetAstBuilder().GetRoot().GetGlobalNodes() {
			if node.GetType() == ast_pb.NodeType_STRUCT_DEFINITION {
				if structVar, ok := node.(*ast.StructDefinition); ok {
					if structVar.GetName() == toReturn.Name {
						for _, member := range structVar.GetMembers() {
							// Mapping types are not supported in structs
							if isMappingType(member.GetTypeDescription().GetString()) {
								continue
							}

							if isContractType(member.GetTypeDescription().GetString()) {
								toReturn.Outputs = append(toReturn.Outputs, MethodIO{
									Name:         member.GetName(),
									Type:         "address",
									InternalType: member.GetTypeDescription().GetString(),
								})

								continue
							}

							dType := t.discoverType(member.GetTypeDescription().GetString())
							if len(dType.Outputs) > 0 {
								for _, out := range dType.Outputs {
									toReturn.Components = append(toReturn.Components, MethodIO{
										Name:         out.Name,
										Type:         out.Type,
										InternalType: member.GetTypeDescription().GetString(),
									})
								}
							} else {
								toReturn.Components = append(toReturn.Components, MethodIO{
									Name:         member.GetName(),
									Type:         dType.Type,
									InternalType: member.GetTypeDescription().GetString(),
								})
							}
						}
					}
				}
			}
		}
	}

	return toReturn
}

// discoverType determines the type of a given typeName.
// It searches through the contracts and their structs to find a matching type.
// Returns a Type representation of the discovered type.
// @WARN: This function will probably need more work to handle more complex types.
func (t *TypeResolver) discoverType(typeName string) Type {
	if t.processedTypes == nil {
		t.processedTypes = make(map[string]bool)
	}

	// Check if type has already been processed to avoid recursion
	if _, exists := t.processedTypes[typeName]; exists {
		return Type{} // Return an empty Type to break recursion
	}

	// Mark this type as processed
	t.processedTypes[typeName] = true

	defer func() {
		// Before returning, mark this type as not processed for future calls
		delete(t.processedTypes, typeName)
	}()

	toReturn := Type{
		Outputs: make([]Type, 0),
	}

	normalization := utils.NewNormalizeType().Normalize(typeName)
	if normalization.Normalized {
		toReturn.Type = normalization.TypeName
		toReturn.InternalType = normalization.TypeName
		return toReturn
	} else {
		typeName = strings.ReplaceAll(typeName, "[]", "")

		typeNameParts := strings.Split(typeName, ".")
		if len(typeNameParts) > 1 {
			typeName = typeNameParts[1]
		}

		for _, contract := range t.parser.GetRoot().GetContracts() {
			if contract.GetName() == typeName {
				toReturn.Outputs = append(toReturn.Outputs, Type{
					Name:         contract.GetName(),
					Type:         "address",
					InternalType: contract.GetName(),
				})
				return toReturn
			}

			for _, enumVar := range contract.GetEnums() {
				if enumVar.GetName() == typeName {
					toReturn.Outputs = append(toReturn.Outputs, Type{
						Name:         enumVar.GetName(),
						Type:         "uint8",
						InternalType: enumVar.GetAST().GetTypeDescription().GetString(),
					})
					return toReturn
				}
			}

			for _, structVar := range contract.GetStructs() {
				if structVar.GetName() == typeName {
					for _, member := range structVar.GetMembers() {
						if isMappingType(member.GetTypeDescription().GetString()) {
							in, out := t.ResolveMappingType(member.GetTypeDescription())
							for _, in := range in {
								toReturn.Outputs = append(toReturn.Outputs, Type{
									Name:         in.Name,
									Type:         in.Type,
									InternalType: in.InternalType,
								})
							}

							for _, out := range out {
								toReturn.Outputs = append(toReturn.Outputs, Type{
									Name:         out.Name,
									Type:         out.Type,
									InternalType: out.InternalType,
								})
							}

							continue
						}

						if isContractType(member.GetTypeDescription().GetString()) {
							toReturn.Outputs = append(toReturn.Outputs, Type{
								Name:         member.GetName(),
								Type:         "address",
								InternalType: member.GetTypeDescription().GetString(),
							})

							continue
						}

						if isStructType(member.GetTypeDescription().GetString()) {
							// Recursively resolve the nested struct
							nestedStructType := t.ResolveStructType(member.GetTypeDescription())
							toReturn.Outputs = append(toReturn.Outputs, Type{
								Name:         member.GetName(),
								Type:         "tuple",
								InternalType: member.GetTypeDescription().GetString(),
								Components:   nestedStructType.Components,
							})

							continue
						}

						if isEnumType(member.GetTypeDescription().GetString()) {
							toReturn.Outputs = append(toReturn.Outputs, Type{
								Name:         member.GetName(),
								Type:         "uint8",
								InternalType: member.GetTypeDescription().GetString(),
							})
							continue
						}

						toReturn.Outputs = append(toReturn.Outputs, Type{
							Name:         member.GetName(),
							Type:         normalizeTypeName(member.GetTypeDescription().GetString()),
							InternalType: member.GetTypeDescription().GetString(),
						})
					}
					return toReturn
				}
			}
		}

		for _, node := range t.parser.GetRoot().GetAST().GetGlobalNodes() {
			switch nodeCtx := node.(type) {
			case *ast.EnumDefinition:
				if nodeCtx.GetName() == typeName {
					toReturn.Outputs = append(toReturn.Outputs, Type{
						Name:         nodeCtx.GetName(),
						Type:         "uint8",
						InternalType: nodeCtx.GetTypeDescription().GetString(),
					})
					return toReturn
				}
			case *ast.StructDefinition:
				if nodeCtx.GetName() == typeName {
					for _, member := range nodeCtx.GetMembers() {
						if isMappingType(member.GetTypeDescription().GetString()) {
							in, out := t.ResolveMappingType(member.GetTypeDescription())

							for _, in := range in {
								toReturn.Outputs = append(toReturn.Outputs, Type{
									Name:         in.Name,
									Type:         in.Type,
									InternalType: in.InternalType,
								})
							}

							for _, out := range out {
								toReturn.Outputs = append(toReturn.Outputs, Type{
									Name:         out.Name,
									Type:         out.Type,
									InternalType: out.InternalType,
								})
							}

							continue
						}

						if isContractType(member.GetTypeDescription().GetString()) {
							toReturn.Outputs = append(toReturn.Outputs, Type{
								Name:         member.GetName(),
								Type:         "address",
								InternalType: member.GetTypeDescription().GetString(),
							})

							continue
						}

						if isStructType(member.GetTypeDescription().GetString()) {
							// Recursively resolve the nested struct
							nestedStructType := t.ResolveStructType(member.GetTypeDescription())
							toReturn.Outputs = append(toReturn.Outputs, Type{
								Name:         member.GetName(),
								Type:         "tuple",
								InternalType: member.GetTypeDescription().GetString(),
								Components:   nestedStructType.Components,
							})

							continue
						}

						if isEnumType(member.GetTypeDescription().GetString()) {
							toReturn.Outputs = append(toReturn.Outputs, Type{
								Name:         member.GetName(),
								Type:         "uint8",
								InternalType: member.GetTypeDescription().GetString(),
							})
							continue
						}

						toReturn.Outputs = append(toReturn.Outputs, Type{
							Name:         member.GetName(),
							Type:         normalizeTypeName(member.GetTypeDescription().GetString()),
							InternalType: member.GetTypeDescription().GetString(),
						})
					}
					return toReturn
				}
			}
		}

	}

	return toReturn
}
