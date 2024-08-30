package ast

import (
	"fmt"
	ast_pb "github.com/unpackdev/protos/dist/go/ast"
	"github.com/unpackdev/solgo/parser"
	"regexp"
	"strings"
)

// getLiterals extracts individual words from a given literal string.
func getLiterals(literal string) []string {
	// This regular expression matches sequences of word characters (letters, digits, underscores)
	// and sequences of non-word characters. It treats each match as a separate word.
	re := regexp.MustCompile(`\w+|\W+`)
	allLiterals := re.FindAllString(literal, -1)
	var literals []string
	for _, field := range allLiterals {
		field = strings.Trim(field, " ")
		if field != "" {
			// If the field is not empty after trimming spaces, add it to the literals
			literals = append(literals, field)
		}
	}
	return literals
}

// normalizeTypeName normalizes Solidity type names by handling array, slice, and common type variations.
func normalizeTypeName(typeName string) string {
	// Check if the type is an array.
	isArray, _ := regexp.MatchString(`\[\d+\]`, typeName)
	isSlice := strings.HasPrefix(typeName, "[]")

	switch {
	case isArray:
		numberPart := typeName[strings.Index(typeName, "[")+1 : strings.Index(typeName, "]")]
		typePart := typeName[strings.Index(typeName, "]")+1:]
		return "[" + numberPart + "]" + normalizeTypeName(typePart)

	case isSlice:
		typePart := typeName[2:]
		return "[]" + normalizeTypeName(typePart)

	case strings.HasPrefix(typeName, "uint"):
		if typeName == "uint" {
			return "uint256"
		}
		return typeName
	case strings.HasPrefix(typeName, "int"):
		if typeName == "int" {
			return "int256"
		}
		return typeName
	case strings.HasPrefix(typeName, "bool"):
		return typeName
	case strings.HasPrefix(typeName, "bytes"):
		return typeName
	case typeName == "string":
		return "string"
	case typeName == "address":
		return "address"
	case typeName == "addresspayable":
		return "address"
	case typeName == "tuple":
		return "tuple"
	default:
		return typeName
	}
}

// normalizeTypeDescription normalizes type names and generates corresponding type identifiers.
func normalizeTypeDescription(typeName string) (string, string) {
	isArray := strings.Contains(typeName, "[") && strings.Contains(typeName, "]")
	isSlice := strings.HasSuffix(typeName, "[]")
	isPrefixSlice := strings.HasPrefix(typeName, "[]")

	switch {
	case isArray:
		numberPart := typeName[strings.Index(typeName, "[")+1 : strings.Index(typeName, "]")]
		typePart := typeName[:strings.Index(typeName, "[")]
		normalizedTypePart := normalizeTypeName(typePart)
		return normalizedTypePart + "[" + numberPart + "]", fmt.Sprintf("t_%s_array", normalizedTypePart)

	case isSlice:
		typePart := typeName[:len(typeName)-2]
		normalizedTypePart := normalizeTypeName(typePart)
		return normalizedTypePart + "[]", fmt.Sprintf("t_%s_slice", normalizedTypePart)

	case isPrefixSlice:
		typePart := typeName[2:]
		normalizedTypePart := normalizeTypeName(typePart)
		return "[]" + normalizedTypePart, fmt.Sprintf("t_%s_slice", normalizedTypePart)

	case strings.HasPrefix(typeName, "uint"):
		if typeName == "uint" {
			return "uint256", "t_uint256"
		}
		return typeName, fmt.Sprintf("t_%s", typeName)

	case strings.HasPrefix(typeName, "int"):
		if typeName == "int" {
			return "int256", "t_int256"
		}
		return typeName, fmt.Sprintf("t_%s", typeName)

	case strings.HasPrefix(typeName, "bool"):
		return typeName, fmt.Sprintf("t_%s", typeName)

	case strings.HasPrefix(typeName, "bytes"):
		return typeName, fmt.Sprintf("t_%s", typeName)

	case typeName == "string":
		return "string", "t_string"

	case typeName == "address":
		return "address", "t_address"

	case typeName == "addresspayable":
		return "address", "t_address_payable"

	case typeName == "tuple":
		return "tuple", "t_tuple"

	default:
		return typeName, fmt.Sprintf("t_%s", typeName)
	}
}

// builtInTypePrefixes is a set of known built-in type prefixes.
var builtInTypePrefixes = []string{
	"uint",
	"int",
	"bool",
	"bytes",
	"string",
	"address",
	"addresspayable",
	"tuple",
}

// isBuiltInType checks if a type name is a built-in type by its prefix.
func isBuiltInType(typeName string) bool {
	for _, prefix := range builtInTypePrefixes {
		if strings.HasPrefix(typeName, prefix) {
			return true
		}
	}
	return false
}

// normalizeTypeDescriptionWithStatus normalizes type names and generates corresponding type identifiers.
// Returns true if normalization occurred.
func normalizeTypeDescriptionWithStatus(typeName string) (string, string, bool) {
	isArray := strings.Contains(typeName, "[") && strings.Contains(typeName, "]")
	isSlice := strings.HasSuffix(typeName, "[]")
	isPrefixSlice := strings.HasPrefix(typeName, "[]")

	switch {
	case isArray:
		numberPart := typeName[strings.Index(typeName, "[")+1 : strings.Index(typeName, "]")]
		typePart := typeName[:strings.Index(typeName, "[")]
		if !isBuiltInType(typePart) {
			return typeName, fmt.Sprintf("t_%s", typeName), false
		}
		normalizedTypePart := normalizeTypeName(typePart)
		return normalizedTypePart + "[" + numberPart + "]", fmt.Sprintf("t_%s_array", normalizedTypePart), true

	case isSlice:
		typePart := typeName[:len(typeName)-2]
		if !isBuiltInType(typePart) {
			return typeName, fmt.Sprintf("t_%s", typeName), false
		}
		normalizedTypePart := normalizeTypeName(typePart)
		return normalizedTypePart + "[]", fmt.Sprintf("t_%s_slice", normalizedTypePart), true

	case isPrefixSlice:
		typePart := typeName[2:]
		if !isBuiltInType(typePart) {
			return typeName, fmt.Sprintf("t_%s", typeName), false
		}
		normalizedTypePart := normalizeTypeName(typePart)
		return "[]" + normalizedTypePart, fmt.Sprintf("t_%s_slice", normalizedTypePart), true

	case strings.HasPrefix(typeName, "uint"):
		if typeName == "uint" {
			return "uint256", "t_uint256", true
		}
		return typeName, fmt.Sprintf("t_%s", typeName), true

	case strings.HasPrefix(typeName, "int"):
		if typeName == "int" {
			return "int256", "t_int256", true
		}
		return typeName, fmt.Sprintf("t_%s", typeName), true

	case strings.HasPrefix(typeName, "bool"):
		return typeName, fmt.Sprintf("t_%s", typeName), true

	case strings.HasPrefix(typeName, "bytes"):
		return typeName, fmt.Sprintf("t_%s", typeName), true

	case typeName == "string":
		return "string", "t_string", true

	case typeName == "address":
		return "address", "t_address", true

	case typeName == "addresspayable":
		return "address", "t_address_payable", true

	case typeName == "tuple":
		return "tuple", "t_tuple", true

	default:
		return typeName, fmt.Sprintf("t_%s", typeName), false
	}
}

// getStorageLocationFromDataLocationCtx extracts the storage location from the given data location context.
func getStorageLocationFromDataLocationCtx(ctx parser.IDataLocationContext) ast_pb.StorageLocation {
	if ctx != nil {
		if ctx.Memory() != nil {
			return ast_pb.StorageLocation_MEMORY
		} else if ctx.Storage() != nil {
			return ast_pb.StorageLocation_STORAGE
		} else if ctx.Calldata() != nil {
			return ast_pb.StorageLocation_CALLDATA
		}
	}
	return ast_pb.StorageLocation_DEFAULT
}

// ToNode takes a value of type T, which implements the Node interface,
// and returns the value along if casting was ok.
func ToNode[T any](node Node[NodeType]) (T, bool) {
	concreteNode, ok := node.(T)
	return concreteNode, ok
}
