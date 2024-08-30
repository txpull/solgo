package ast

import (
	"fmt"
	ast_pb "github.com/unpackdev/protos/dist/go/ast"
	"math"
	"strconv"
	"strings"
)

// StorageSize calculates and returns the storage size requirement of the type represented by
// the TypeName instance, in bits. It also returns a boolean indicating whether the size calculation
// is exact or an approximation. The function covers elementary types, mappings, function types,
// user-defined types, and identifiers, with special handling for each category.
func (t *TypeName) StorageSize() (int64, bool) {
	switch t.NodeType {
	case ast_pb.NodeType_ELEMENTARY_TYPE_NAME:
		// Handle elementary types (int, uint, etc.)
		return elementaryTypeSizeInBits(t.Name)

	case ast_pb.NodeType_MAPPING_TYPE_NAME:
		// Mappings in Solidity are implemented as a hash table.
		// Since they don't occupy a fixed amount of space in a contract's storage,
		// it's not straightforward to define their size in bits.
		// This might be represented as a pointer size.
		return 256, true

	case ast_pb.NodeType_FUNCTION_TYPE_NAME:
		// Function types in Solidity represent external function pointers and typically take up 24 bytes.
		// Converting this size into bits.
		return 24 * 8, true

	case ast_pb.NodeType_USER_DEFINED_PATH_NAME:
		if size, found := elementaryTypeSizeInBits(t.Name); found {
			return size, true
		}

		return 256, true

	case ast_pb.NodeType_IDENTIFIER:
		if size, found := elementaryTypeSizeInBits(t.Name); found {
			return size, true
		}

		if identifier, ok := t.Expression.(*PrimaryExpression); ok {
			if len(identifier.GetValue()) > 0 {
				return 256, true
			}
		}

		// For now this is a major hack...
		if strings.Contains(t.GetTypeDescription().GetString(), "struct") {
			return 256, true
		}

		if strings.Contains(t.GetTypeDescription().GetString(), "int_const") {
			rationalParts := strings.Split(t.GetTypeDescription().GetIdentifier(), "_by_")
			if len(rationalParts) == 2 {
				numerator, err1 := strconv.Atoi(strings.Replace(rationalParts[0], "t_rational_", "", -1))
				denominator, err2 := strconv.Atoi(rationalParts[1])
				if err1 == nil && err2 == nil {
					bitSize := int64(math.Ceil(math.Log2(float64(numerator / denominator))))
					return bitSize, true
				}
			}
		}

		return 0, false

	// Add cases for other node types like struct, enum, etc., as needed.
	default:
		panic(fmt.Sprintf("Unhandled node type @ StorageSize: %s", t.NodeType))
		return 0, false // Type not recognized or not handled yet.
	}
}

// elementaryTypeSizeInBits returns the storage size, in bits, for elementary types like `int`, `uint`, etc.,
// based on the type's name. It leverages getTypeSizeInBits to find the size. If the type is not recognized,
// it returns 0 and false.
func elementaryTypeSizeInBits(typeName string) (int64, bool) {
	size, found := getTypeSizeInBits(typeName)
	if !found {
		return 0, false // Type not recognized
	}

	return size, true
}

// getTypeSizeInBits calculates the storage size, in bits, for a given type name.
// It covers special cases for types like `bool`, `address`, `int`/`uint` with specific sizes,
// `bytes` with a fixed size, and dynamically sized types like `string` and `bytes`.
// Returns the size and a boolean indicating if the type is recognized.
func getTypeSizeInBits(typeName string) (int64, bool) {
	// Handle array types
	if strings.HasSuffix(typeName, "[]") {
		elementType := strings.TrimSuffix(typeName, "[]")
		elementSize, ok := getTypeSizeInBits(elementType)
		if !ok {
			return 0, false
		}
		// For dynamic arrays, the size in bits depends on the actual content
		// and includes the overhead for array length (256 bits).
		return elementSize + 256, true
	}

	switch {
	case typeName == "bool":
		return 8, true
	case typeName == "address" || typeName == "addresspayable" || strings.HasPrefix("contract", typeName):
		return 160, true
	case strings.HasPrefix(typeName, "int") || strings.HasPrefix(typeName, "uint"):
		if typeName == "uint" || typeName == "int" {
			return 256, true
		}

		bitSizeStr := strings.TrimPrefix(typeName, "int")
		bitSizeStr = strings.TrimPrefix(bitSizeStr, "uint")
		bitSize, err := strconv.Atoi(bitSizeStr)

		if err != nil || bitSize < 8 || bitSize > 256 || bitSize%8 != 0 {
			return 0, false // Invalid size
		}

		return int64(bitSize), true
	case typeName == "string":
		// Dynamic-size types; the size depends on the actual content.
		// It's hard to determine the exact size in bits without the content.
		// Returning a default size for the pointer.
		return 256, true
	case typeName == "bytes":
		// Dynamic-size types; the size depends on the actual content.
		// It's hard to determine the exact size in bits without the content.
		// Returning a default size for the pointer.
		return 256, true
	case strings.HasPrefix(typeName, "bytes"):
		byteSizeStr := strings.TrimPrefix(typeName, "bytes")
		if byteSizeStr == "" {
			return 0, false // Dynamic-sized bytes array, which is not supported
		}
		byteSize, err := strconv.Atoi(byteSizeStr)
		if err != nil || byteSize < 1 || byteSize > 32 {
			return 0, false
		}
		return int64(byteSize) * 8, true

	default:
		return 0, false // Type not recognized
	}
}
