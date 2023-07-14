package ast

import (
	"fmt"
	"regexp"
	"strings"
)

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

func normalizeTypeName(typeName string) string {
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

func normalizeTypeDescription(typeName string) (string, string) {
	isArray, _ := regexp.MatchString(`\[\d+\]`, typeName)
	isSlice := strings.HasPrefix(typeName, "[]")

	switch {
	case isArray:
		numberPart := typeName[strings.Index(typeName, "[")+1 : strings.Index(typeName, "]")]
		typePart := typeName[strings.Index(typeName, "]")+1:]
		normalizedTypePart := normalizeTypeName(typePart)
		return "[" + numberPart + "]" + normalizedTypePart, fmt.Sprintf("t_%s_array", normalizedTypePart)

	case isSlice:
		typePart := typeName[2:]
		return "[]" + normalizeTypeName(typePart), fmt.Sprintf("t_%s_slice", normalizeTypeName(typePart))

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