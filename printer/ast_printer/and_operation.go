package ast_printer

import (
	"strings"

	"github.com/unpackdev/solgo/ast"
)

func printAndOperation(node *ast.AndOperation, sb *strings.Builder, depth int) bool {
	expressions := []string{}
	success := true
	for _, exp := range node.GetExpressions() {
		s, ok := Print(exp)
		success = ok && success
		expressions = append(expressions, s)
	}
	writeSeperatedList(sb, " && ", expressions)
	return success
}
