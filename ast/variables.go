package ast

import (
	"sync/atomic"

	ast_pb "github.com/txpull/protos/dist/go/ast"
	"github.com/txpull/solgo/parser"
)

func (b *ASTBuilder) traverseVariableDeclaration(node *ast_pb.Node, bodyNode *ast_pb.Body, statementNode *ast_pb.Statement, variableCtx *parser.VariableDeclarationStatementContext) *ast_pb.Statement {
	declarationCtx := variableCtx.VariableDeclaration()
	identifierCtx := declarationCtx.Identifier()

	declaration := &ast_pb.Declaration{
		Id: atomic.AddInt64(&b.nextID, 1) - 1,
		Src: &ast_pb.Src{
			Line:        int64(declarationCtx.GetStart().GetLine()),
			Column:      int64(declarationCtx.GetStart().GetColumn()),
			Start:       int64(declarationCtx.GetStart().GetStart()),
			End:         int64(declarationCtx.GetStop().GetStop()),
			Length:      int64(declarationCtx.GetStop().GetStop() - declarationCtx.GetStart().GetStart() + 1),
			ParentIndex: statementNode.Id,
		},
		Name:            identifierCtx.GetText(),
		Mutability:      ast_pb.Mutability_MUTABLE,
		NodeType:        ast_pb.NodeType_VARIABLE_DECLARATION,
		Scope:           bodyNode.Id,
		StorageLocation: ast_pb.StorageLocation_DEFAULT,
		Visibility:      ast_pb.Visibility_INTERNAL,
	}
	statementNode.Declarations = append(statementNode.Declarations, declaration)
	statementNode.Assignments = append(statementNode.Assignments, declaration.Id)

	if declarationCtx.DataLocation() != nil {
		if declarationCtx.DataLocation().Memory() != nil {
			declaration.StorageLocation = ast_pb.StorageLocation_MEMORY
		} else if declarationCtx.DataLocation().Storage() != nil {
			declaration.StorageLocation = ast_pb.StorageLocation_STORAGE
		} else if declarationCtx.DataLocation().Calldata() != nil {
			declaration.StorageLocation = ast_pb.StorageLocation_CALLDATA
		}
	}

	typeCtx := declarationCtx.GetType_().ElementaryTypeName()
	normalizedTypeName, normalizedTypeIdentifier := normalizeTypeDescription(
		typeCtx.GetText(),
	)

	declaration.TypeName = &ast_pb.TypeName{
		Id:   atomic.AddInt64(&b.nextID, 1) - 1,
		Name: typeCtx.GetText(),
		Src: &ast_pb.Src{
			Line:        int64(typeCtx.GetStart().GetLine()),
			Column:      int64(typeCtx.GetStart().GetColumn()),
			Start:       int64(typeCtx.GetStart().GetStart()),
			End:         int64(typeCtx.GetStop().GetStop()),
			Length:      int64(typeCtx.GetStop().GetStop() - typeCtx.GetStart().GetStart() + 1),
			ParentIndex: statementNode.Id,
		},
		NodeType: ast_pb.NodeType_ELEMENTARY_TYPE_NAME,
		TypeDescriptions: &ast_pb.TypeDescriptions{
			TypeIdentifier: normalizedTypeIdentifier,
			TypeString:     normalizedTypeName,
		},
	}

	if variableCtx.VariableDeclarationTuple() != nil {
		panic("Tuple is fucking finally not nil...")
	}

	expressionCtx := variableCtx.Expression()

	initialValue := &ast_pb.InitialValue{
		Id: atomic.AddInt64(&b.nextID, 1) - 1,
		Src: &ast_pb.Src{
			Line:        int64(expressionCtx.GetStart().GetLine()),
			Column:      int64(expressionCtx.GetStart().GetColumn()),
			Start:       int64(expressionCtx.GetStart().GetStart()),
			End:         int64(expressionCtx.GetStop().GetStop()),
			Length:      int64(expressionCtx.GetStop().GetStop() - expressionCtx.GetStart().GetStart() + 1),
			ParentIndex: declaration.Id,
		},
		CommonType: &ast_pb.TypeDescriptions{
			TypeIdentifier: normalizedTypeIdentifier,
			TypeString:     normalizedTypeName,
		},
		TypeDescriptions: &ast_pb.TypeDescriptions{
			TypeIdentifier: normalizedTypeIdentifier,
			TypeString:     normalizedTypeName,
		},
		IsConstant:      false, // @TODO
		IsLValue:        false, // @TODO
		IsPure:          false, // @TODO
		LValueRequested: false, // @TODO
	}

	switch variableCtx.Expression().(type) {
	case *parser.AddSubOperationContext:
		childCtx := variableCtx.Expression().(*parser.AddSubOperationContext)
		initialValue.NodeType = ast_pb.NodeType_BINARY_OPERATION
		initialValue.Operator = ast_pb.Operator_ADDITION

		operatorCtx := childCtx.AllExpression()
		if len(operatorCtx) != 2 {
			panic("Expected two operands for binary operation...")
		}

		leftHandExpressionCtx := operatorCtx[0]
		rightHandExpressionCtx := operatorCtx[1]

		leftHandExpression := &ast_pb.Expression{
			Id: atomic.AddInt64(&b.nextID, 1) - 1,
			Src: &ast_pb.Src{
				Line:        int64(leftHandExpressionCtx.GetStart().GetLine()),
				Column:      int64(leftHandExpressionCtx.GetStart().GetColumn()),
				Start:       int64(leftHandExpressionCtx.GetStart().GetStart()),
				End:         int64(leftHandExpressionCtx.GetStop().GetStop()),
				Length:      int64(leftHandExpressionCtx.GetStop().GetStop() - leftHandExpressionCtx.GetStart().GetStart() + 1),
				ParentIndex: initialValue.Id,
			},
			Name:                   leftHandExpressionCtx.GetText(),
			NodeType:               ast_pb.NodeType_IDENTIFIER,
			OverloadedDeclarations: []int64{},
		}

		for _, parameter := range node.Parameters.GetParameters() {
			if parameter.Name == leftHandExpressionCtx.GetText() {
				leftHandExpression.ReferencedDeclaration = parameter.Id
				leftHandExpression.TypeDescriptions = parameter.GetTypeName().GetTypeDescriptions()
			}
		}

		rightHandExpression := &ast_pb.Expression{
			Id: atomic.AddInt64(&b.nextID, 1) - 1,
			Src: &ast_pb.Src{
				Line:        int64(rightHandExpressionCtx.GetStart().GetLine()),
				Column:      int64(rightHandExpressionCtx.GetStart().GetColumn()),
				Start:       int64(rightHandExpressionCtx.GetStart().GetStart()),
				End:         int64(rightHandExpressionCtx.GetStop().GetStop()),
				Length:      int64(rightHandExpressionCtx.GetStop().GetStop() - rightHandExpressionCtx.GetStart().GetStart() + 1),
				ParentIndex: initialValue.Id,
			},
			Name:     rightHandExpressionCtx.GetText(),
			NodeType: ast_pb.NodeType_IDENTIFIER,
		}

		for _, parameter := range node.Parameters.GetParameters() {
			if parameter.Name == rightHandExpressionCtx.GetText() {
				rightHandExpression.ReferencedDeclaration = parameter.Id
				rightHandExpression.TypeDescriptions = parameter.GetTypeName().GetTypeDescriptions()
			}
		}

		initialValue.LeftExpression = leftHandExpression
		initialValue.RightExpression = rightHandExpression
	}

	statementNode.InitialValue = initialValue

	return statementNode
}