package ast

import (
	"sync/atomic"

	ast_pb "github.com/txpull/protos/dist/go/ast"
	"github.com/txpull/solgo/parser"
)

func (b *ASTBuilder) parseBodyElement(sourceUnit *ast_pb.SourceUnit, identifierNode *ast_pb.Node, bodyElement parser.IContractBodyElementContext) *ast_pb.Node {
	id := atomic.AddInt64(&b.nextID, 1) - 1
	toReturn := &ast_pb.Node{
		Id: id,
		Src: &ast_pb.Src{
			Line:        int64(bodyElement.GetStart().GetLine()),
			Start:       int64(bodyElement.GetStart().GetStart()),
			End:         int64(bodyElement.GetStop().GetStop()),
			Length:      int64(bodyElement.GetStop().GetStop() - bodyElement.GetStart().GetStart() + 1),
			ParentIndex: identifierNode.Id,
		},
	}

	if usingForDeclaration := bodyElement.UsingDirective(); usingForDeclaration != nil {
		toReturn = b.parseUsingForDeclaration(
			sourceUnit,
			toReturn,
			usingForDeclaration.(*parser.UsingDirectiveContext),
		)
	} else if stateVariableDeclaration := bodyElement.StateVariableDeclaration(); stateVariableDeclaration != nil {
		toReturn = b.parseStateVariableDeclaration(
			sourceUnit,
			toReturn,
			stateVariableDeclaration.(*parser.StateVariableDeclarationContext),
		)
	} else if eventDefinition := bodyElement.EventDefinition(); eventDefinition != nil {
		toReturn = b.parseEventDefinition(
			sourceUnit,
			toReturn,
			eventDefinition.(*parser.EventDefinitionContext),
		)
	} else if functionDefinition := bodyElement.FunctionDefinition(); functionDefinition != nil {
		toReturn = b.parseFunctionDefinition(
			sourceUnit,
			toReturn,
			functionDefinition.(*parser.FunctionDefinitionContext),
		)
	} else if constructorDefinition := bodyElement.ConstructorDefinition(); constructorDefinition != nil {
		panic("Constructor definition....")
	} else if modifierDefinition := bodyElement.ModifierDefinition(); modifierDefinition != nil {
		panic("Modifier definition....")
	} else if fallbackFunctionDefinition := bodyElement.FallbackFunctionDefinition(); fallbackFunctionDefinition != nil {
		panic("Fallback function definition....")
	} else if receiveFunctionDefinition := bodyElement.ReceiveFunctionDefinition(); receiveFunctionDefinition != nil {
		panic("Receive function definition....")
	} else if structDefinition := bodyElement.StructDefinition(); structDefinition != nil {
		panic("Struct definition....")
	} else if enumDefinition := bodyElement.EnumDefinition(); enumDefinition != nil {
		panic("Enum definition....")
	} else {
		panic("Another type of body element that needs to be parsed...")
	}

	return toReturn
}
