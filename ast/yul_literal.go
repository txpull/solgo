package ast

import (
	"encoding/hex"
	"fmt"
	"strings"

	ast_pb "github.com/unpackdev/protos/dist/go/ast"
	"github.com/unpackdev/solgo/parser"
)

type YulLiteralStatement struct {
	*ASTBuilder

	Id       int64           `json:"id"`
	NodeType ast_pb.NodeType `json:"node_type"`
	Kind     ast_pb.NodeType `json:"kind"`
	Src      SrcNode         `json:"src"`
	Value    string          `json:"value"`
	HexValue string          `json:"hex_value"`
}

func NewYulLiteralStatement(b *ASTBuilder) *YulLiteralStatement {
	return &YulLiteralStatement{
		ASTBuilder: b,
		Id:         b.GetNextID(),
		NodeType:   ast_pb.NodeType_YUL_LITERAL,
	}
}

// SetReferenceDescriptor sets the reference descriptions of the YulLiteralStatement node.
func (y *YulLiteralStatement) SetReferenceDescriptor(refId int64, refDesc *TypeDescription) bool {
	return false
}

func (y *YulLiteralStatement) GetId() int64 {
	return y.Id
}

func (y *YulLiteralStatement) GetType() ast_pb.NodeType {
	return y.NodeType
}

func (y *YulLiteralStatement) GetSrc() SrcNode {
	return y.Src
}

func (y *YulLiteralStatement) GetNodes() []Node[NodeType] {
	toReturn := make([]Node[NodeType], 0)
	return toReturn
}

func (y *YulLiteralStatement) GetTypeDescription() *TypeDescription {
	return &TypeDescription{}
}

func (y *YulLiteralStatement) ToProto() NodeType {
	return ast_pb.Statement{}
}

func (y *YulLiteralStatement) Parse(
	unit *SourceUnit[Node[ast_pb.SourceUnit]],
	contractNode Node[NodeType],
	fnNode Node[NodeType],
	bodyNode *BodyNode,
	assemblyNode *Yul,
	statementNode *YulStatement,
	parentNode Node[NodeType],
	ctx *parser.YulLiteralContext,
) Node[NodeType] {
	if ctx.YulBoolean() != nil {
		literal := ctx.YulBoolean()
		y.Value = literal.GetText()
		y.Kind = ast_pb.NodeType_BOOLEAN
		y.Src = SrcNode{
			Id:          y.GetNextID(),
			Line:        int64(literal.GetStart().GetLine()),
			Column:      int64(literal.GetStart().GetColumn()),
			Start:       int64(literal.GetStart().GetStart()),
			End:         int64(literal.GetStart().GetStop()),
			Length:      int64(literal.GetStart().GetStop() - literal.GetStart().GetStart() + 1),
			ParentIndex: y.GetId(),
		}

	}

	if ctx.YulDecimalNumber() != nil {
		literal := ctx.YulDecimalNumber()
		y.Value = literal.GetText()
		y.Kind = ast_pb.NodeType_DECIMAL_NUMBER
		y.Src = SrcNode{
			Id:          y.GetNextID(),
			Line:        int64(literal.GetSymbol().GetLine()),
			Column:      int64(literal.GetSymbol().GetColumn()),
			Start:       int64(literal.GetSymbol().GetStart()),
			End:         int64(literal.GetSymbol().GetStop()),
			Length:      int64(literal.GetSymbol().GetStop() - literal.GetSymbol().GetStart() + 1),
			ParentIndex: y.GetId(),
		}
	}

	if ctx.YulStringLiteral() != nil {
		literal := ctx.YulStringLiteral()
		y.Value = literal.GetText()
		y.Kind = ast_pb.NodeType_STRING
		y.Src = SrcNode{
			Id:          y.GetNextID(),
			Line:        int64(literal.GetSymbol().GetLine()),
			Column:      int64(literal.GetSymbol().GetColumn()),
			Start:       int64(literal.GetSymbol().GetStart()),
			End:         int64(literal.GetSymbol().GetStop()),
			Length:      int64(literal.GetSymbol().GetStop() - literal.GetSymbol().GetStart() + 1),
			ParentIndex: y.GetId(),
		}
	}

	if ctx.YulHexNumber() != nil {
		literal := ctx.YulHexNumber()
		y.Kind = ast_pb.NodeType_HEX_NUMBER
		y.HexValue = literal.GetText()
		y.Src = SrcNode{
			Id:          y.GetNextID(),
			Line:        int64(literal.GetSymbol().GetLine()),
			Column:      int64(literal.GetSymbol().GetColumn()),
			Start:       int64(literal.GetSymbol().GetStart()),
			End:         int64(literal.GetSymbol().GetStop()),
			Length:      int64(literal.GetSymbol().GetStop() - literal.GetSymbol().GetStart() + 1),
			ParentIndex: y.GetId(),
		}

		bytes, _ := hex.DecodeString(strings.Replace(y.HexValue, "0x", "", -1))
		value := int64(0)
		for _, b := range bytes {
			value = (value << 8) | int64(b)
		}
		y.Value = fmt.Sprintf("%d", value)
	}

	if ctx.YulHexStringLiteral() != nil {
		literal := ctx.YulHexStringLiteral()
		y.Kind = ast_pb.NodeType_HEX_STRING
		y.HexValue = literal.GetText()
		y.Value = strings.Replace(y.HexValue, "0x", "", -1)
		y.Src = SrcNode{
			Id:          y.GetNextID(),
			Line:        int64(literal.GetSymbol().GetLine()),
			Column:      int64(literal.GetSymbol().GetColumn()),
			Start:       int64(literal.GetSymbol().GetStart()),
			End:         int64(literal.GetSymbol().GetStop()),
			Length:      int64(literal.GetSymbol().GetStop() - literal.GetSymbol().GetStart() + 1),
			ParentIndex: y.GetId(),
		}

	}

	return y
}
