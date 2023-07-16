package ast

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/txpull/solgo"
	"github.com/txpull/solgo/tests"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestAstBuilder(t *testing.T) {
	config := zap.NewDevelopmentConfig()
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	logger, err := config.Build()
	assert.NoError(t, err)

	// Replace the global logger.
	zap.ReplaceGlobals(logger)

	// Define multiple test cases
	testCases := []struct {
		name      string
		contracts map[string]string
		expected  string
	}{
		{
			name: "Empty Contract",
			contracts: map[string]string{
				"Empty": tests.ReadContractFileForTest(t, "Empty").Content,
			},
			expected: `{"source_units":[{"id":0,"license":"","node_type":"SourceUnit","nodes":[],"src":{"line":1,"start":0,"end":0,"length":0,"index":0}}]}`,
		},
		{
			name: "Simple Storage Contract",
			contracts: map[string]string{
				"MathLib": tests.ReadContractFileForTest(t, "ast/MathLib").Content,
				//tests.ReadContractFileForTest(t, "ast/SimpleStorage").Content,
			},
			expected: `{"source_units":[]}`,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			for contractName, contract := range testCase.contracts {
				parser, err := solgo.NewParser(context.TODO(), strings.NewReader(contract))
				assert.NoError(t, err)
				assert.NotNil(t, parser)

				// Register the contract information listener
				astBuilder := NewAstBuilder(
					// We need to provide parser to the ast builder so that it can
					// access comments and other information from the parser.
					parser.GetParser(),
				)
				err = parser.RegisterListener(solgo.ListenerAst, astBuilder)
				assert.NoError(t, err)

				syntaxErrs := parser.Parse()
				assert.Empty(t, syntaxErrs)

				prettyJson, err := astBuilder.ToPrettyJSON()
				assert.NoError(t, err)
				assert.NotEmpty(t, prettyJson)

				fmt.Println(string(prettyJson))

				err = astBuilder.WriteJSONToFile("../data/tests/ast/" + contractName + ".solgo.ast.json")
				assert.NoError(t, err)

				/* 				astJson, err := astBuilder.ToJSON()
				   				assert.NoError(t, err)
				   				assert.NotEmpty(t, astJson)
				   				ioutil.WriteFile(testCase.name+".json", []byte(astJson), 0777)
				   				assert.Equal(t, testCase.expected, astJson) */
			}
		})
	}
}
