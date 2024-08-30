package abi

import (
	"github.com/unpackdev/solgo/ir"
)

// processError processes an IR error and returns a Method representation of it.
// It extracts the name and parameters of the error and sets its type to "error" and state mutability to "view".
func (b *Builder) processError(unit *ir.Error) (*Method, error) {
	toReturn := &Method{
		Name:            unit.GetName(),
		Inputs:          make([]MethodIO, 0),
		Outputs:         make([]MethodIO, 0),
		Type:            "error",
		StateMutability: "view", // Errors in Ethereum are view-only and don't modify state.
	}

	for _, parameter := range unit.GetParameters() {
		if parameter.GetTypeDescription() == nil {
			//utils.DumpNodeWithExit(unit)
			//return nil, fmt.Errorf("nil type description for error parameter %s", parameter.GetName())
			continue
		}

		methodIo := MethodIO{
			Name:    parameter.GetName(),
			Indexed: parameter.IsIndexed(),
		}
		toReturn.Inputs = append(
			toReturn.Inputs,
			b.buildMethodIO(methodIo, parameter.GetTypeDescription()),
		)
	}

	return toReturn, nil
}
