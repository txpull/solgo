package abi

import (
	"github.com/unpackdev/solgo/ir"
)

// processStateVariable processes the provided StateVariable from the IR and constructs a Method representation.
// The returned Method will have its Type set to "function" and its StateMutability determined by the state variable's mutability.
// Depending on the type of the state variable (e.g., mapping, contract, enum), the method's Inputs and Outputs are populated accordingly.
func (b *Builder) processStateVariable(stateVar *ir.StateVariable) *Method {
	toReturn := &Method{
		Name:            stateVar.GetName(),
		Inputs:          make([]MethodIO, 0),
		Outputs:         make([]MethodIO, 0),
		Type:            "function", // Type is always set to "function" for state variables
		StateMutability: b.normalizeStateMutability(stateVar.GetStateMutability()),
	}

	if stateVar.GetTypeDescription() == nil {
		return nil
	}

	typeName := b.resolver.ResolveType(stateVar.GetTypeDescription())

	switch typeName {
	case "mapping":
		// For mapping types, resolve the input and output types and append them to the method's Inputs and Outputs
		inputList, outputList := b.resolver.ResolveMappingType(stateVar.GetTypeDescription())
		toReturn.Inputs = append(toReturn.Inputs, inputList...)
		toReturn.Outputs = append(toReturn.Outputs, outputList...)
	case "struct":
		toReturn.Outputs = append(toReturn.Outputs,
			b.resolver.ResolveStructType(stateVar.GetTypeDescription()),
		)
	case "contract":
		// For contract types, the output is always an address
		toReturn.Outputs = append(toReturn.Outputs, MethodIO{
			Type:         "address",
			InternalType: stateVar.GetTypeDescription().GetString(),
		})
	case "enum":
		// For enum types, the output is represented as uint8 in the ABI
		toReturn.Outputs = append(toReturn.Outputs, MethodIO{
			Type:         "uint8",
			InternalType: stateVar.GetTypeDescription().GetString(),
		})
	default:
		// For all other types, simply append the type to the method's Outputs
		toReturn.Outputs = append(toReturn.Outputs, MethodIO{
			Type:         typeName,
			InternalType: stateVar.GetTypeDescription().GetString(),
		})
	}

	return toReturn
}
