package abi

import (
	abi_pb "github.com/unpackdev/protos/dist/go/abi"
	ast_pb "github.com/unpackdev/protos/dist/go/ast"
	"github.com/unpackdev/solgo/ast"
	"github.com/unpackdev/solgo/ir"
	"strings"
)

// Contract represents a collection of Ethereum contract methods.
type Contract []*Method

func (c *Contract) GetMethodByType(typeName string) *Method {
	for _, method := range *c {
		if method.Type == typeName {
			return method
		}
	}

	return nil
}

func (c *Contract) GetMethodByName(name string) *Method {
	for _, method := range *c {
		if method.Name == name {
			return method
		}
	}

	return nil
}

// ToProto converts the Contract into its protocol buffer representation.
func (c *Contract) ToProto() *abi_pb.Contract {
	toReturn := &abi_pb.Contract{
		Methods: make([]*abi_pb.Method, 0),
	}

	for _, method := range *c {
		toReturn.Methods = append(toReturn.Methods, method.ToProto())
	}

	return toReturn
}

// processContract processes an IR contract and returns a Contract representation of it.
// It extracts state variables, events, errors, constructor, functions, fallback, and receive methods.
func (b *Builder) processContract(contract *ir.Contract) (*Contract, error) {
	toReturn := Contract{}

	// Process state variables.
	for _, stateVar := range contract.GetStateVariables() {
		// Some old contracts will have this broken. It's related to 0.4 contracts.
		// Better to have at least something then nothing at all in this point.
		if stateVar.Name == "" && stateVar.GetTypeDescription() == nil {
			continue
		}

		if method := b.processStateVariable(stateVar); method != nil {
			toReturn = append(toReturn, method)
		}
	}

	// Process events.
	for _, event := range contract.GetEvents() {
		method, err := b.processEvent(event)
		if err != nil {
			return nil, err
		}

		toReturn = append(toReturn, method)
	}

	// Process errors.
	for _, errorNode := range contract.GetErrors() {
		method, err := b.processError(errorNode)
		if err != nil {
			return nil, err
		}

		toReturn = append(toReturn, method)
	}

	// Process constructor.
	if contract.GetConstructor() != nil {
		method, err := b.processConstructor(contract.GetConstructor())
		if err != nil {
			return nil, err
		}

		toReturn = append(toReturn, method)
	}

	// Process functions.
	for _, function := range contract.GetFunctions() {
		if function.GetVisibility() == ast_pb.Visibility_PUBLIC && function.GetVisibility() == ast_pb.Visibility_EXTERNAL {
			method, err := b.processFunction(function)
			if err != nil {
				return nil, err
			}

			toReturn = append(toReturn, method)
		}
	}

	// Process fallback.
	if contract.GetFallback() != nil {
		toReturn = append(
			toReturn,
			b.processFallback(contract.GetFallback()),
		)
	}

	// Process receive.
	if contract.GetReceive() != nil {
		method, err := b.processReceive(contract.GetReceive())
		if err != nil {
			return nil, err
		}

		toReturn = append(toReturn, method)
	}

	return &toReturn, nil
}

// buildMethodIO constructs a MethodIO object based on the provided method and type description.
// It resolves the type of the method and sets the appropriate fields.
func (b *Builder) buildMethodIO(method MethodIO, typeDescr *ast.TypeDescription) MethodIO {
	typeName := b.resolver.ResolveType(typeDescr)

	switch typeName {
	case "mapping":
		inputList, outputList := b.resolver.ResolveMappingType(typeDescr)
		method.Inputs = append(method.Inputs, inputList...)
		method.Outputs = append(method.Outputs, outputList...)
	case "contract":
		if strings.ContainsAny(typeDescr.GetString(), "[]") {
			method.Type = "address[]"
		} else {
			method.Type = "address"
		}
		method.InternalType = typeDescr.GetString()
	case "enum":
		if strings.ContainsAny(typeDescr.GetString(), "[]") {
			method.Type = "uint8[]"
		} else {
			method.Type = "uint8"
		}
		method.InternalType = typeDescr.GetString()
	case "struct":
		structMember := b.resolver.ResolveStructType(typeDescr)
		structMember.Name = method.Name
		return structMember
	default:
		method.Type = typeName
		method.InternalType = typeDescr.GetString()
	}

	return method
}
