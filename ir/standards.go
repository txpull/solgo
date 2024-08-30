package ir

import (
	ir_pb "github.com/unpackdev/protos/dist/go/ir"
	"github.com/unpackdev/solgo/standards"
)

// Standard represents a specific Ethereum Improvement Proposal standard that a contract may adhere to.
type Standard struct {
	// ContractId is the unique identifier for the contract.
	ContractId int64 `json:"contract_id"`

	// ContractName is the name of the contract.
	ContractName string `json:"contract_name"`

	// Confidence represents the confidence level of the contract adhering to a specific EIP standard.
	Confidence standards.Discovery `json:"confidences"`

	// Standard provides details about the specific EIP standard.
	Standard standards.ContractStandard `json:"standards"`
}

// GetContractId returns the unique identifier for the contract.
func (e *Standard) GetContractId() int64 {
	return e.ContractId
}

// GetContractName returns the name of the contract.
func (e *Standard) GetContractName() string {
	return e.ContractName
}

// GetConfidence returns the confidence level of the contract adhering to a specific EIP standard.
func (e *Standard) GetConfidence() standards.Discovery {
	return e.Confidence
}

// GetStandard returns the EIP standard.
func (e *Standard) GetStandard() standards.ContractStandard {
	return e.Standard
}

// ToProto converts the EIP to its protobuf representation.
func (e *Standard) ToProto() *ir_pb.EIP {
	return &ir_pb.EIP{
		ContractId:   e.ContractId,
		ContractName: e.ContractName,
		Confidence:   e.Confidence.ToProto(),
		Standard:     e.Standard.ToProto(),
	}
}

// processEips processes the given RootSourceUnit to identify and associate it with known EIP standards.
// It extracts functions and events from the contract and sends them to the EIP discovery package
// to determine if the contract matches any known EIPs.
func (b *Builder) processEips(root *RootSourceUnit) {
	// Extracting functions and events to build actual contract that is going to
	// be sent towards the EIP discovery package.

	contract := &standards.ContractMatcher{
		Name:      root.GetEntryName(),
		Functions: make([]standards.StandardFunction, 0),
		Events:    make([]standards.StandardEvent, 0),
	}

	for _, unit := range root.GetContracts() {
		for _, function := range unit.GetFunctions() {
			inputs := make([]standards.Input, 0)
			outputs := make([]standards.Output, 0)

			for _, param := range function.GetParameters() {
				if param.GetTypeDescription() == nil {
					//utils.DumpNodeWithExit(param)
				}
				inputs = append(inputs, standards.Input{
					Type:    param.GetTypeDescription().GetString(),
					Indexed: false, // Specific to events...
				})
			}

			for _, ret := range function.GetReturnStatements() {
				if ret.GetTypeDescription() == nil {
					//utils.DumpNodeWithExit(function)
				}
				outputs = append(outputs, standards.Output{
					Type: ret.GetTypeDescription().GetString(),
				})
			}

			contract.Functions = append(contract.Functions, standards.StandardFunction{
				Name:    function.GetName(),
				Inputs:  inputs,
				Outputs: outputs,
			})
		}

		for _, event := range unit.GetEvents() {
			inputs := make([]standards.Input, 0)

			for _, param := range event.GetParameters() {
				inputs = append(inputs, standards.Input{
					Type:    param.GetTypeDescription().GetString(),
					Indexed: param.IsIndexed(),
				})
			}

			contract.Events = append(contract.Events, standards.StandardEvent{
				Name:    event.GetName(),
				Inputs:  inputs,
				Outputs: make([]standards.Output, 0),
			})
		}
	}

	// Now when we have full contract functions and events we can send it to the
	// EIP discovery package to find out if it matches any of the EIPs.
	for _, standard := range standards.GetSortedRegisteredStandards() {
		if !root.HasStandard(standard.GetType()) {
			if confidence, found := standards.ConfidenceCheck(standard, contract); found {
				root.Standards = append(root.Standards, &Standard{
					ContractName: contract.Name,
					ContractId:   root.GetEntryId(),
					Confidence:   confidence,
					Standard:     standard.GetStandard(),
				})

				// Fuck finally, lets check if this contract is proxy, upgradeable,
				// nft or token or any other really that we support...
				// We will apply to the overall contract standards only EIPs that are matched with highest confidence
				if confidence.Confidence == standards.HighConfidence {
					root.SetContractType(standard.GetType())
				}
			}
		}
	}

}
