package storage

import (
	"context"
	"fmt"
	"strings"
)

// Reader is responsible for reading and interpreting storage-related information of a smart contract.
// It uses a Descriptor to understand the contract's storage layout and variables.
type Reader struct {
	ctx        context.Context // ctx is the context for operations within Reader.
	storage    *Storage        // storage is the storage system associated with the Reader.
	descriptor *Descriptor     // descriptor contains the contract's storage layout and variable information.
}

// NewReader creates a new instance of Reader with the given context, Storage, and Descriptor.
// It returns a pointer to the created Reader and any error encountered during its creation.
func NewReader(ctx context.Context, s *Storage, d *Descriptor) (*Reader, error) {
	return &Reader{
		ctx:        ctx,
		storage:    s,
		descriptor: d,
	}, nil
}

// GetDescriptor returns the Descriptor associated with the Reader.
func (r *Reader) GetDescriptor() *Descriptor {
	return r.descriptor
}

// DiscoverStorageVariables analyzes the smart contract to discover and categorize storage variables.
// It differentiates between constant and non-constant variables and organizes them accordingly.
func (r *Reader) DiscoverStorageVariables() error {
	cfgBuilder := r.descriptor.GetCFG()
	if cfgBuilder == nil {
		return fmt.Errorf("CFG builder is not available")
	}

	orderedStateVars, err := cfgBuilder.GetStorageStateVariables()
	if err != nil {
		return fmt.Errorf("failed to get ordered state variables: %v", err)
	}

	for _, stateVar := range orderedStateVars {
		contractName := stateVar.GetContract().GetName()
		variable := &Variable{
			Contract:      stateVar.GetContract(),
			EntryContract: stateVar.IsEntryContract(),
			StateVariable: stateVar.GetVariable(),
		}

		r.descriptor.StateVariables[contractName] = append(r.descriptor.StateVariables[contractName], variable)

		if !variable.StateVariable.IsConstant() {
			r.descriptor.TargetVariables[contractName] = append(r.descriptor.TargetVariables[contractName], variable)
		} else {
			r.descriptor.ConstantVariables[contractName] = append(r.descriptor.ConstantVariables[contractName], variable)
		}
	}

	return nil
}

// CalculateStorageLayout calculates and sets the storage layout of the smart contract in the Descriptor.
// It determines the slot and offset for each storage variable and organizes them accordingly.
func (r *Reader) CalculateStorageLayout() error {
	currentSlot := int64(0)
	var previousVars []*Variable

	var sortedSlots []*SlotDescriptor

	for _, variables := range r.descriptor.GetTargetVariables() {
		for _, variable := range variables {
			storageSize, found := variable.GetAST().GetTypeName().StorageSize()
			if !found {
				//utils.DumpNodeNoExit(variable.GetAST().GetTypeName())
				//return fmt.Errorf("error calculating storage size for variable: %s", variable.GetName())
				continue
			}

			typeName := variable.GetType()
			if strings.HasPrefix(typeName, "contract") {
				typeName = "address"
			}

			sortedSlots = append(sortedSlots, &SlotDescriptor{
				DeclarationId:   variable.StateVariable.GetId(),
				Variable:        variable,
				Contract:        variable.Contract,
				Name:            variable.GetName(),
				Type:            typeName,
				TypeDescription: variable.StateVariable.GetTypeDescription(),
				Size:            storageSize,
			})
		}
	}

	for i, variable := range sortedSlots {
		slot, offset, updatedPreviousVars := calculateSlot(variable.Variable, currentSlot, previousVars)
		previousVars = updatedPreviousVars
		sortedSlots[i].Slot = slot
		sortedSlots[i].Offset = offset

		if slot != currentSlot {
			currentSlot = slot
		}
	}

	r.descriptor.StorageLayout = &StorageLayout{
		Slots: sortedSlots,
	}

	return nil
}
