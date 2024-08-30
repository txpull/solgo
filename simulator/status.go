package simulator

import (
	"github.com/google/uuid"
	"github.com/unpackdev/solgo/utils"
)

// NodeStatusType defines the possible states of a simulation node.
type NodeStatusType string

const (
	// NodeStatusTypeError indicates that the simulation node is in an error state.
	NodeStatusTypeError NodeStatusType = "error"

	// NodeStatusTypeRunning indicates that the simulation node is currently running.
	NodeStatusTypeRunning NodeStatusType = "running"

	// NodeStatusTypeStopped indicates that the simulation node has been stopped.
	NodeStatusTypeStopped NodeStatusType = "stopped"
)

// NodeStatus represents the status of a simulation node, including its unique identifier,
// IP address, port, and operational state.
type NodeStatus struct {
	ID          uuid.UUID      `json:"id"`           // Unique identifier for the node.
	BlockNumber uint64         `json:"block_number"` // Block number at which the node is currently operating.
	IPAddr      string         `json:"ip_addr"`      // IP address of the node.
	Port        int            `json:"port"`         // Port on which the node is running.
	Success     bool           `json:"success"`      // Indicates whether the node is operating successfully.
	Status      NodeStatusType `json:"status"`       // Current status of the node.
	Error       error          `json:"error"`        // Error encountered by the node, if any.
}

// NodeStatusResponse contains a mapping of node statuses categorized by simulator type.
type NodeStatusResponse struct {
	Nodes map[utils.SimulatorType][]*NodeStatus `json:"nodes"` // Mapping of simulator types to their respective node statuses.
}

// GetNodesByType returns a slice of NodeStatus pointers for a given simulator type.
func (nr *NodeStatusResponse) GetNodesByType(simType utils.SimulatorType) ([]*NodeStatus, bool) {
	if nodes, ok := nr.Nodes[simType]; ok {
		return nodes, true
	}

	return nil, false
}
