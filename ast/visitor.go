package ast

import (
	"github.com/pkg/errors"
	ast_pb "github.com/unpackdev/protos/dist/go/ast"
)

// NodeVisitor defines a structure for visiting nodes within an AST.
// It supports both a generic visit function and type-specific visit functions.
type NodeVisitor struct {
	// Visit defines a generic function to visit nodes of any type.
	// It should return true to continue traversal, false to stop.
	Visit func(node Node[NodeType]) bool
	// TypeVisit maps node types to slices of functions that visit nodes of that specific type.
	// Each function should return a boolean indicating whether to continue traversal, and an error if one occurred.
	TypeVisit map[ast_pb.NodeType][]func(node Node[NodeType]) (bool, error)
}

// RegisterTypeVisit allows registering one or more visitation functions for a specific node type.
// These functions are called when a node of the specified type is encountered during traversal.
func (nv *NodeVisitor) RegisterTypeVisit(nodeType ast_pb.NodeType, visitFunc func(node Node[NodeType]) (bool, error)) {
	if nv.TypeVisit == nil {
		nv.TypeVisit = make(map[ast_pb.NodeType][]func(node Node[NodeType]) (bool, error))
	}
	nv.TypeVisit[nodeType] = append(nv.TypeVisit[nodeType], visitFunc)
}

// Walk initiates the traversal of the AST from its root, using the provided NodeVisitor.
// It processes the AST nodes based on the visitation functions defined in the visitor.
func (t *Tree) Walk(visitor *NodeVisitor) error {
	return t.WalkNodes(t.astRoot.GetNodes(), visitor)
}

// WalkNode applies the NodeVisitor to a single node and its descendants in the AST.
func (t *Tree) WalkNode(startNode Node[NodeType], visitor *NodeVisitor) error {
	_, err := t.walkRecursive(startNode, visitor)
	return err
}

// WalkNodes applies the NodeVisitor to a slice of nodes and their descendants in the AST.
func (t *Tree) WalkNodes(startNodes []Node[NodeType], visitor *NodeVisitor) error {
	for _, node := range startNodes {
		_, err := t.walkRecursive(node, visitor)
		if err != nil {
			return err
		}
	}
	return nil
}

// ExecuteTypeVisit executes a visitation function on all nodes of a specific type in the AST, starting from the root.
func (t *Tree) ExecuteTypeVisit(nodeType ast_pb.NodeType, visitFunc func(node Node[NodeType]) (bool, error)) (bool, error) {
	if t.astRoot == nil || t.astRoot.GetNodes() == nil {
		return false, errors.New("cannot execute type visit on empty tree")
	}
	return t.executeTypeVisitRecursive(t.astRoot.GetNodes(), nodeType, visitFunc)
}

// ExecuteCustomTypeVisit executes a visitation function on all nodes of a specific type in a provided slice of nodes.
func (t *Tree) ExecuteCustomTypeVisit(nodes []Node[NodeType], nodeType ast_pb.NodeType, visitFunc func(node Node[NodeType]) (bool, error)) (bool, error) {
	return t.executeTypeVisitRecursive(nodes, nodeType, visitFunc)
}

// executeTypeVisitRecursive is an internal helper method that recursively applies a visitation function
// to all nodes of a specific type, including their descendants.
func (t *Tree) executeTypeVisitRecursive(nodes []Node[NodeType], nodeType ast_pb.NodeType, visitFunc func(node Node[NodeType]) (bool, error)) (bool, error) {
	for _, node := range nodes {
		if node == nil {
			continue
		}

		// Execute the visit function if the node type matches
		if node.GetType() == nodeType {
			if status, err := visitFunc(node); err != nil {
				return status, err
			} else if !status {
				return status, err
			}
		}

		// Recursively call this function for all child nodes
		status, err := t.executeTypeVisitRecursive(node.GetNodes(), nodeType, visitFunc)
		if err != nil {
			return status, err
		}
	}

	return false, nil
}

// walkRecursive is an internal helper method that recursively applies the NodeVisitor to a node and its descendants.
func (t *Tree) walkRecursive(node Node[NodeType], visitor *NodeVisitor) (bool, error) {
	if node == nil {
		return true, nil
	}

	// Execute all registered functions sequentially for this node type
	if visitFuncs, ok := visitor.TypeVisit[node.GetType()]; ok {
		for _, visitFunc := range visitFuncs {
			status, err := visitFunc(node)
			if err != nil {
				return status, err
			}
			if !status {
				return status, nil
			}
		}
	} else if visitor.Visit != nil {
		status := visitor.Visit(node)
		if !status {
			return status, nil
		}
	}

	// Recursively call this function for all child nodes
	for _, child := range node.GetNodes() {
		status, err := t.walkRecursive(child, visitor)
		if err != nil {
			return status, err
		}
		if !status {
			return status, nil
		}
	}

	return true, nil
}
