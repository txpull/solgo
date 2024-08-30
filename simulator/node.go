package simulator

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Node represents a single node in the simulation environment. It encapsulates the
// details and operations for a blockchain simulation node.
type Node struct {
	cmd             *exec.Cmd   `json:"-"`                // The command used to start the node process. Not exported in JSON.
	simulator       *Simulator  `json:"-"`                // Reference to the Simulator instance managing this node. Not exported in JSON.
	provider        Provider    `json:"-"`                // The Provider instance representing the blockchain network provider. Not exported in JSON.
	ID              uuid.UUID   `json:"id"`               // Unique identifier for the node.
	PID             int         `json:"pid"`              // Process ID of the running node.
	Addr            net.TCPAddr `json:"addr"`             // TCP address on which the node is running.
	IpcPath         string      `json:"ipc_path"`         // The file path for the IPC endpoint of the node.
	AutoImpersonate bool        `json:"auto_impersonate"` // Flag indicating whether the node should automatically impersonate accounts.
	BlockNumber     *big.Int    `json:"block_number"`     // The block number from which the node is operating, if applicable.
	PidPath         string      `json:"pid_path"`         // The file path where the node's PID file is stored.
	ExecutablePath  string      `json:"executable_path"`  // The file path to the executable used by this node.
	Fork            bool        `json:"fork"`             // Flag indicating whether the node is running in fork mode.
	ForkEndpoint    string      `json:"fork_endpoint"`    // The endpoint URL of the blockchain to fork from, if fork mode is enabled.
}

// GetNodeAddr returns the HTTP address of the node.
func (n *Node) GetNodeAddr() string {
	return fmt.Sprintf("http://%s:%d", n.Addr.IP.String(), n.Addr.Port)
}

// GetSimulator returns the Simulator instance associated with the node.
func (n *Node) GetSimulator() *Simulator {
	return n.simulator
}

// GetProvider returns the Provider instance associated with the node.
func (n *Node) GetProvider() Provider {
	return n.provider
}

// GetID returns the unique identifier of the node.
func (n *Node) GetID() uuid.UUID {
	return n.ID
}

// Start initiates the Anvil node's process, capturing its output and handling its lifecycle.
func (n *Node) Start(ctx context.Context) error {
	started := make(chan struct{})

	cmd := exec.CommandContext(ctx, n.ExecutablePath, n.provider.GetCmdArguments(n)...)

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdout pipe: %v", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to get stderr pipe: %v", err)
	}

	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("failed to start Anvil node: %v", err)
	}

	n.PID = cmd.Process.Pid
	n.cmd = cmd

	nodeJSON, err := json.Marshal(n)
	if err != nil {
		return fmt.Errorf("failed to marshal Node data to JSON: %v", err)
	}

	pidFileName := fmt.Sprintf("anvil.%d.pid.json", n.Addr.Port)
	filePath := filepath.Join(n.PidPath, pidFileName)

	err = os.WriteFile(filePath, nodeJSON, 0644) // Using 0644 as a common permission setting
	if err != nil {
		return fmt.Errorf("failed to write Node JSON to file: %v", err)
	}

	go n.streamOutput(stdoutPipe, "stdout", started)
	go n.streamOutput(stderrPipe, "stderr", nil)

	go func() {
		err := cmd.Wait()
		if err != nil {
			// Ignore the error if the process was killed
			if strings.Contains(err.Error(), "no child processes") ||
				strings.Contains(err.Error(), "signal: killed") {
				return
			}

			zap.L().Error("Anvil node exited with error", zap.Error(err))
		} else {
			zap.L().Info("Anvil node exited successfully")
		}
	}()

	select {
	case <-started:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("failed to start Anvil node: %v", ctx.Err())
	}
}

// Stop terminates the Anvil node's process, cleans up resources, and removes relevant files.
func (n *Node) Stop(ctx context.Context, force bool) error {
	zap.L().Info(
		"Stopping Anvil node...",
		zap.String("addr", n.Addr.String()),
		zap.Int("port", n.Addr.Port),
		zap.String("network", n.provider.Network().String()),
		zap.Any("network_id", n.provider.NetworkID()),
		zap.Any("block_number", n.BlockNumber),
	)

	if n.cmd == nil || n.cmd.Process == nil {
		return fmt.Errorf("process not started or already stopped")
	}

	err := n.cmd.Process.Signal(os.Interrupt) // or syscall.SIGTERM, depending on how your node handles signals
	if err != nil {
		if !errors.Is(err, os.ErrProcessDone) {
			return fmt.Errorf("failed to send interrupt signal to process: %v", err)
		}
	}

	if !force && err == nil {
		_, err = n.cmd.Process.Wait()
		if err != nil && !errors.Is(err, os.ErrProcessDone) {
			return fmt.Errorf("error waiting for process to exit: %v", err)
		}
	}

	pidFileName := fmt.Sprintf("anvil.%d.pid.json", n.Addr.Port)
	filePath := filepath.Join(n.PidPath, pidFileName)
	os.Remove(filePath)

	pidFileName = fmt.Sprintf("anvil.%d.ipc", n.Addr.Port)
	filePath = filepath.Join(n.PidPath, pidFileName)
	os.Remove(filePath)

	zap.L().Info(
		"Anvil node successfully stopped",
		zap.String("addr", n.Addr.String()),
		zap.Int("port", n.Addr.Port),
		zap.String("network", n.provider.Network().String()),
		zap.Any("network_id", n.provider.NetworkID()),
		zap.Any("block_number", n.BlockNumber),
	)

	return nil
}

// Status checks the current status of the node, including its running state and error conditions.
func (n *Node) Status(ctx context.Context) (*NodeStatus, error) {
	if n.cmd == nil || n.cmd.Process == nil {
		return &NodeStatus{
			ID:          n.ID,
			BlockNumber: n.BlockNumber.Uint64(),
			IPAddr:      n.Addr.IP.String(),
			Port:        n.Addr.Port,
			Success:     false,
			Status:      NodeStatusTypeStopped,
			Error:       nil,
		}, nil
	}

	// Check if the process is still running
	process, err := os.FindProcess(n.cmd.Process.Pid)
	if err != nil {
		return &NodeStatus{
			ID:          n.ID,
			BlockNumber: n.BlockNumber.Uint64(),
			IPAddr:      n.Addr.IP.String(),
			Port:        n.Addr.Port,
			Success:     false,
			Status:      NodeStatusTypeError,
			Error:       fmt.Errorf("error finding process: %v", err),
		}, fmt.Errorf("error finding process: %v", err)
	}

	// Sending signal 0 to a process checks for its existence without killing it
	err = process.Signal(syscall.Signal(0))
	if err == nil {
		return &NodeStatus{
			ID:          n.ID,
			BlockNumber: n.BlockNumber.Uint64(),
			IPAddr:      n.Addr.IP.String(),
			Port:        n.Addr.Port,
			Success:     true,
			Status:      NodeStatusTypeRunning,
			Error:       nil,
		}, nil
	}

	if errors.Is(err, os.ErrProcessDone) {
		return &NodeStatus{
			ID:          n.ID,
			BlockNumber: n.BlockNumber.Uint64(),
			IPAddr:      n.Addr.IP.String(),
			Port:        n.Addr.Port,
			Success:     true,
			Status:      NodeStatusTypeStopped,
			Error:       nil,
		}, nil
	}

	return &NodeStatus{
		ID:          n.ID,
		BlockNumber: n.BlockNumber.Uint64(),
		IPAddr:      n.Addr.IP.String(),
		Port:        n.Addr.Port,
		Success:     false,
		Status:      NodeStatusTypeError,
		Error:       fmt.Errorf("error checking process status: %v", err),
	}, fmt.Errorf("error checking process status: %v", err)
}

// streamOutput handles the output from the node's stdout and stderr, extracting information
// like block number and node readiness, and logging the output.
func (n *Node) streamOutput(pipe io.ReadCloser, outputType string, done chan struct{}) {
	blockNumberRegex := regexp.MustCompile(`Block number:\s+(\d+)`)
	listeningRegex := regexp.MustCompile(`Listening on ([\d\.]+:\d+)`)
	revertedRegex := regexp.MustCompile(`Error: reverted with:\s+(.+)`)
	scanner := bufio.NewScanner(pipe)

	for scanner.Scan() {
		line := scanner.Text()

		if lineTrimmed := strings.TrimSpace(line); lineTrimmed != "" {
			zap.L().Debug(
				line,
				zap.String("addr", n.Addr.String()),
				zap.Int("port", n.Addr.Port),
				zap.String("network", n.provider.Network().String()),
				zap.Any("network_id", n.provider.NetworkID()),
				zap.Any("block_number", n.BlockNumber),
			)
		}

		// Check for block number in the output
		if matches := blockNumberRegex.FindStringSubmatch(line); len(matches) > 1 {
			blockNumber, err := strconv.ParseInt(matches[1], 10, 64)
			if err == nil {
				n.BlockNumber = big.NewInt(blockNumber) // Update the BlockNumber field
				zap.L().Info(
					"Discovered block number for Anvil node",
					zap.String("addr", n.Addr.String()),
					zap.Int("port", n.Addr.Port),
					zap.String("network", n.provider.Network().String()),
					zap.Any("network_id", n.provider.NetworkID()),
					zap.Uint64("block_number", n.BlockNumber.Uint64()),
				)
			}
		}

		// Check for revert messages....
		if matches := revertedRegex.FindStringSubmatch(line); len(matches) > 1 {
			zap.L().Error(
				"Discovered revert message",
				zap.Error(fmt.Errorf("%s", matches[1])),
				zap.String("addr", n.Addr.String()),
				zap.Int("port", n.Addr.Port),
				zap.String("network", n.provider.Network().String()),
				zap.Any("network_id", n.provider.NetworkID()),
				zap.Uint64("block_number", n.BlockNumber.Uint64()),
			)
		}

		// Check if the node is listening and if the done channel is set
		if done != nil && listeningRegex.MatchString(line) {
			close(done) // Close the done channel to signal readiness
			done = nil  // Prevent further attempts to close the channel
		}
	}

	if err := scanner.Err(); err != nil {
		if !strings.Contains(err.Error(), "file already closed") {
			zap.L().Error(fmt.Sprintf("Error reading from node %s: %v", outputType, err))
		}
	}
}
