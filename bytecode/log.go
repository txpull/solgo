package bytecode

import (
	"bytes"
	"fmt"
	"math/big"
	"strings"

	abi "github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/unpackdev/solgo/utils"
)

// Topic represents a single decoded topic from an Ethereum event log. Topics are attributes
// of an event, such as the method signature and indexed parameters.
type Topic struct {
	Name  string `json:"name"`  // The name of the topic.
	Value any    `json:"value"` // The value of the topic, decoded into the appropriate Go data type.
}

// Log encapsulates a decoded Ethereum event log. It includes the event's details such as its name,
// signature, the contract that emitted the event, and the decoded data and topics.
type Log struct {
	Event        *abi.Event         `json:"-"`             // ABI definition of the log's event.
	Address      common.Address     `json:"address"`       // Address of the contract that emitted the event.
	Abi          string             `json:"abi"`           // ABI string of the event.
	SignatureHex common.Hash        `json:"signature_hex"` // Hex-encoded signature of the event.
	Signature    string             `json:"signature"`     // Signature of the event.
	Type         utils.LogEventType `json:"type"`          // Type of the event, classified by solgo.
	Name         string             `json:"name"`          // Name of the event.
	Data         map[string]any     `json:"data"`          // Decoded event data.
	Topics       []Topic            `json:"topics"`        // Decoded topics of the event.
}

// DecodeLogFromAbi decodes an Ethereum event log using the provided ABI data. It returns a Log
// instance containing the decoded event name, data, and topics. The function requires the event log
// and its ABI as inputs. It handles errors such as missing topics or failure to parse the ABI.
func DecodeLogFromAbi(log *types.Log, abiData []byte) (*Log, error) {
	if log == nil || len(log.Topics) < 1 {
		return nil, fmt.Errorf("log is nil or has no topics")
	}

	logABI, err := abi.JSON(bytes.NewReader(abiData))
	if err != nil {
		return nil, fmt.Errorf("failed to parse abi: %s", err)
	}

	event, err := logABI.EventByID(log.Topics[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get event by id %s: %s", log.Topics[0].Hex(), err)
	}

	data := make(map[string]any)
	if err := event.Inputs.UnpackIntoMap(data, log.Data); err != nil {
		return nil, fmt.Errorf("failed to unpack inputs into map: %s", err)
	}

	// Identify and decode indexed inputs
	indexedInputs := make([]abi.Argument, 0)
	for _, input := range event.Inputs {
		if input.Indexed {
			indexedInputs = append(indexedInputs, input)
		}
	}

	decodedTopics := make([]Topic, len(indexedInputs))
	if len(log.Topics) >= len(indexedInputs)+1 {
		for i, indexedInput := range indexedInputs {
			decodedTopic, err := decodeTopic(log.Topics[i+1], indexedInput)
			if err != nil {
				return nil, fmt.Errorf("failed to decode topic: %s", err)
			}

			decodedTopics[i] = Topic{
				Name:  indexedInput.Name,
				Value: decodedTopic,
			}
		}
	}

	eventAbi, err := utils.EventToABI(event)
	if err != nil {
		return nil, fmt.Errorf("failed to cast event into the abi: %w", err)
	}

	toReturn := &Log{
		Event:        event,
		Address:      log.Address,
		Abi:          eventAbi,
		SignatureHex: log.Topics[0],
		Signature:    strings.TrimLeft(event.String(), "event "),
		Name:         event.Name,
		Type:         utils.LogEventType(strings.ToLower(event.Name)),
		Data:         data,
		Topics:       decodedTopics, // Include only the decoded topics
	}

	return toReturn, nil
}

// decodeTopic decodes a single topic from an Ethereum event log based on its ABI argument type.
// It supports various data types including addresses, booleans, integers, strings, bytes, and more.
// This function is internal and used within DecodeLogFromAbi to process each topic individually.
func decodeTopic(topic common.Hash, argument abi.Argument) (interface{}, error) {
	switch argument.Type.T {
	case abi.AddressTy:
		return common.BytesToAddress(topic.Bytes()), nil
	case abi.BoolTy:
		return topic[common.HashLength-1] == 1, nil
	case abi.IntTy, abi.UintTy:
		size := argument.Type.Size
		if size > 256 {
			return nil, fmt.Errorf("unsupported integer size: %d", size)
		}
		integer := new(big.Int).SetBytes(topic[:])
		if argument.Type.T == abi.IntTy && size < 256 {
			integer = adjustIntSize(integer, size)
		}
		return integer, nil
	case abi.StringTy:
		return topic, nil
	case abi.BytesTy, abi.FixedBytesTy:
		return topic.Bytes(), nil
	case abi.SliceTy, abi.ArrayTy:
		return nil, fmt.Errorf("array/slice decoding not implemented")
	default:
		return nil, fmt.Errorf("decoding for type %v not implemented", argument.Type.T)
	}
}

// adjustIntSize adjusts the size of an integer to match its ABI-specified size, which is relevant
// for signed integers smaller than 256 bits. This function ensures the integer is correctly
// interpreted according to its defined bit size in the ABI.
func adjustIntSize(integer *big.Int, size int) *big.Int {
	if size == 256 || integer.Bit(size-1) == 0 {
		return integer
	}
	return new(big.Int).Sub(integer, new(big.Int).Lsh(big.NewInt(1), uint(size)))
}

// GetTopicByName searches for and returns a Topic by its name from a slice of Topic instances.
// It facilitates accessing specific topics directly by name rather than iterating over the slice.
// If the topic is not found, it returns nil.
func GetTopicByName(name string, topics []Topic) *Topic {
	for _, topic := range topics {
		if topic.Name == name {
			return &topic
		}
	}
	return nil
}
