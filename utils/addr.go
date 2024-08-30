package utils

import (
	"github.com/ethereum/go-ethereum/common"
	"bytes"
	"encoding/binary"
)

var (
	// ZeroAddress represents a zero Ethereum address
	ZeroAddress = common.HexToAddress("0x0000000000000000000000000000000000000000")

	// ZeroHash represents a hash value consisting of all zeros.
	ZeroHash = common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000")
)

// NamedAddr encapsulates detailed information about an Ethereum address along with its metadata.
// It includes a human-readable name, an optional Ethereum Name Service (ENS) domain, a set of
// tags for categorization or annotation, the Ethereum address itself, and the type of address
// which provides additional context about its use or origin.
type NamedAddr struct {
	Name string         `json:"name"`
	Ens  string         `json:"ens"`
	Tags []string       `json:"tags"`
	Addr common.Address `json:"addr"`
	Type AddressType    `json:"type"`
}

// AppendTags appends unique tags to the named address
func (n NamedAddr) AppendTags(tags ...string) NamedAddr {
	for _, tag := range tags {
		if !StringInSlice(tag, n.Tags) {
			n.Tags = append(n.Tags, tag)
		}
	}
	return n
}

func (n NamedAddr) Hex() string {
	return n.Addr.Hex()
}

// IsZeroAddress checks whenever named address is zero address
func (n NamedAddr) IsZeroAddress() bool {
	return n.Addr == ZeroAddress
}

// NamedAddr encapsulates detailed information about an Ethereum address along with its metadata.
// It includes a human-readable name, an optional Ethereum Name Service (ENS) domain, a set of
// tags for categorization or annotation, the Ethereum address itself, and the type of address
// which provides additional context about its use or origin.
type Addr struct {
	NetworkId NetworkID `json:"networkId"`
	Name string         `json:"name"`
	Ens  string         `json:"ens"`
	Tags []string       `json:"tags"`
	Addr common.Address `json:"addr"`
	Type AddressType    `json:"type"`
}

func (n *Addr) Hex() string {
	return n.Addr.Hex()
}

// AppendTags appends unique tags to the named address
func (n *Addr) AppendTags(tags ...string) *Addr {
	for _, tag := range tags {
		if !StringInSlice(tag, n.Tags) {
			n.Tags = append(n.Tags, tag)
		}
	}
	return n
}

// IsZeroAddress checks whenever named address is zero address
func (n *Addr) IsZeroAddress() bool {
	return n.Addr == ZeroAddress
}

// Encode serializes the Addr into bytes
func (n *Addr) Encode() ([]byte, error) {
	var buf bytes.Buffer

	// Encode NetworkId
	if err := binary.Write(&buf, binary.LittleEndian, n.NetworkId.Uint64()); err != nil {
		return nil, err
	}

	// Encode Name
	nameBytes := []byte(n.Name)
	nameLen := uint32(len(nameBytes))
	if err := binary.Write(&buf, binary.LittleEndian, nameLen); err != nil {
		return nil, err
	}
	if _, err := buf.Write(nameBytes); err != nil {
		return nil, err
	}

	// Encode ENS
	ensBytes := []byte(n.Ens)
	ensLen := uint32(len(ensBytes))
	if err := binary.Write(&buf, binary.LittleEndian, ensLen); err != nil {
		return nil, err
	}
	if _, err := buf.Write(ensBytes); err != nil {
		return nil, err
	}

	// Encode Tags
	tagsLen := uint32(len(n.Tags))
	if err := binary.Write(&buf, binary.LittleEndian, tagsLen); err != nil {
		return nil, err
	}

	for _, tag := range n.Tags {
		tagBytes := []byte(tag)
		tagLen := uint32(len(tagBytes))
		if err := binary.Write(&buf, binary.LittleEndian, tagLen); err != nil {
			return nil, err
		}
		if _, err := buf.Write(tagBytes); err != nil {
			return nil, err
		}
	}

	// Encode Addr
	if _, err := buf.Write(n.Addr.Bytes()); err != nil {
		return nil, err
	}

	// Encode Type
	typeBytes := []byte(n.Type)
	typeLen := uint32(len(typeBytes))
	if err := binary.Write(&buf, binary.LittleEndian, typeLen); err != nil {
		return nil, err
	}
	if _, err := buf.Write(typeBytes); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Decode deserializes bytes into Addr
func (n *Addr) Decode(data []byte) error {
	buf := bytes.NewReader(data)

	// Decode NetworkId
	var networkId uint64
	if err := binary.Read(buf, binary.LittleEndian, &networkId); err != nil {
		return err
	}
	n.NetworkId = NetworkID(networkId)

	// Decode Name
	var nameLen uint32
	if err := binary.Read(buf, binary.LittleEndian, &nameLen); err != nil {
		return err
	}
	nameBytes := make([]byte, nameLen)
	if _, err := buf.Read(nameBytes); err != nil {
		return err
	}
	n.Name = string(nameBytes)

	// Decode ENS
	var ensLen uint32
	if err := binary.Read(buf, binary.LittleEndian, &ensLen); err != nil {
		return err
	}
	ensBytes := make([]byte, ensLen)
	if _, err := buf.Read(ensBytes); err != nil {
		return err
	}
	n.Ens = string(ensBytes)

	// Decode Tags
	var tagsLen uint32
	if err := binary.Read(buf, binary.LittleEndian, &tagsLen); err != nil {
		return err
	}
	n.Tags = make([]string, tagsLen)
	for i := uint32(0); i < tagsLen; i++ {
		var tagLen uint32
		if err := binary.Read(buf, binary.LittleEndian, &tagLen); err != nil {
			return err
		}
		tagBytes := make([]byte, tagLen)
		if _, err := buf.Read(tagBytes); err != nil {
			return err
		}
		n.Tags[i] = string(tagBytes)
	}

	// Decode Addr
	addrBytes := make([]byte, common.AddressLength)
	if _, err := buf.Read(addrBytes); err != nil {
		return err
	}
	n.Addr = common.BytesToAddress(addrBytes)

	// Decode Type
	var typeLen uint32
	if err := binary.Read(buf, binary.LittleEndian, &typeLen); err != nil {
		return err
	}
	typeBytes := make([]byte, typeLen)
	if _, err := buf.Read(typeBytes); err != nil {
		return err
	}
	n.Type = AddressType(typeBytes)

	return nil
}
