package ospf3

import (
	"encoding/binary"
	"fmt"
	"time"
)

// Version is the OSPF version supported by this library (OSPFv3).
const Version = 3

// A PacketType is the type of an OSPFv3 packet.
type PacketType uint8

// Possible OSPFv3 packet types.
const (
	HelloPacket                    PacketType = 1
	DatabaseDescriptionPacket      PacketType = 2
	LinkStateRequestPacket         PacketType = 3
	LinkStateUpdatePacket          PacketType = 4
	LinkStateAcknowledgementPacket PacketType = 5
)

// An ID is a four byte identifier typically used for OSPFv3 router and/or area
// IDs in a dotted-decimal IPv4 format.
type ID [4]byte

func (id ID) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", id[0], id[1], id[2], id[3])
}

// Options is a bitmask of OSPFv3 options as described in RFC5340, appendix A.2.
type Options uint32

// Possible OSPFv3 options bits.
const (
	V6Bit    Options = 1 << 0
	EBit     Options = 1 << 1
	xBit     Options = 1 << 2
	NBit     Options = 1 << 3
	RBit     Options = 1 << 4
	DCBit    Options = 1 << 5
	star1Bit Options = 1 << 6
	star2Bit Options = 1 << 7
	AFBit    Options = 1 << 8
	LBit     Options = 1 << 9
	ATBit    Options = 1 << 10
)

// String returns the string representation of an Options bitmask.
func (o Options) String() string {
	names := []string{
		"V6-bit",
		"E-bit",
		"x-bit",
		"N-bit",
		"R-bit",
		"DC-bit",
		"*-bit",
		"*-bit",
		"AF-bit",
		"L-bit",
		"AT-bit",
	}

	var s string
	left := uint(o)
	for i, name := range names {
		if o&(1<<uint(i)) != 0 {
			if s != "" {
				s += "|"
			}

			s += name

			left ^= (1 << uint(i))
		}
	}

	if s == "" && left == 0 {
		s = "0"
	}

	if left > 0 {
		if s != "" {
			s += "|"
		}
		s += fmt.Sprintf("%#x", left)
	}

	return s
}

// headerLen is the length of an OSPFv3 header.
const headerLen = 16

// A Header is the OSPFv3 packet header as described in RFC5340, appendix A.3.1.
type Header struct {
	Version      uint8
	Type         PacketType
	PacketLength uint16
	RouterID     ID
	AreaID       ID
	Checksum     uint16
	InstanceID   uint8
}

// parseHeader parses an OSPFv3 Header and the offset of the end of an OSPF
// packet from bytes.
func parseHeader(b []byte) (Header, int, error) {
	if l := len(b); l < headerLen {
		return Header{}, 0, fmt.Errorf("ospf3: not enough bytes for OSPFv3 header: %d", l)
	}

	if v := b[0]; v != Version {
		return Header{}, 0, fmt.Errorf("ospf3: unrecognized OSPF version: %d", v)
	}

	h := Header{
		Version:      b[0],
		Type:         PacketType(b[1]),
		PacketLength: binary.BigEndian.Uint16(b[2:4]),
		Checksum:     binary.BigEndian.Uint16(b[12:14]),
		InstanceID:   b[14],
		// b[15] is reserved.
	}
	copy(h.RouterID[:], b[4:8])
	copy(h.AreaID[:], b[8:12])

	// TODO(mdlayher): inspect Checksum?

	// Make sure the input buffer has enough data as indicated by the packet
	// length field so we know how much to pass to Message.unmarshal.
	if h.PacketLength < headerLen {
		return Header{}, 0, fmt.Errorf("ospf3: header packet length %d is too short for a valid packet", h.PacketLength)
	}
	if l := len(b); l < int(h.PacketLength) {
		return Header{}, 0, fmt.Errorf("ospf3: header packet length is %d bytes but only %d bytes are available",
			h.PacketLength, l)
	}

	// Clamp the max to the packet length if it's shorter than the buffer.
	max := len(b)
	if int(h.PacketLength) < len(b) {
		max = int(h.PacketLength)
	}

	return h, max, nil
}

// A Message is an OSPFv3 message.
type Message interface {
	unmarshal(b []byte) error
}

// ParseMessage parses an OSPFv3 Header and trailing Message from bytes.
func ParseMessage(b []byte) (Message, error) {
	// The Header is added to each Message and max is the offset where the
	// packet ends.
	h, max, err := parseHeader(b)
	if err != nil {
		return nil, err
	}

	// Now that we've decoded the Header we can identify the rest of the
	// payload as a known Message type.
	var m Message
	switch h.Type {
	case HelloPacket:
		m = &Hello{Header: h}
	default:
		// TODO(mdlayher): implement more Messages!
		return nil, fmt.Errorf("ospf3: parsing not implemented message type: %s", h.Type)
	}

	// The unmarshal methods assume the header has already been processed so
	// just pass the rest of the payload up to the max defined by
	// Header.PacketLength.
	if err := m.unmarshal(b[headerLen:max]); err != nil {
		return nil, err
	}

	return m, nil
}

// TODO(mdlayher): consider breaking out Hello/HelloSeen or using methods to
// more clearly differentiate whether or not NeighborID is or should be set.

var _ Message = &Hello{}

// A Hello is an OSPFv3 Hello message as described in RFC5340, appendix A.3.2.
type Hello struct {
	Header                   Header
	InterfaceID              uint32
	RouterPriority           uint8
	Options                  Options
	HelloInterval            time.Duration
	RouterDeadInterval       time.Duration
	DesignatedRouterID       ID
	BackupDesignatedRouterID ID
	NeighborIDs              []ID
}

// helloLen is the length of a Hello message with no trailing array of neighbor
// IDs.
const helloLen = 20

// unmarshal implements Message.
func (h *Hello) unmarshal(b []byte) error {
	if l := len(b); l < helloLen {
		return fmt.Errorf("ospf3: not enough bytes for Hello: %d", l)
	}

	// Hello must end on a 4 byte boundary so we can parse any possible
	// NeighborIDs in the trailing array.
	if l := len(b); l%4 != 0 {
		return fmt.Errorf("ospf3: Hello message must end on a 4 byte boundary, got %d bytes", l)
	}

	h.InterfaceID = binary.BigEndian.Uint32(b[0:4])
	h.RouterPriority = b[4]
	// Options is 24 bits.
	h.Options = Options(binary.BigEndian.Uint32(b[4:8]) & 0x00ffffff)
	h.HelloInterval = time.Duration(binary.BigEndian.Uint16(b[8:10])) * time.Second
	h.RouterDeadInterval = time.Duration(binary.BigEndian.Uint16(b[10:12])) * time.Second
	copy(h.DesignatedRouterID[:], b[12:16])
	copy(h.BackupDesignatedRouterID[:], b[16:20])

	// Allocate enough space for each trailing neighbor ID after the fixed
	// length Hello and parse each one.
	h.NeighborIDs = make([]ID, 0, len(b[helloLen:])/4)
	for i := helloLen; i < len(b); i += 4 {
		var id ID
		copy(id[:], b[i:i+4])
		h.NeighborIDs = append(h.NeighborIDs, id)
	}

	return nil
}
