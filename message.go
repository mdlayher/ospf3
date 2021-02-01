package ospf3

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	// version is the OSPF version supported by this library (OSPFv3).
	version = 3

	// Fixed length structures. Note that some messages don't have constants
	// here because they only contain trailing variable length data.
	headerLen    = 16
	lsaLen       = 12
	lsaHeaderLen = 20
	helloLen     = 20 // No trailing array of neighbor IDs.
	ddLen        = 12 // No trailing array of LSA headers.
)

// Sentinel errors used to differentiate various types of errors in tests.
var (
	errMarshal = errors.New("failed to marshal bytes")
	errParse   = errors.New("failed to parse bytes")
)

// A packetType is the type of an OSPFv3 packet.
type packetType uint8

// Possible OSPFv3 packet types.
const (
	hello                    packetType = 1
	databaseDescription      packetType = 2
	linkStateRequest         packetType = 3
	linkStateUpdate          packetType = 4
	linkStateAcknowledgement packetType = 5
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

// options parses Options as a uint32 and then masks off the high 8 bits to
// interpret b as a 24-bit Options bitmask.
func options(b []byte) Options {
	return Options(binary.BigEndian.Uint32(b) & 0x00ffffff)
}

// valid checks if the Options bitmask is valid; that is, if it only has bits
// set in the lower 24 bits of the uint32.
func (o Options) valid() bool { return (o & 0xff000000) == 0 }

// String returns the string representation of an Options bitmask.
func (o Options) String() string {
	return flagsString(uint(o), []string{
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
	})
}

// A Header is the OSPFv3 packet header as described in RFC5340, appendix A.3.1.
// Headers accompany each Message implementation. The Header only allows setting
// OSPFv3 header fields which are not calculated programmatically. Version,
// packet type, and packet length are set automatically when calling
// MarshalMessage.
type Header struct {
	RouterID   ID
	AreaID     ID
	Checksum   uint16
	InstanceID uint8
}

// marshal packs a Header's bytes into b while also setting packet type and
// length. It assumes b has allocated enough space for a Header to avoid a
// panic.
func (h *Header) marshal(b []byte, ptyp packetType, plen uint16) {
	b[0] = version
	b[1] = byte(ptyp)
	binary.BigEndian.PutUint16(b[2:4], plen)
	copy(b[4:8], h.RouterID[:])
	copy(b[8:12], h.AreaID[:])
	binary.BigEndian.PutUint16(b[12:14], h.Checksum)
	b[14] = h.InstanceID
	// b[15] is reserved.
}

// parseHeader parses an OSPFv3 Header and the offset of the end of an OSPF
// packet from bytes.
func parseHeader(b []byte) (Header, packetType, int, error) {
	if l := len(b); l < headerLen {
		return Header{}, 0, 0, fmt.Errorf("not enough bytes for OSPFv3 header: %d: %w", l, errParse)
	}

	if v := b[0]; v != version {
		return Header{}, 0, 0, fmt.Errorf("unrecognized OSPF version: %d: %w", v, errParse)
	}

	h := Header{
		Checksum:   binary.BigEndian.Uint16(b[12:14]),
		InstanceID: b[14],
		// b[15] is reserved.
	}
	copy(h.RouterID[:], b[4:8])
	copy(h.AreaID[:], b[8:12])

	// TODO(mdlayher): inspect Checksum?

	// Make sure the input buffer has enough data as indicated by the packet
	// length field so we know how much to pass to Message.unmarshal.
	plen := int(binary.BigEndian.Uint16(b[2:4]))
	if plen < headerLen {
		return Header{}, 0, 0, fmt.Errorf("header packet length %d is too short for a valid packet: %w", plen, errParse)
	}
	if l := len(b); l < plen {
		return Header{}, 0, 0, fmt.Errorf("header packet length is %d bytes but only %d bytes are available: %w",
			plen, l, errParse)
	}

	return h, packetType(b[1]), plen, nil
}

// A Message is an OSPFv3 message.
type Message interface {
	len() int
	marshal(b []byte) error
	unmarshal(b []byte) error
}

// MarshalMessage turns a Message into OSPFv3 packet bytes.
func MarshalMessage(m Message) ([]byte, error) {
	if m == nil {
		return nil, fmt.Errorf("ospf3: cannot marshal nil Message: %w", errMarshal)
	}

	// Allocate enough space for the fixed length Header and then the
	// appropriate number of bytes for the trailing message.
	b := make([]byte, m.len())
	if err := m.marshal(b); err != nil {
		return nil, fmt.Errorf("ospf3: failed to marshal Message: %w", err)
	}

	return b, nil
}

// ParseMessage parses an OSPFv3 Header and trailing Message from bytes.
func ParseMessage(b []byte) (Message, error) {
	// The Header is added to each Message and the parsed type and length are
	// used to choose the appropriate Message and its end offset.
	h, ptyp, plen, err := parseHeader(b)
	if err != nil {
		return nil, fmt.Errorf("ospf3: failed to parse Header: %w", err)
	}

	// Now that we've decoded the Header we can identify the rest of the
	// payload as a known Message type.
	var m Message
	switch ptyp {
	case hello:
		m = &Hello{Header: h}
	case databaseDescription:
		m = &DatabaseDescription{Header: h}
	case linkStateRequest:
		m = &LinkStateRequest{Header: h}
	case linkStateAcknowledgement:
		m = &LinkStateAcknowledgement{Header: h}
	default:
		// TODO(mdlayher): implement more Messages!
		return nil, fmt.Errorf("ospf3: parsing not implemented message type: %d", ptyp)
	}

	// The unmarshal methods assume the header has already been processed so
	// just pass the rest of the payload up to the max defined by
	// Header.PacketLength.
	if err := m.unmarshal(b[headerLen:plen]); err != nil {
		return nil, fmt.Errorf("ospf3: failed to parse Message: %w", err)
	}

	return m, nil
}

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

// len implements Message.
func (h *Hello) len() int {
	// Fixed Header and Hello, plus 4 bytes per neighbor ID.
	return headerLen + helloLen + (4 * len(h.NeighborIDs))
}

// marshal implements Message.
func (h *Hello) marshal(b []byte) error {
	if !h.Options.valid() {
		return fmt.Errorf("Hello Options bitmask is not valid: %w", errMarshal)
	}

	// Marshal the Header and then store the Hello bytes following it.
	const n = headerLen
	h.Header.marshal(b[:n], hello, uint16(h.len()))

	binary.BigEndian.PutUint32(b[n:n+4], h.InterfaceID)
	// Router priority is 8 bits, Options is 24 bits immediately following.
	binary.BigEndian.PutUint32(b[n+4:n+8], uint32(h.RouterPriority)<<24|uint32(h.Options))
	putUint16Seconds(b[n+8:n+10], h.HelloInterval)
	putUint16Seconds(b[n+10:n+12], h.RouterDeadInterval)
	copy(b[n+12:n+16], h.DesignatedRouterID[:])
	copy(b[n+16:n+20], h.BackupDesignatedRouterID[:])

	// Each neighbor ID is packed into 4 adjacent bytes.
	nn := n + 20
	for i := range h.NeighborIDs {
		copy(b[nn:nn+4], h.NeighborIDs[i][:])
		nn += 4
	}

	return nil
}

// unmarshal implements Message.
func (h *Hello) unmarshal(b []byte) error {
	if l := len(b); l < helloLen {
		return fmt.Errorf("not enough bytes for Hello: %d: %w", l, errParse)
	}

	// Hello must end on a 4 byte boundary so we can parse any possible
	// NeighborIDs in the trailing array.
	if l := len(b); l%4 != 0 {
		return fmt.Errorf("Hello message must end on a 4 byte boundary, got %d bytes: %w", l, errParse)
	}

	h.InterfaceID = binary.BigEndian.Uint32(b[0:4])
	h.RouterPriority = b[4]
	// Options is 24 bits.
	h.Options = options(b[4:8])
	h.HelloInterval = uint16Seconds(b[8:10])
	h.RouterDeadInterval = uint16Seconds(b[10:12])
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

// DDFlags are flags which may appear in an OSPFv3 Database Description message
// as described in RFC5340, appendix A.3.3.
type DDFlags uint16

// Possible DDFlags values.
const (
	MSBit DDFlags = 1 << 0
	MBit  DDFlags = 1 << 1
	IBit  DDFlags = 1 << 2
)

// String returns the string representation of a DDFlags bitmask.
func (f DDFlags) String() string {
	return flagsString(uint(f), []string{
		"MS-bit",
		"M-bit",
		"I-bit",
	})
}

var _ Message = &DatabaseDescription{}

// A DatabaseDescription is an OSPFv3 Database Description message as described
// in RFC5340, appendix A.3.3.
type DatabaseDescription struct {
	Header         Header
	Options        Options
	InterfaceMTU   uint16
	Flags          DDFlags
	SequenceNumber uint32
	LSAs           []LSAHeader
}

// len implements Message.
func (dd *DatabaseDescription) len() int {
	// Fixed Header and DatabaseDescription, plus 20 bytes per LSA header.
	return headerLen + ddLen + (lsaHeaderLen * len(dd.LSAs))
}

// marshal implements Message.
func (dd *DatabaseDescription) marshal(b []byte) error {
	if !dd.Options.valid() {
		return fmt.Errorf("Hello Options bitmask is not valid: %w", errMarshal)
	}

	// Marshal the Header and then store the Database Description bytes following it.
	const n = headerLen
	dd.Header.marshal(b[:n], databaseDescription, uint16(dd.len()))

	binary.BigEndian.PutUint32(b[n:n+4], uint32(dd.Options))
	binary.BigEndian.PutUint16(b[n+4:n+6], dd.InterfaceMTU)
	// b[6] is reserved.
	b[n+7] = byte(dd.Flags)
	binary.BigEndian.PutUint32(b[n+8:n+12], dd.SequenceNumber)

	// Each LSA header is packed into 20 adjacent bytes.
	nn := n + 12
	for i := range dd.LSAs {
		dd.LSAs[i].marshal(b[nn : nn+lsaHeaderLen])
		nn += lsaHeaderLen
	}

	return nil
}

// unmarshal implements Message.
func (dd *DatabaseDescription) unmarshal(b []byte) error {
	if l := len(b); l < ddLen {
		return fmt.Errorf("not enough bytes for DatabaseDescription: %d: %w", l, errParse)
	}

	// b[0] is reserved.
	// Options is 24 bits.
	dd.Options = options(b[0:4])
	dd.InterfaceMTU = binary.BigEndian.Uint16(b[4:6])
	// b[6] is reserved
	dd.Flags = DDFlags(b[7])
	dd.SequenceNumber = binary.BigEndian.Uint32(b[8:12])

	// DatabaseDescription must end on a 20 byte boundary so we can parse any
	// possible LSAHeaders in the trailing array.
	const lsaOff = 12
	if l := len(b[lsaOff:]); l%lsaHeaderLen != 0 {
		return fmt.Errorf("DatabaseDescription message must end on a 20 byte boundary for trailing LSA headers, got %d bytes: %w", l, errParse)
	}

	// We now know the number of LSA headers because they have a fixed size.
	n := len(b[lsaOff:]) / lsaHeaderLen
	dd.LSAs = make([]LSAHeader, 0, n)
	for i := 0; i < n; i++ {
		// Parse each 20 byte LSA header from the slice.
		var (
			start = lsaOff + (i * lsaHeaderLen)
			end   = lsaOff + lsaHeaderLen + (i * lsaHeaderLen)
		)

		dd.LSAs = append(dd.LSAs, parseLSAHeader(b[start:end]))
	}

	return nil
}

var _ Message = &LinkStateRequest{}

// A LinkStateRequest is an OSPFv3 Link State Request message as described
// in RFC5340, appendix A.3.4.
type LinkStateRequest struct {
	Header Header
	LSAs   []LSA
}

// len implements Message.
func (lsr *LinkStateRequest) len() int {
	// Fixed Header plus 12 bytes per LSA. Notably this message has no body
	// of its own.
	return headerLen + (lsaLen * len(lsr.LSAs))
}

// marshal implements Message.
func (lsr *LinkStateRequest) marshal(b []byte) error {
	// Marshal the Header and then store the LSA bytes following it.
	const n = headerLen
	lsr.Header.marshal(b[:n], linkStateRequest, uint16(lsr.len()))

	// Each LSA is packed into 12 adjacent bytes.
	nn := n
	for i := range lsr.LSAs {
		// LSA.Type offset is 2 bytes in due to reserved space.
		lsr.LSAs[i].marshal(b[2+nn : nn+lsaLen])
		nn += lsaLen
	}

	return nil
}

// unmarshal implements Message.
func (lsr *LinkStateRequest) unmarshal(b []byte) error {
	// LinkStateRequest must end on a 12 byte boundary so we can parse any
	// possible LSAs in the trailing array.
	if l := len(b); l%lsaLen != 0 {
		return fmt.Errorf("LinkStateRequest message must end on a 12 byte boundary for trailing LSAs, got %d bytes: %w", l, errParse)
	}

	// We now know the number of LSAs because they have a fixed size.
	n := len(b) / lsaLen
	lsr.LSAs = make([]LSA, 0, n)
	for i := 0; i < n; i++ {
		// Parse each 12 byte LSA from the slice. Note that the first two bytes
		// are reserved so start parsing LSA.Type at 2 bytes.
		var (
			start = 2 + (i * lsaLen)
			end   = lsaLen + (i * lsaLen)
		)

		lsr.LSAs = append(lsr.LSAs, parseLSA(b[start:end]))
	}

	return nil
}

var _ Message = &LinkStateAcknowledgement{}

// A LinkStateAcknowledgement is an OSPFv3 Link State Acknowledgement message as
// described in RFC5340, appendix A.3.6.
type LinkStateAcknowledgement struct {
	Header Header
	LSAs   []LSAHeader
}

// len implements Message.
func (lsa *LinkStateAcknowledgement) len() int {
	// Fixed Header plus 20 bytes per LSA header. Notably this message has no
	// body of its own.
	return headerLen + (lsaHeaderLen * len(lsa.LSAs))
}

// marshal implements Message.
func (lsa *LinkStateAcknowledgement) marshal(b []byte) error {
	// Marshal the Header and then store the LSA header bytes following it.
	const n = headerLen
	lsa.Header.marshal(b[:n], linkStateAcknowledgement, uint16(lsa.len()))

	// Each LSA header is packed into 20 adjacent bytes.
	nn := n
	for i := range lsa.LSAs {
		lsa.LSAs[i].marshal(b[nn : nn+lsaHeaderLen])
		nn += lsaHeaderLen
	}

	return nil
}

// unmarshal implements Message.
func (lsa *LinkStateAcknowledgement) unmarshal(b []byte) error {
	// LinkStateAcknowledgement must end on a 20 byte boundary so we can parse
	// any possible LSAHeaders in the trailing array.
	if l := len(b); l%lsaHeaderLen != 0 {
		return fmt.Errorf("LinkStateAcknowledgement message must end on a 20 byte boundary for trailing LSA headers, got %d bytes: %w", l, errParse)
	}

	// We now know the number of LSA headers because they have a fixed size.
	n := len(b) / lsaHeaderLen
	lsa.LSAs = make([]LSAHeader, 0, n)
	for i := 0; i < n; i++ {
		// Parse each 20 byte LSA header from the slice.
		var (
			start = i * lsaHeaderLen
			end   = lsaHeaderLen + (i * lsaHeaderLen)
		)

		lsa.LSAs = append(lsa.LSAs, parseLSAHeader(b[start:end]))
	}

	return nil
}

// An LSType is the type of an OSPFv3 Link State Advertisement as described in
// RFC5340, appendix A.4.2.1.
type LSType uint16

// Possible LSType values.
const (
	RouterLSA          LSType = 0x2001
	NetworkLSA         LSType = 0x2002
	InterAreaPrefixLSA LSType = 0x2003
	InterAreaRouterLSA LSType = 0x2004
	ASExternalLSA      LSType = 0x4005
	deprecatedLSA      LSType = 0x2006
	NSSALSA            LSType = 0x2007
	LinkLSA            LSType = 0x0008
	IntraAreaPrefixLSA LSType = 0x2009
)

// LSAHandling returns the value of the U-bit in the LSType. False indicates the
// LSA should be treated as if it had link-local flooding scope. True indicates
// that a router should store and flood the LSA as if the type is understood.
func (t LSType) LSAHandling() bool {
	return (t & 0xf000) != 0
}

// FloodingScope returns the LSA flooding scope value stored in the S1 and S2
// bits in the LSType.
func (t LSType) FloodingScope() FloodingScope {
	return FloodingScope((t & 0x6000) >> 13)
}

// A FloodingScope is an OSPFv3 LSA flooding scope as described in RFC 5340,
// appendix A.4.2.1.
type FloodingScope uint8

// Possible FloodingScope values.
const (
	LinkLocalScoping FloodingScope = 0b00
	AreaScoping      FloodingScope = 0b01
	ASScoping        FloodingScope = 0b10
	reservedScoping  FloodingScope = 0b11
)

// An LSA is an OSPFv3 Link State Advertisement as described in RFC5340, section
// 4.4.
type LSA struct {
	Type              LSType
	LinkStateID       ID
	AdvertisingRouter ID
}

// marshal packs an LSA's bytes into b. It assumes b has allocated enough space
// for an LSA to avoid a panic.
func (l LSA) marshal(b []byte) {
	binary.BigEndian.PutUint16(b[0:2], uint16(l.Type))
	copy(b[2:6], l.LinkStateID[:])
	copy(b[6:10], l.AdvertisingRouter[:])
}

// parseLSA unpacks an LSA from a byte slice.
func parseLSA(b []byte) LSA {
	l := LSA{Type: LSType(binary.BigEndian.Uint16(b[0:2]))}
	copy(l.LinkStateID[:], b[2:6])
	copy(l.AdvertisingRouter[:], b[6:10])
	return l
}

// An LSAHeader is an OSPFv3 Link State Advertisement header as described in
// RFC5340, appendix A.4.2.
type LSAHeader struct {
	Age            time.Duration
	LSA            LSA
	SequenceNumber uint32
	Checksum       uint16
	Length         uint16
}

// marshal stores the LSAHeader bytes into b. It assumes b has allocated enough
// space for an LSAHeader to avoid a panic.
func (h LSAHeader) marshal(b []byte) {
	putUint16Seconds(b[0:2], h.Age)
	h.LSA.marshal(b[2:12])
	binary.BigEndian.PutUint32(b[12:16], h.SequenceNumber)
	binary.BigEndian.PutUint16(b[16:18], h.Checksum)
	binary.BigEndian.PutUint16(b[18:20], h.Length)
}

// parseLSAHeader unpacks an LSAHeader from a byte slice.
func parseLSAHeader(b []byte) LSAHeader {
	return LSAHeader{
		Age:            uint16Seconds(b[0:2]),
		LSA:            parseLSA(b[2:12]),
		SequenceNumber: binary.BigEndian.Uint32(b[12:16]),
		Checksum:       binary.BigEndian.Uint16(b[16:18]),
		Length:         binary.BigEndian.Uint16(b[18:20]),
	}
}

// uint16Seconds interprets big endian uint16 bytes as a number of seconds.
func uint16Seconds(b []byte) time.Duration {
	return time.Duration(binary.BigEndian.Uint16(b)) * time.Second
}

// putUint16Seconds stores d in b as big endian uint16 bytes, rounded to the
// nearest whole second.
func putUint16Seconds(b []byte, d time.Duration) {
	binary.BigEndian.PutUint16(b, uint16(d.Round(time.Second).Seconds()))
}

// flagsString generates a pretty-printed flags bitmask using the input value
// and sequence of names.
func flagsString(f uint, names []string) string {
	var s string
	left := f
	for i, name := range names {
		if f&(1<<uint(i)) != 0 {
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
