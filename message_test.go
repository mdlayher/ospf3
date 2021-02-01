package ospf3

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

var (
	bufTrailing = []byte{0xff, 0xff, 0xff, 0xff}

	bufHeaderCommon = []byte{
		192, 0, 2, 1, // Router ID
		0, 0, 0, 0, // Area ID
		0x00, 0x00, // Checksum
		0x01, // InstanceID
		0x00, // Reserved
	}

	bufRouterLSA = []byte{
		byte(RouterLSA >> 8), byte(RouterLSA & 0x00ff), // Type
		0, 0, 0, 0, // Link state ID
		192, 0, 2, 1, // Advertising router
	}

	bufRouterLSAHeader = merge(
		[]byte{
			0x00, 0x01, // Age
		},
		bufRouterLSA,
		[]byte{
			0x00, 0x00, 0x00, 0xff, // Sequence number
			0x00, 0x00, // Checksum
			0x00, lsaHeaderLen, // Length
		},
	)

	bufLinkLSAHeader = merge(
		[]byte{
			0x00, 0x02, // Age
		},
		bufLinkLSA,
		[]byte{
			0x00, 0x00, 0x01, 0xff, // Sequence number
			0x00, 0x00, // Checksum
			0x00, lsaHeaderLen, // Length
		},
	)

	bufLinkLSA = []byte{
		byte(LinkLSA >> 8), byte(LinkLSA & 0x00ff), // Type
		0, 0, 0, 5, // Link state ID
		192, 0, 2, 1, // Advertising router
	}

	bufHello = merge(
		// Header
		[]byte{
			version,      // OSPFv3
			uint8(hello), // Hello
			0x00, 44,     // PacketLength
		},
		bufHeaderCommon,
		// Hello
		[]byte{
			0x00, 0x00, 0x00, 0x01, // Interface ID
			0x01,                                 // Router priority
			0x00, 0x00, byte(V6Bit) | byte(EBit), // Options
			0x00, 0x05, // Hello interval
			0x00, 0x0a, // Router dead interval
			192, 0, 2, 1, // Designated router ID
			192, 0, 2, 2, // Backup designated router ID
			// Neighbor IDs
			192, 0, 2, 2,
			192, 0, 2, 3,
		},
		// Ignored.
		bufTrailing,
	)

	msgHello = &Hello{
		Header: Header{
			RouterID:   ID{192, 0, 2, 1},
			InstanceID: 1,
		},
		InterfaceID:              1,
		RouterPriority:           1,
		Options:                  V6Bit | EBit,
		HelloInterval:            5 * time.Second,
		RouterDeadInterval:       10 * time.Second,
		DesignatedRouterID:       ID{192, 0, 2, 1},
		BackupDesignatedRouterID: ID{192, 0, 2, 2},
		NeighborIDs: []ID{
			{192, 0, 2, 2},
			{192, 0, 2, 3},
		},
	}

	bufDatabaseDescription = merge(
		// Header
		[]byte{
			version,                    // OSPFv3
			uint8(databaseDescription), // Database Description
			0x00, 68,                   // PacketLength
		},
		bufHeaderCommon,
		// DatabaseDescription
		[]byte{
			0x00, 0x00, byte(AFBit - 255), byte(V6Bit) | byte(EBit) | byte(RBit), // Options
			0x05, 0xdc, // Interface MTU
			0x00,                    // Reserved
			byte(IBit) | byte(MBit), // Flags
			0x00, 0x00, 0x00, 0x01,  // Sequence number
		},
		// LSA headers
		bufRouterLSAHeader,
		bufLinkLSAHeader,
		// Ignored.
		bufTrailing,
	)

	msgDatabaseDescription = &DatabaseDescription{
		Header: Header{
			RouterID:   ID{192, 0, 2, 1},
			InstanceID: 1,
		},
		Options:        V6Bit | EBit | RBit | AFBit,
		InterfaceMTU:   1500,
		Flags:          IBit | MBit,
		SequenceNumber: 1,
		LSAs: []LSAHeader{
			{
				Age: 1 * time.Second,
				LSA: LSA{
					Type:              RouterLSA,
					AdvertisingRouter: ID{192, 0, 2, 1},
				},
				SequenceNumber: 255,
				Length:         20,
			},
			{
				Age: 2 * time.Second,
				LSA: LSA{
					Type:              LinkLSA,
					LinkStateID:       ID{0, 0, 0, 5},
					AdvertisingRouter: ID{192, 0, 2, 1},
				},
				SequenceNumber: 511,
				Length:         20,
			},
		},
	}

	bufLinkStateRequest = merge(
		// Header
		[]byte{
			version,                 // OSPFv3
			uint8(linkStateRequest), // Link State Request
			0x00, 40,                // PacketLength
		},
		bufHeaderCommon,
		// LinkStateRequest LSAs (with reserved padding).
		[]byte{0x00, 0x00},
		bufRouterLSA,
		[]byte{0x00, 0x00},
		bufLinkLSA,
		// Ignored.
		bufTrailing,
	)

	msgLinkStateRequest = &LinkStateRequest{
		Header: Header{
			RouterID:   ID{192, 0, 2, 1},
			InstanceID: 1,
		},
		LSAs: []LSA{
			{
				Type:              RouterLSA,
				AdvertisingRouter: ID{192, 0, 2, 1},
			},
			{
				Type:              LinkLSA,
				LinkStateID:       ID{0, 0, 0, 5},
				AdvertisingRouter: ID{192, 0, 2, 1},
			},
		},
	}

	bufLinkStateAcknowledgement = merge(
		// Header
		[]byte{
			version,                         // OSPFv3
			uint8(linkStateAcknowledgement), // Link State Acknowledgement
			0x00, 56,                        // PacketLength
		},
		bufHeaderCommon,
		// LinkStateAcknowledgement LSA headers
		bufRouterLSAHeader,
		bufLinkLSAHeader,
		// Ignored.
		bufTrailing,
	)

	msgLinkStateAcknowledgement = &LinkStateAcknowledgement{
		Header: Header{
			RouterID:   ID{192, 0, 2, 1},
			InstanceID: 1,
		},
		LSAs: []LSAHeader{
			{
				Age: 1 * time.Second,
				LSA: LSA{
					Type:              RouterLSA,
					AdvertisingRouter: ID{192, 0, 2, 1},
				},
				SequenceNumber: 255,
				Length:         20,
			},
			{
				Age: 2 * time.Second,
				LSA: LSA{
					Type:              LinkLSA,
					LinkStateID:       ID{0, 0, 0, 5},
					AdvertisingRouter: ID{192, 0, 2, 1},
				},
				SequenceNumber: 511,
				Length:         20,
			},
		},
	}
)

func merge(bs ...[]byte) []byte {
	var out []byte
	for _, b := range bs {
		out = append(out, b...)
	}

	return out
}

func TestParseMessageErrors(t *testing.T) {
	tests := []struct {
		name string
		b    []byte
	}{
		{
			name: "empty",
		},
		{
			name: "OSPFv2",
			b: append(
				[]byte{0x02},
				bytes.Repeat([]byte{0x00}, 15)...,
			),
		},
		{
			name: "unknown message type",
			b: append(
				[]byte{version, 0xff},
				bytes.Repeat([]byte{0x00}, 14)...,
			),
		},
		{
			name: "short header",
			b: []byte{
				version,
				uint8(hello),
				0x00, 0x00, // Zero length
				0x00, 0x00,
				192, 0, 2, 1,
				0, 0, 0, 0,
				0x01,
				0x00,
			},
		},
		{
			name: "bad packet length",
			b: []byte{
				version,
				uint8(hello),
				0xff, 0xff, // Max length
				0x00, 0x00,
				192, 0, 2, 1,
				0, 0, 0, 0,
				0x01,
				0x00,
			},
		},
		{
			name: "short hello",
			b: []byte{
				version,
				uint8(hello),
				0x00, 17, // Header + 1 trailing byte
				0x00, 0x00,
				192, 0, 2, 1,
				0, 0, 0, 0,
				0x01,
				0x00,

				0xff, // Truncated Hello
			},
		},
		{
			name: "bad hello neighbor IDs",
			b: []byte{
				// Header
				version,      // OSPFv3
				uint8(hello), // Hello
				0x00, 39,     // PacketLength
				192, 0, 2, 1, // Router ID
				0, 0, 0, 0, // Area ID
				0x00, 0x00, // Checksum
				0x01, // InstanceID
				0x00, // Reserved

				// Hello
				0x00, 0x00, 0x00, 0x01, // Interface ID
				0x01,                                 // Router priority
				0x00, 0x00, byte(V6Bit) | byte(EBit), // Options
				0x00, 0x05, // Hello interval
				0x00, 0x0a, // Router dead interval
				192, 0, 2, 1, // Designated router ID
				192, 0, 2, 2, // Backup designated router ID
				// Neighbor IDs, truncated
				192, 0, 2,
			},
		},
		{
			name: "short database description",
			b: []byte{
				version,
				uint8(databaseDescription),
				0x00, 17, // Header + 1 trailing byte
				0x00, 0x00,
				192, 0, 2, 1,
				0, 0, 0, 0,
				0x01,
				0x00,

				0xff, // Truncated Database Description
			},
		},
		{
			name: "bad database description LSAs",
			b: []byte{
				// Header
				version,                    // OSPFv3
				uint8(databaseDescription), // Database Descriptions
				0x00, 29,                   // PacketLength
				192, 0, 2, 1, // Router ID
				0, 0, 0, 0, // Area ID
				0x00, 0x00, // Checksum
				0x01, // InstanceID
				0x00, // Reserved

				// DatabaseDescription
				0x00, 0x00, byte(AFBit - 255), byte(V6Bit) | byte(EBit) | byte(RBit), // Options
				0x05, 0xdc, // Interface MTU
				0x00,                    // Reserved
				byte(IBit) | byte(MBit), // Flags
				0x00, 0x00, 0x00, 0x01,  // Sequence number

				0xff, // Truncated LSA header
			},
		},
		{
			name: "bad link state request LSA",
			b: []byte{
				version,
				uint8(linkStateRequest),
				0x00, 17, // Header + 1 trailing byte
				0x00, 0x00,
				192, 0, 2, 1,
				0, 0, 0, 0,
				0x01,
				0x00,

				0xff, // Truncated LSA
			},
		},
		{
			name: "bad link state acknowledgement LSAs",
			b: []byte{
				version,
				uint8(linkStateAcknowledgement),
				0x00, 17, // Header + 1 trailing byte
				0x00, 0x00,
				192, 0, 2, 1,
				0, 0, 0, 0,
				0x01,
				0x00,

				0xff, // Truncated LSA header
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseMessage(tt.b)
			if diff := cmp.Diff(errParse, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected error (-want +got):\n%s", diff)
			}

			t.Logf("err: %v", err)
		})
	}
}

func TestMarshalMessageErrors(t *testing.T) {
	tests := []struct {
		name string
		m    Message
	}{
		{
			name: "untyped nil",
		},
		{
			name: "Hello Options",
			m: &Hello{
				Options: 0xf0000000 | V6Bit,
			},
		},
		{
			name: "DatabaseDescription Options",
			m: &DatabaseDescription{
				Options: 0xf0000000 | V6Bit,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := MarshalMessage(tt.m)
			if diff := cmp.Diff(errMarshal, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected error (-want +got):\n%s", diff)
			}

			t.Logf("err: %v", err)
		})
	}
}

func TestMessageRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		b    []byte
		m    Message
	}{
		{
			name: "hello",
			b:    bufHello,
			m:    msgHello,
		},
		{
			name: "database description",
			b:    bufDatabaseDescription,
			m:    msgDatabaseDescription,
		},
		{
			name: "link state request",
			b:    bufLinkStateRequest,
			m:    msgLinkStateRequest,
		},
		{
			name: "link state acknowledgement",
			b:    bufLinkStateAcknowledgement,
			m:    msgLinkStateAcknowledgement,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m1, err := ParseMessage(tt.b)
			if err != nil {
				t.Fatalf("failed to parse first Message: %v", err)
			}

			if diff := cmp.Diff(tt.m, m1); diff != "" {
				t.Fatalf("unexpected initial Message (-want +got):\n%s", diff)
			}

			b, err := MarshalMessage(m1)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}

			if diff := cmp.Diff(tt.b[:len(b)], b); diff != "" {
				t.Fatalf("unexpected bytes (-want +got):\n%s", diff)
			}

			m2, err := ParseMessage(b)
			if err != nil {
				t.Fatalf("failed to parse second Message: %v", err)
			}

			if diff := cmp.Diff(m1, m2); diff != "" {
				t.Fatalf("unexpected final Message (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_flagsString(t *testing.T) {
	tests := []struct {
		name  string
		f     uint
		names []string
		s     string
	}{
		{
			name: "empty",
			f:    1,
			s:    "0x1",
		},
		{
			name:  "known",
			f:     1<<0 | 1<<1 | 1<<2,
			names: []string{"A", "B", "C"},
			s:     "A|B|C",
		},
		{
			name:  "unknown",
			f:     1<<1 | 1<<3 | 1<<10,
			names: []string{"foo", "bar", "baz", "qux"},
			s:     "bar|qux|0x400",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.s, flagsString(tt.f, tt.names)); diff != "" {
				t.Fatalf("unexpected string (-want +got):\n%s", diff)
			}
		})
	}
}

func BenchmarkMarshalMessage(b *testing.B) {
	tests := []struct {
		name string
		m    Message
	}{
		{
			name: "hello",
			m:    msgHello,
		},
		{
			name: "database description",
			m:    msgDatabaseDescription,
		},
		{
			name: "link state request",
			m:    msgLinkStateRequest,
		},
		{
			name: "link state acknowledgement",
			m:    msgLinkStateAcknowledgement,
		},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := MarshalMessage(tt.m); err != nil {
					b.Fatalf("failed to marshal: %v", err)
				}
			}
		})
	}
}

func BenchmarkParseMessage(b *testing.B) {
	tests := []struct {
		name string
		b    []byte
	}{
		{
			name: "hello",
			b:    bufHello,
		},
		{
			name: "database description",
			b:    bufDatabaseDescription,
		},
		{
			name: "link state request",
			b:    bufLinkStateRequest,
		},
		{
			name: "link state acknowledgement",
			b:    bufLinkStateAcknowledgement,
		},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := ParseMessage(tt.b); err != nil {
					b.Fatalf("failed to parse: %v", err)
				}
			}
		})
	}
}
