package ospf3

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

var (
	msgHello = []byte{
		// Header
		version,      // OSPFv3
		uint8(hello), // Hello
		0x00, 44,     // PacketLength
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
		// Neighbor IDs
		192, 0, 2, 2,
		192, 0, 2, 3,

		// LSA headers
		0x00, 0x01,
		0x00, 0x00,

		// Trailing bytes, ignored
		0x00, 0x00, 0x00, 0x00,
	}

	msgDatabaseDescription = []byte{
		// Header
		version,                    // OSPFv3
		uint8(databaseDescription), // Hello
		0x00, 68,                   // PacketLength
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

		// LSA headers
		//
		// Router-LSA
		0x00, 0x01, // Age
		byte(RouterLSA >> 8), byte(RouterLSA & 0x00ff), // Type
		0, 0, 0, 0, // Link state ID
		192, 0, 2, 1, // Advertising router
		0x00, 0x00, 0x00, 0xff, // Sequence number
		0x00, 0x00, // Checksum
		0x00, lsaHeaderLen, // Length

		// Link-LSA
		0x00, 0x02, // Age
		byte(LinkLSA >> 8), byte(LinkLSA & 0x00ff), // Type
		0, 0, 0, 5, // Link state ID
		192, 0, 2, 1, // Advertising router
		0x00, 0x00, 0x01, 0xff, // Sequence number
		0x00, 0x00, // Checksum
		0x00, lsaHeaderLen, // Length

		// Trailing bytes, ignored
		0x00, 0x00, 0x00, 0x00,
	}
)

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
				uint8(databaseDescription), // Hello
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

				// LSA headers, truncated
				0xff,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseMessage(tt.b)
			if err == nil {
				t.Fatal("expected an error, but none occurred")
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
			b:    msgHello,
			m: &Hello{
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
			},
		},
		{
			name: "database description",
			b:    msgDatabaseDescription,
			m: &DatabaseDescription{
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
						Age:               1 * time.Second,
						Type:              RouterLSA,
						AdvertisingRouter: ID{192, 0, 2, 1},
						SequenceNumber:    255,
						Length:            20,
					},
					{
						Age:               2 * time.Second,
						Type:              LinkLSA,
						LinkStateID:       ID{0, 0, 0, 5},
						AdvertisingRouter: ID{192, 0, 2, 1},
						SequenceNumber:    511,
						Length:            20,
					},
				},
			},
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

func BenchmarkMarshalMessage(b *testing.B) {
	tests := []struct {
		name string
		m    Message
	}{
		{
			name: "Hello",
			m: &Hello{
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
			},
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
			name: "Hello",
			b:    msgHello,
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
