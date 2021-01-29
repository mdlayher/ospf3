package ospf3

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestParseMessage(t *testing.T) {
	tests := []struct {
		name string
		b    []byte
		m    Message
		ok   bool
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
				[]byte{0x03, 0xff},
				bytes.Repeat([]byte{0x00}, 14)...,
			),
		},
		{
			name: "short header",
			b: []byte{
				0x03,
				uint8(HelloPacket),
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
				0x03,
				uint8(HelloPacket),
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
				0x03,
				uint8(HelloPacket),
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
			name: "OK hello",
			b: []byte{
				// Header
				0x03,               // OSPFv3
				uint8(HelloPacket), // Hello
				0x00, 40,           // PacketLength
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
				192, 0, 2, 2, // Neighbor ID

				// Trailing bytes, ignored
				0x00, 0x00, 0x00, 0x00,
			},
			m: &Hello{
				Header: Header{
					Version:      3,
					Type:         HelloPacket,
					PacketLength: 40,
					RouterID:     ID{192, 0, 2, 1},
					InstanceID:   1,
				},
				InterfaceID:              1,
				RouterPriority:           1,
				Options:                  V6Bit | EBit,
				HelloInterval:            5 * time.Second,
				RouterDeadInterval:       10 * time.Second,
				DesignatedRouterID:       ID{192, 0, 2, 1},
				BackupDesignatedRouterID: ID{192, 0, 2, 2},
				NeighborID:               &ID{192, 0, 2, 2},
			},
			ok: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := ParseMessage(tt.b)
			if tt.ok && err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatal("expected an error, but none occurred")
			}
			if err != nil {
				t.Logf("err: %v", err)
				return
			}

			if diff := cmp.Diff(tt.m, m); diff != "" {
				t.Fatalf("unexpected Message (-want +got):\n%s", diff)
			}
		})
	}
}
