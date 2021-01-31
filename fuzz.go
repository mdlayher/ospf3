package ospf3

import (
	"fmt"

	"github.com/google/go-cmp/cmp"
)

// fuzz is a shared function for go-fuzz and tests that verify go-fuzz bugs
// are fixed.
func fuzz(b1 []byte) int {
	// 1. parse, marshal, parse again to check m1 and m2 for equality after
	// a round trip.
	m1, err := ParseMessage(b1)
	if err != nil {
		return 0
	}

	b2, err := MarshalMessage(m1)
	if err != nil {
		panicf("failed to marshal: %v", err)
	}

	m2, err := ParseMessage(b2)
	if err != nil {
		panicf("failed to parse: %v", err)
	}

	if diff := cmp.Diff(m1, m2); diff != "" {
		panicf("unexpected Message (-want +got):\n%s", diff)
	}

	// 2. marshal again and compare b2 and b3 (b1 may have reserved bytes set
	// which we ignore and fill with zeros when marshaling) for equality.
	b3, err := MarshalMessage(m2)
	if err != nil {
		panicf("failed to marshal again: %v", err)
	}

	if diff := cmp.Diff(b2, b3); diff != "" {
		panicf("unexpected bytes (-want +got):\n%s", diff)
	}

	return 1
}

func panicf(format string, a ...interface{}) {
	panic(fmt.Sprintf(format, a...))
}
