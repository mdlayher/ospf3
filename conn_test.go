package ospf3_test

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/ospf3"
)

func TestConn(t *testing.T) {
	c1, c2 := testConns(t)

	// Pass a series of fixed messages from a sender to a receiver and then
	// verify that information at the end of the test.
	const n = 3
	type msg struct {
		ID ospf3.ID
		IP net.IP
	}

	var (
		id   = ospf3.ID{192, 0, 2, 1}
		msgC = make(chan msg, n)
	)

	var wg sync.WaitGroup
	wg.Add(2)
	defer wg.Wait()

	// Send multicast Hello messages.
	go func() {
		defer wg.Done()

		for i := 0; i < n; i++ {
			err := c1.WriteTo(
				&ospf3.Hello{Header: ospf3.Header{RouterID: id}},
				nil,
				ospf3.AllSPFRouters,
			)
			if err != nil {
				panicf("failed to write Hello: %v", err)
			}
		}
	}()

	// Receive messages and pass them back to the main goroutine on the channel.
	go func() {
		defer func() {
			close(msgC)
			wg.Done()
		}()

		for i := 0; i < n; i++ {
			m, cm, _, err := c2.ReadFrom()
			if err != nil {
				panicf("failed to read Message: %v", err)
			}

			// Enforce IPv6 header invariants.
			if cm.HopLimit != 1 || cm.TrafficClass != 0xc0 {
				panicf("invalid IPv6 control message: %+v", cm)
			}

			msgC <- msg{
				// TODO(mdlayher): consider adding a Header method to the
				// Message interface.
				ID: m.(*ospf3.Hello).Header.RouterID,
				IP: cm.Dst,
			}
		}
	}()

	// Verify that every message has the expected contents.
	for m := range msgC {
		if diff := cmp.Diff(msg{ID: id, IP: ospf3.AllSPFRouters.IP}, m); diff != "" {
			t.Fatalf("unexpected message (-want +got):\n%s", diff)
		}
	}
}

// testConns sets up a pair of *ospf3.Conns pointed at each other using a fixed
// set of veth interfaces for integration testing purposes.
func testConns(t *testing.T) (c1, c2 *ospf3.Conn) {
	t.Helper()

	var veths [2]*net.Interface
	for i, v := range []string{"vethospf0", "vethospf1"} {
		ifi, err := net.InterfaceByName(v)
		if err != nil {
			var nerr *net.OpError
			if errors.As(err, &nerr) && nerr.Err.Error() == "no such network interface" {
				t.Skipf("skipping, interface %q does not exist", v)
			}

			t.Fatalf("failed to get interface %q: %v", v, err)
		}

		veths[i] = ifi
	}

	// Now that we have the veths, make sure they're usable.
	waitInterfacesReady(t, veths[0], veths[1])

	var conns [2]*ospf3.Conn
	for i, v := range veths {
		c, err := ospf3.Listen(v)
		if err != nil {
			if errors.Is(err, os.ErrPermission) {
				t.Skipf("skipping, permission denied while trying to listen OSPFv3 on %q", v.Name)
			}

			t.Fatalf("failed to listen OSPFv3 on %q: %v", v.Name, err)
		}

		conns[i] = c
		t.Cleanup(func() { c.Close() })
	}

	return conns[0], conns[1]
}

func waitInterfacesReady(t *testing.T, a, b *net.Interface) {
	t.Helper()

	for i := 0; i < 5; i++ {
		if i > 0 {
			time.Sleep(1 * time.Second)
			t.Log("waiting for interface readiness...")
		}

		aaddrs, err := a.Addrs()
		if err != nil {
			t.Fatalf("failed to get first addresses: %v", err)
		}

		baddrs, err := b.Addrs()
		if err != nil {
			t.Fatalf("failed to get second addresses: %v", err)
		}

		if len(aaddrs) == 0 || len(baddrs) == 0 {
			// No addresses yet.
			continue
		}

		// Do we have a link-local address assigned to each interface, and
		// can we bind to that address?
		if !linkLocalReady(t, aaddrs, a.Name) || !linkLocalReady(t, baddrs, b.Name) {
			continue
		}

		return
	}

	t.Fatal("failed to wait for interface readiness")
}

func linkLocalReady(t *testing.T, addrs []net.Addr, zone string) bool {
	t.Helper()

	for _, a := range addrs {
		ip, ok := a.(*net.IPNet)
		if !ok {
			continue
		}

		if ip.IP.To16() == nil || ip.IP.To4() != nil || !ip.IP.IsLinkLocalUnicast() {
			continue
		}

		// We've found a link-local IPv6 address. Try to bind a random socket to
		// it to verify the address is ready for use.
		addr := &net.UDPAddr{
			IP:   ip.IP,
			Port: 0,
			Zone: zone,
		}

		l, err := net.ListenPacket("udp", addr.String())
		if err != nil {
			return false
		}
		_ = l.Close()

		t.Logf("ready: %s", addr.String())

		return true
	}

	return false
}

func panicf(format string, a ...interface{}) {
	panic(fmt.Sprintf(format, a...))
}
