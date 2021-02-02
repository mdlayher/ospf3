package ospf3

import (
	"net"
	"time"

	"golang.org/x/net/ipv6"
)

// Fixed IPv6 header parameters for Conn use.
const (
	tclass   = 0xc0 // DSCP CS6, per appendix A.1.
	hopLimit = 1
)

var (
	// AllSPFRouters is the IPv6 multicast group address that all routers
	// running OSPFv3 should participate in.
	AllSPFRouters = &net.IPAddr{IP: net.ParseIP("ff02::5")}

	// AllDRouters is the IPv6 multicast group address that the Designated
	// Router and Backup Designated Router running OSPFv3 must participate in.
	AllDRouters = &net.IPAddr{IP: net.ParseIP("ff02::6")}
)

// A Conn can send and receive OSPFv3 packets which implement the Packet
// interface.
type Conn struct {
	c      *ipv6.PacketConn
	ifi    *net.Interface
	groups []*net.IPAddr
}

// Listen creates a *Conn using the specified network interface.
func Listen(ifi *net.Interface) (*Conn, error) {
	// IP protocol number 89 is OSPF.
	conn, err := net.ListenPacket("ip6:89", "::")
	if err != nil {
		return nil, err
	}
	c := ipv6.NewPacketConn(conn)

	// Return all possible control message information to the caller so they
	// can make more informed choices.
	if err := c.SetControlMessage(^ipv6.ControlFlags(0), true); err != nil {
		return nil, err
	}

	// Process checksums in the OSPFv3 header.
	if err := c.SetChecksum(true, 12); err != nil {
		return nil, err
	}

	// Set IPv6 header parameters per the RFC.
	if err := c.SetHopLimit(hopLimit); err != nil {
		return nil, err
	}
	if err := c.SetMulticastHopLimit(hopLimit); err != nil {
		return nil, err
	}
	if err := c.SetTrafficClass(tclass); err != nil {
		return nil, err
	}

	// Join the appropriate multicast groups. Note that point-to-point links
	// don't use DR/BDR and can skip joining that group.
	if err := c.SetMulticastInterface(ifi); err != nil {
		return nil, err
	}

	groups := []*net.IPAddr{AllSPFRouters}
	if ifi.Flags&net.FlagPointToPoint == 0 {
		groups = append(groups, AllDRouters)
	}

	for _, g := range groups {
		if err := c.JoinGroup(ifi, g); err != nil {
			return nil, err
		}
	}

	// Don't read our own multicast packets during concurrent read/write.
	if err := c.SetMulticastLoopback(false); err != nil {
		return nil, err
	}

	return &Conn{
		c:      c,
		ifi:    ifi,
		groups: groups,
	}, nil
}

// Close closes the Conn's underlying network connection.
func (c *Conn) Close() error {
	for _, g := range c.groups {
		if err := c.c.LeaveGroup(c.ifi, g); err != nil {
			return err
		}
	}

	return c.c.Close()
}

// SetReadDeadline sets the read deadline associated with the Conn.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.c.SetReadDeadline(t)
}

// ReadFrom reads a single OSPFv3 packet and returns a Packet along with its
// associated IPv6 control message and source address. ReadFrom will block until
// a timeout occurs or a valid OSPFv3 packet is read.
func (c *Conn) ReadFrom() (Packet, *ipv6.ControlMessage, *net.IPAddr, error) {
	b := make([]byte, c.ifi.MTU)
	for {
		n, cm, src, err := c.c.ReadFrom(b)
		if err != nil {
			return nil, nil, nil, err
		}

		p, err := ParsePacket(b[:n])
		if err != nil {
			// Assume invalid OSPFv3 data, keep reading.
			continue
		}

		return p, cm, src.(*net.IPAddr), nil
	}
}

// WriteTo writes a single OSPFv3 Packet to the specified destination address
// or multicast group.
func (c *Conn) WriteTo(p Packet, dst *net.IPAddr) error {
	b, err := MarshalPacket(p)
	if err != nil {
		return err
	}

	// TODO(mdlayher): consider parameterizing control message if necessary but
	// it seems that x/net/ipv6 lets us configure the kernel to do a lot of the
	// work for us.
	_, err = c.c.WriteTo(b, nil, dst)
	return err
}
