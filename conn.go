package ospf3

import (
	"net"
	"time"

	"golang.org/x/net/ipv6"
)

var (
	// AllSPFRouters is the IPv6 multicast group address that all routers
	// running OSPFv3 should participate in.
	AllSPFRouters = &net.IPAddr{IP: net.ParseIP("ff02::5")}

	// AllDRouters is the IPv6 multicast group address that the Designated
	// Router and Backup Designated Router running OSPFv3 must participate in.
	AllDRouters = &net.IPAddr{IP: net.ParseIP("ff02::6")}
)

// A Conn can send and receive OSPFv3 messages which implement the Message
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

	// Return all possible control message information to the caller so they
	// can make more informed choices.
	c := ipv6.NewPacketConn(conn)
	if err := c.SetControlMessage(^ipv6.ControlFlags(0), true); err != nil {
		return nil, err
	}

	// Join the appropriate multicast groups. Note that point-to-point links
	// don't use DR/BDR and can skip joining that group.
	groups := []*net.IPAddr{AllSPFRouters}
	if ifi.Flags&net.FlagPointToPoint == 0 {
		groups = append(groups, AllDRouters)
	}

	for _, g := range groups {
		if err := c.JoinGroup(ifi, g); err != nil {
			return nil, err
		}
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

// ReadFrom reads a single OSPFv3 message and returns a Message along with its
// associated IPv6 control message and source address. ReadFrom will block until
// a timeout occurs or a valid OSPFv3 message is read.
func (c *Conn) ReadFrom() (Message, *ipv6.ControlMessage, *net.IPAddr, error) {
	b := make([]byte, c.ifi.MTU)
	for {
		n, cm, src, err := c.c.ReadFrom(b)
		if err != nil {
			return nil, nil, nil, err
		}

		m, err := ParseMessage(b[:n])
		if err != nil {
			// Assume invalid OSPFv3 data, keep reading.
			continue
		}

		return m, cm, src.(*net.IPAddr), nil
	}
}

// WriteTo writes a single OSPFv3 Message to the specified destination address
// with an optional IPv6 control message. If cm is nil, a default control
// message will be used with parameters specific to OSPFv3.
func (c *Conn) WriteTo(m Message, cm *ipv6.ControlMessage, dst *net.IPAddr) error {
	b, err := MarshalMessage(m)
	if err != nil {
		return err
	}

	if cm == nil {
		cm = &ipv6.ControlMessage{
			TrafficClass: 0xc0, // DSCP CS6, per appendix A.1.
			HopLimit:     1,    // Always 1.
			IfIndex:      c.ifi.Index,
		}
	}

	_, err = c.c.WriteTo(b, cm, dst)
	return err
}
