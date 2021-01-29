package ospf3

import (
	"net"
	"time"

	"golang.org/x/net/ipv6"
)

// Multicast groups used by OSPFv3.
var (
	allSPFRouters = &net.IPAddr{IP: net.ParseIP("ff02::5")}
	allDRouters   = &net.IPAddr{IP: net.ParseIP("ff02::6")}
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
	groups := []*net.IPAddr{allSPFRouters}
	if ifi.Flags&net.FlagPointToPoint == 0 {
		groups = append(groups, allDRouters)
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
