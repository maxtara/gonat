package nat

import (
	"gonat/dhcp"
	"net"
)

type Interface struct {
	IfName      string
	IfHWAddr    net.HardwareAddr
	IPv4Addr    net.IP
	IPv4Netmask net.IPMask
	IPv4Network net.IPNet
	IPv4Gateway net.IP
	NatEnabled  bool
	DHCPEnabled bool
	DHCPHandler *dhcp.DHCPHandler
	Callback    Dest
	MTU         int
	// isUp bool
	// isRunning bool
	// isLoopback bool
	// isBridge bool
	// isPointToPoint bool
	// isPrimary bool
	// isSecondary bool
	// isMulticast bool
	// isMtuSet bool
}

// Source - a source of packets. Interface to make it easier to test with.
type Source interface {
	Start(nat *Nat, bpf string)
}

// Dest - a Destination of packets. Interface to make it easier to test with.
type Dest interface {
	Send(*Packet) (err error)
	SendBytes([]byte) (err error)
}
