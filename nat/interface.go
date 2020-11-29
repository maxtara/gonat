package nat

import (
	"errors"
	"net"

	"github.com/google/gopacket"
)

var (
	ErrNoInterfaceFound = errors.New("could not find interface with that name")
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
	// isUp bool
	// isRunning bool
	// isLoopback bool
	// isBridge bool
	// isPointToPoint bool
	// isPrimary bool
	// isSecondary bool
	// isMulticast bool
	// isMtuSet bool
	// mtu int
}

// Source - a source of packets. Interface to make it easier to test with.
type Source interface {
	Start(nat *Nat, bpf string) (err error)
}

// Dest - a Destination of packets. Interface to make it easier to test with.
type Dest interface {
	Send(gopacket.Packet) (err error)
	SendBytes([]byte) (err error)
}