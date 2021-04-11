package nat

import (
	"net"

	"github.com/google/gopacket/layers"
)

// PFRule is used by the configuration and instatiation or port forwarding rules.
type PFRule struct {
	Name              string `yaml:"name"`
	InternalPortStart uint16 `yaml:"internalPortStart"`
	ExternalPortStart uint16 `yaml:"externalPortStart"`
	ExternalPortEnd   uint16 `yaml:"externalPortEnd"`
	Protocol          string `yaml:"protocol"`
	InternalIP        string `yaml:"internalIP"`
}

// PortForwardingEntry represents a port forwarding Destination.
type PortForwardingEntry struct {
	InternalIP   net.IP
	InternalPort uint16
}

// PortForwardingRule represents a port forwarding rule entry (source)
type PortForwardingKey struct {
	ExternalPort uint16
	Protocol     layers.IPProtocol
}
