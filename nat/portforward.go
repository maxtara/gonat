package nat

import (
	"net"

	"github.com/google/gopacket/layers"
)

type PFRule struct {
	Name              string `yaml:"name"`
	InternalPortStart uint16 `yaml:"internalPortStart"`
	ExternalPortStart uint16 `yaml:"externalPortStart"`
	ExternalPortEnd   uint16 `yaml:"externalPortEnd"`
	Protocol          string `yaml:"protocol"`
	InternalIP        string `yaml:"internalIP"`
}

type PortForwardingEntry struct {
	InternalIP   net.IP
	InternalPort uint16
}
type PortForwardingKey struct {
	ExternalPort uint16
	Protocol     layers.IPProtocol
}
