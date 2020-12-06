package nat

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/google/gopacket/layers"
)

type PortForwardingRules []PortForwardingRule

type PortForwardingRule struct {
	InternalIP        net.IP
	ExternalPortStart uint16
	ExternalPortEnd   uint16
	InternalPortStart uint16
	InternalPortEnd   uint16
	Protocol          layers.IPProtocol
}
type PortForwardingEntry struct {
	InternalIP   net.IP
	InternalPort uint16
}
type PortForwardingKey struct {
	ExternalPort uint16
	Protocol     layers.IPProtocol
}

func (i *PortForwardingRules) String() string {
	var s string
	for _, v := range *i {
		s += fmt.Sprintf("%s,%s,%d-%d,%d-%d", v.InternalIP, v.Protocol, v.ExternalPortStart, v.ExternalPortEnd, v.InternalPortStart, v.InternalPortEnd)
	}
	return s
}
func parsePortRange(s string) (start uint16, end uint16, err error) {
	var startTmp uint64

	if strings.Contains(s, "-") {
		parts := strings.Split(s, "-")
		if len(parts) != 2 {
			return 0, 0, fmt.Errorf("invalid port range %s", s)
		}
		startTmp, err = strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			return
		}
		start = uint16(startTmp)
		startTmp, err = strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			return
		}
		end = uint16(startTmp)
	} else {
		startTmp, err = strconv.ParseUint(s, 10, 16)
		if err != nil {
			return
		}
		end = uint16(startTmp)
		start = uint16(startTmp)
	}

	return start, end, err
}

// Set - Port Forwarding rules. In the format ip,tcp|udp|both,externalstart<-end>,internalstart. Eg, 10.0.0.2,tcp,2000,2000, or 10.0.0.2,udp,2000-2001,3000
func (pf *PortForwardingRules) Set(value string) (err error) {
	i := PortForwardingRule{}
	parts := strings.Split(value, ",")
	if len(parts) != 4 {
		return fmt.Errorf("invalid port forwarding rule %s", value)
	}

	if parts[1] == "tcp" {
		i.Protocol = layers.IPProtocolTCP
	} else if parts[1] == "udp" {
		i.Protocol = layers.IPProtocolUDP
	} else {
		return fmt.Errorf("invalid protocol %s", parts[1])
	}

	i.InternalIP = net.ParseIP(parts[0])
	if i.InternalIP == nil {
		return fmt.Errorf("invalid ip -  %s", parts[0])
	}

	i.ExternalPortStart, i.ExternalPortEnd, err = parsePortRange(parts[2])
	if err != nil {
		return
	}
	i.InternalPortStart, i.InternalPortEnd, err = parsePortRange(parts[3])
	if err != nil {
		return
	}
	i.InternalPortEnd = i.InternalPortStart + (i.ExternalPortEnd - i.ExternalPortStart)
	if i.InternalPortStart > i.InternalPortEnd {
		return fmt.Errorf("invalid port range %s", value)
	}
	*pf = append(*pf, i)
	return nil
}
