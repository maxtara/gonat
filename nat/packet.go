package nat

import (
	"gonat/common"
	"net"

	"github.com/rs/zerolog/log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Packet extends gopacket.Packet to allow for layer3 and layer4 independent modifications.
type Packet struct {
	gopacket.Packet
	ThreadNo      int // Thread number, starting from 1. The first is dedicated for ARP entries, as they are done asyncronously
	FromInterface *Interface
	// Packet references. Used so i dont have to reflect multiple times, or pass paramters around a lot
	// Layer 2
	Eth *layers.Ethernet
	// Layer 3
	Ip4 *layers.IPv4
	Ip6 *layers.IPv6
	// Layer 4
	Tcp   *layers.TCP
	Udp   *layers.UDP
	Icmp  *layers.ICMPv4
	Icmp6 *layers.ICMPv6
}

func (p *Packet) SetIPs(src, dst net.IP) {
	if p.Ip6 != nil {
		p.Ip6.SrcIP = src
		p.Ip6.DstIP = dst

	} else if p.Ip4 != nil {
		p.Ip4.SrcIP = src
		p.Ip4.DstIP = dst

	} else {
		log.Fatal().Msgf("Packet %v has no IP layer, and you are trying to set it.", p)
	}
}

func (p *Packet) SetPorts(src, dst uint16) {
	if p.Tcp != nil {
		p.Tcp.SrcPort = layers.TCPPort(src)
		p.Tcp.DstPort = layers.TCPPort(dst)
	} else if p.Udp != nil {
		p.Udp.SrcPort = layers.UDPPort(src)
		p.Udp.DstPort = layers.UDPPort(dst)
	} else if p.Icmp != nil {
		p.Icmp.Id = src // Never set the Sequence number
	}
}

func (p *Packet) SetLayer4() {
	protocol := p.Protocol()
	if protocol == layers.IPProtocolTCP {
		p.Tcp, _ = p.Layer(layers.LayerTypeTCP).(*layers.TCP)
		_ = p.Tcp.SetNetworkLayerForChecksum(p.NetworkLayer())
	} else if protocol == layers.IPProtocolUDP {
		p.Udp, _ = p.Layer(layers.LayerTypeUDP).(*layers.UDP)
		_ = p.Udp.SetNetworkLayerForChecksum(p.NetworkLayer())
	} else if protocol == layers.IPProtocolICMPv4 {
		p.Icmp, _ = p.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	} else if protocol == layers.IPProtocolICMPv6 {
		p.Icmp6, _ = p.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	} else if protocol == layers.IPProtocolIGMP {
		log.Debug().Msgf("Trying to NAT IGMP. Going to pass this through, TODO - investigate")
	} else {
		log.Warn().Msgf("Trying to NAT unsupported protocol. You better hope a layer 2/3 NAT works. - %s", p)
	}

}
func (p *Packet) Ports() (src, dst uint16) {
	if p.Tcp != nil {
		return uint16(p.Tcp.SrcPort), uint16(p.Tcp.DstPort)
	} else if p.Udp != nil {
		return uint16(p.Udp.SrcPort), uint16(p.Udp.DstPort)
	} else if p.Icmp != nil {
		return uint16(p.Icmp.Id), uint16(p.Icmp.Id)
	} else if p.Icmp6 != nil {
		return 0, 0 // gopacket doesnt store the Id???? TODO - investigate. In the meantime, dont NAT the ID, shouldnt cause an issue in real world scenarios
	} else {
		return 0, 0
	}
}

func (p *Packet) IPs() (src, dst net.IP) {
	return common.GetIPs(p.NetworkLayer())
}

func (p *Packet) SrcIP() (dst net.IP) {
	return common.GetSrcIP(p.NetworkLayer())
}
func (p *Packet) DstIP() (dst net.IP) {
	return common.GetDstIP(p.NetworkLayer())
}

func (p *Packet) SetSrcPort(srcport uint16) {
	if p.Tcp != nil {
		p.Tcp.SrcPort = layers.TCPPort(srcport)
	} else if p.Udp != nil {
		p.Udp.SrcPort = layers.UDPPort(srcport)
	} else if p.Icmp != nil {
		p.Icmp.Id = uint16(srcport)
	} // no icmp6
}
func (p *Packet) SetDstPort(dstport uint16) {
	if p.Tcp != nil {
		p.Tcp.DstPort = layers.TCPPort(dstport)
	} else if p.Udp != nil {
		p.Udp.DstPort = layers.UDPPort(dstport)
	}
}

func (p *Packet) Protocol() layers.IPProtocol {
	if p.Ip6 != nil {
		return p.Ip6.NextHeader
	} else if p.Ip4 != nil {
		return p.Ip4.Protocol
	} else {
		return layers.IPProtocolNoNextHeader
	}

}
