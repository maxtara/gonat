package nat

import (
	"gonat/common"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Packet extends gopacket.Packet to allow for layer3 and layer4 independent modifications.
type Packet struct {
	gopacket.Packet
	ThreadNo      int // Thread number, starting from 1. The first is dedicated for ARP entries, as they are done asyncronously
	FromInterface *Interface
	// Packet references. Used so i dont have to reflect multiple times, or pass paramters around a lot
	Eth   *layers.Ethernet
	Ip4   *layers.IPv4
	Ip6   *layers.IPv6
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
		log.Fatalf("Packet %v has no IP layer, and you are trying to set it.", p)
	}
}

func (p *Packet) SetSrcIP(src net.IP) {
	if p.Ip6 != nil {
		p.Ip6.SrcIP = src
	} else if p.Ip4 != nil {
		p.Ip4.SrcIP = src
	} else {
		log.Fatalf("Packet %v has no IP layer, and you are trying to set it.", p)
	}
}
func (p *Packet) SetDstIP(dst net.IP) {
	if p.Ip6 != nil {
		p.Ip6.DstIP = dst
	} else if p.Ip4 != nil {
		p.Ip4.DstIP = dst
	} else {
		log.Fatalf("Packet %v has no IP layer, and you are trying to set it.", p)
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

func (p *Packet) Protocol() layers.IPProtocol {
	if p.Ip6 != nil {
		return p.Ip6.NextHeader
	} else if p.Ip4 != nil {
		return p.Ip4.Protocol
	} else {
		return layers.IPProtocolNoNextHeader
	}

}
