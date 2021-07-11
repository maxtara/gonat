package nat

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog/log"
)

var (
	_, LinkLocalNet, _ = net.ParseCIDR("fe80::/64")
)

// AcceptPkt6 decides what to do with an ipv6 packet packet.
func (n *Nat) AcceptPkt6(pkt *Packet) {

	// log.Info().Msgf("Got an IPv6 packet.%s", pkt)
	ipv6tmp, _ := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	pkt.Ip6 = ipv6tmp
	ipsrc, ipdst := pkt.IPs()
	if pkt.Ip6.NextHeader == layers.IPProtocolICMPv6 {
		icmp, _ := pkt.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
		if icmp.TypeCode.Type() == layers.ICMPv6TypeEchoRequest {
			log.Info().Msgf("EchoRequest %s", ipdst)
		} else if icmp.TypeCode.Type() == layers.ICMPv6TypeEchoReply {
			log.Info().Msgf("EchoReply %s", ipdst)
		} else if icmp.TypeCode.Type() == layers.ICMPv6TypeRouterSolicitation {
			log.Info().Msgf("RouterSolicitation %s", ipdst)
			rs, _ := pkt.Layer(layers.LayerTypeICMPv6RouterSolicitation).(*layers.ICMPv6RouterSolicitation)
			log.Info().Msgf("RS: %s", rs)
			if !LinkLocalNet.Contains(ipsrc) {
				log.Error().Msgf("I dont think you can get an RS not from a linklocalnet address")
			}
		} else if icmp.TypeCode.Type() == layers.ICMPv6TypeRouterAdvertisement {
			log.Info().Msgf("RouterAdvertisement %s", ipdst)
			ra, _ := pkt.Layer(layers.LayerTypeICMPv6RouterAdvertisement).(*layers.ICMPv6RouterAdvertisement)
			log.Info().Msgf("RA: %v", ra)
			if !LinkLocalNet.Contains(ipsrc) {
				log.Error().Msgf("I dont think you can get an RA not from a linklocalnet address")
			}
		} else if icmp.TypeCode.Type() == layers.ICMPv6TypeNeighborSolicitation {
			n.handleNeighborSolicitation(pkt, icmp)
		} else if icmp.TypeCode.Type() == layers.ICMPv6TypeNeighborAdvertisement {
			log.Info().Msgf("NeighborAdvertisement %s", ipdst)
			ns, _ := pkt.Layer(layers.LayerTypeICMPv6NeighborAdvertisement).(*layers.ICMPv6NeighborAdvertisement)
			log.Info().Msgf("NS: %v", ns)
			if !LinkLocalNet.Contains(ipsrc) {
				log.Error().Msgf("I dont think you can get an NS not from a linklocalnet address")
			}
		} else {
			log.Info().Msgf("Unknown ICMPv6 type %d", icmp.TypeCode.Type())
		}

	}
	// Network discovery protocol
	// FE80::/64

}

func (n *Nat) handleNeighborSolicitation(pkt *Packet, icmp *layers.ICMPv6) {
	ipsrc := pkt.SrcIP()

	ns, _ := pkt.Layer(layers.LayerTypeICMPv6NeighborSolicitation).(*layers.ICMPv6NeighborSolicitation)
	log.Info().Msgf("NeighborSolicitation: %s", ns)
	if !LinkLocalNet.Contains(ipsrc) {
		log.Error().Msgf("I dont think you can get an NS not from a linklocalnet address")
	}

	// While we are here, lets update the arp table with the source of this request. Why not!
	n.arpNotify.AddArpEntry(ipsrc, pkt.Eth.SrcMAC, pkt.FromInterface.IfName)

	// Check if its to me
	if !ns.TargetAddress.Equal(pkt.FromInterface.IPv4Addr) {
		// Send a Neighbor Advertisement
		// n.sendNeighborAdvertisement(pkt, ifName)
		log.Info().Msgf("Not to me!!!!")

		return
	}
	log.Info().Msgf("Its to me. Lets write a response")
	buffer := gopacket.NewSerializeBuffer()
	icmp6reply := layers.ICMPv6NeighborAdvertisement{TargetAddress: ns.TargetAddress}
	// icmp6reply.SetNetworkLayerForChecksum(ipv4)
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false}, pkt.Eth, pkt.Ip6, icmp, &icmp6reply)

	if err != nil {
		log.Error().Err(err).Msgf("failed to serialize packet %s", err)
		return
	}
	pktNewDebug := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	log.Info().Msgf("=====================================output pkts for %s ------ =====================================", pktNewDebug)
	// pkt.FromInterface.Callback.SendBytes(buffer.Bytes())

}

/*
	- Layer 1 (14 bytes) = Ethernet {Contents=[..14..] Payload=[..56..] SrcMAC=00:15:5d:13:30:21 DstMAC=33:33:00:00:00:02 EthernetType=IPv6 Length=0}
	- Layer 2 (40 bytes) = IPv6     {Contents=[..40..] Payload=[..16..] Version=6 TrafficClass=0 FlowLabel=0 Length=16 NextHeader=ICMPv6 HopLimit=255 SrcIP=fe80::215:5dff:fe13:3021 DstIP=ff02::2 HopByHop=nil}
	- Layer 3 (04 bytes) = ICMPv6   {Contents=[133, 0, 96, 155] Payload=[..12..] TypeCode=RouterSolicitation Checksum=24731 TypeBytes=[]}
	- Layer 4 (00 bytes) = ICMPv6RouterSolicitation {Contents=[] Payload=[] Options=[ICMPv6Option(SourceAddress:00:15:5d:13:30:21)]}
*/
