package nat

import (
	"encoding/binary"
	"gonat/common"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	_, LinkLocalNet, _ = net.ParseCIDR("fe80::/64")
	AllRouters         = net.ParseIP("ff02::2")
)

// AcceptPkt6 decides what to do with an ipv6 packet packet.
func (n *Nat) AcceptPkt6(pkt *Packet) {

	// log.Info().Msgf("Got an IPv6 packet.%s", pkt)
	ipv6tmp, _ := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	pkt.Ip6 = ipv6tmp
	ipsrc, ipdst := pkt.IPs()

	/*
		TODO: Allow for multiple interfaces.
		if !(pkt.FromInterface.IPv4Network.Contains(ipsrc) || pkt.FromInterface.IPv4Network.Contains(ipdst)) {
			log.Info().Msgf("Packet is not for us. Possibly broadcasted - possibly DHCP  %s", pkt)
			return
		} else
	*/

	if pkt.Ip6.HopLimit == 0 {
		log.Warn().Msgf("Dropping packet with TTL 0, TODO - send ICMP back")
		return
	}
	if pkt.Ip6.NextHeader == layers.IPProtocolICMPv6 {
		icmp, _ := pkt.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
		switch icmp.TypeCode.Type() {
		case layers.ICMPv6TypeNeighborSolicitation:
			n.handleNeighborSolicitation(pkt, icmp)
			return // Dont route or NAT
		case layers.ICMPv6TypeNeighborAdvertisement:
			ns, _ := pkt.Layer(layers.LayerTypeICMPv6NeighborAdvertisement).(*layers.ICMPv6NeighborAdvertisement)
			log.Info().Msgf("NS: %v", ns)
			if !LinkLocalNet.Contains(ipsrc) {
				log.Error().Msgf("I dont think you can get an NS not from a linklocalnet address - %v", pkt)
			}
			n.handleNeighborAdvertisement(pkt, ns)
			return // Dont route or NAT
		case layers.ICMPv6TypeRouterSolicitation:
			n.handleRouterSolicitation(pkt, icmp)
			return // Dont route or NAT
		case layers.ICMPv6TypeRouterAdvertisement:
			log.Info().Msgf("RouterAdvertisement %s", ipdst)
			ra, _ := pkt.Layer(layers.LayerTypeICMPv6RouterAdvertisement).(*layers.ICMPv6RouterAdvertisement)
			log.Info().Msgf("RA: %v", ra)
			if !LinkLocalNet.Contains(ipsrc) {
				log.Error().Msgf("I dont think you can get an RA not from a linklocalnet address")
			}
			return // Dont route or NAT
		case layers.ICMPv6TypeEchoRequest:
			if ipdst.Equal(pkt.FromInterface.IPv4Addr) { // is it to me?
				log.Info().Msgf("EchoRequest to me from %s", ipsrc)
				if err := sendICMPv6EchoResponse(icmp, pkt); err != nil {
					log.Error().Err(err).Msgf("failed to send packet %s", err)
				}
				return // Sent packet or error'd. Dont NAT, return.
			}
			log.Info().Msgf("EchoRequest going through to NAT. %s %s", ipsrc, ipdst)
		case layers.ICMPv6TypeEchoReply:
			log.Info().Msgf("EchoReply %s:%s. Passing through NAT", ipsrc, ipdst)
		default:
			log.Warn().Msgf("Unhandled ICMPv6 type %d", icmp.TypeCode.Type())
		}

	}

	// Check if its from AND to a LAN interface
	// Im assuming its faster to just loop over internalRoutes, instead of implementing a ipnetwork tree object, as
	// most of the time there will only be one LAN network, at most a few.
	if pkt.FromInterface.NatEnabled {
		for _, route := range n.internalRoutes {
			if route.Contains(ipdst) && !pkt.FromInterface.IPv4Addr.Equal(ipdst) {
				log.Debug().Msgf("Packet to %s:%s is internal. Sending straight out the right interface", ipsrc, ipdst)
				if err := n.routeInternally(pkt); err != nil {
					log.Error().Err(err).Msgf("failed to route packet %s", err)
				}
				return
			}
		}
	}

	// If the default gateway is ipv6, then we can NAT
	if !common.IsIPv4(n.defaultGateway.IPv4Addr) {
		if len(pkt.Data()) > n.defaultGateway.MTU {
			log.Warn().Msg("Cannot sent packet on the WAN interface due to MTU constraints. TODO, send ICMP back")
		}

		// Probably a NAT'able packet from here on
		// Drop the TTL. This will mean anything onwards should have the TTL down.
		pkt.Ip6.HopLimit -= 1
		if err := n.natPacket(pkt, pkt.Eth); err != nil {
			log.Error().Err(err).Msgf("failed to NAT packet %s", pkt)
		}
	}
}
func (n *Nat) handleRouterSolicitation(pkt *Packet, icmp *layers.ICMPv6) {
	ipsrc, ipdst := pkt.IPs()
	rs, _ := pkt.Layer(layers.LayerTypeICMPv6RouterSolicitation).(*layers.ICMPv6RouterSolicitation)
	log.Info().Msgf("RS: %s. From %s %s", rs, ipsrc, ipdst)
	if !AllRouters.Equal(ipdst) {
		log.Error().Msgf("I think routerSols need to go to ff02::2")
		return
	}

	// While we are here, lets update the arp table with the source of this request. Why not!
	n.arpNotify.AddArpEntry(ipsrc, pkt.Eth.SrcMAC, pkt.FromInterface.IfName)

	log.Debug().Interface("RouterSol", pkt).Msg("Router Solicitaion input")

	// Don't drop the TTL, or it will fail.
	// Flip the packet around, and send it pack. Shortcut to generating an ICMP packet.
	pkt.Ip6.DstIP = pkt.Ip6.SrcIP
	pkt.Ip6.SrcIP = pkt.FromInterface.IPv4Addr

	pkt.Eth.DstMAC = pkt.Eth.SrcMAC
	pkt.Eth.SrcMAC = pkt.FromInterface.IfHWAddr

	icmp.TypeCode = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeRouterAdvertisement, 0) // zero code according to RFC 4443

	buffer := gopacket.NewSerializeBuffer()

	// TODO, function to generate a router advertisement / options
	opts := []layers.ICMPv6Option{
		{Type: layers.ICMPv6OptPrefixInfo, Data: []byte("\x40\xc0\x00\x00\x1a\x49\x00\x00\x0c\x38\x00\x00\x00\x00\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")}, // prefix to fd00::/64
		{Type: layers.ICMPv6Opt(25), Data: []byte("\x40\xc0\x00\x00\x04\xb0\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01")},                                       // DNS server to fd00::1
		{Type: layers.ICMPv6OptMTU, Data: []byte("\x00\x00\x00\x00\x05\xd4")},                                                                                                        // MTU to 1492.
		{Type: layers.ICMPv6Opt(24), Data: []byte("\x00\x00\x00\x00\x07\x08")},                                                                                                       // static route for ::/0
		{Type: layers.ICMPv6OptSourceAddress, Data: pkt.Eth.SrcMAC},
	}
	icmp6reply := layers.ICMPv6RouterAdvertisement{
		Options:        opts,
		HopLimit:       0xff,
		Flags:          0x40,
		RouterLifetime: 10, // 10 seconds while testing? 1800 is normal i think
		ReachableTime:  0,
		RetransTimer:   0,
	}
	// icmp.Payload = gopacket.Payload(icmp6reply)
	_ = icmp.SetNetworkLayerForChecksum(pkt.Ip6)
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, pkt.Eth, pkt.Ip6, icmp, &icmp6reply)

	if err != nil {
		log.Error().Err(err).Msgf("failed to serialize packet %s", err)
		return
	}
	common.PrintPacket(buffer.Bytes(), zerolog.InfoLevel)
	if err = pkt.FromInterface.Callback.SendBytes(buffer.Bytes()); err != nil {
		log.Error().Err(err).Msgf("failed to send RouterAdvertisement %s", err)
	}
	n.arpNotify.AddArpEntry(pkt.Ip6.DstIP, pkt.Eth.DstMAC, pkt.FromInterface.IfName)

}

// handleNeighborAdvertisement handles a Neighbor Advertisement packet.
// I think there is only every one option, and its always a ICMPv6OptTargetAddress anyway
func (n *Nat) handleNeighborAdvertisement(pkt *Packet, ns *layers.ICMPv6NeighborAdvertisement) {
	for _, option := range ns.Options {
		if option.Type == layers.ICMPv6OptTargetAddress {
			n.arpNotify.AddArpEntry(ns.TargetAddress, option.Data, pkt.FromInterface.IfName)
		}
	}

}
func (n *Nat) handleNeighborSolicitation(pkt *Packet, icmp *layers.ICMPv6) {
	ipsrc := pkt.SrcIP()

	ns, _ := pkt.Layer(layers.LayerTypeICMPv6NeighborSolicitation).(*layers.ICMPv6NeighborSolicitation)
	if !LinkLocalNet.Contains(ipsrc) {
		log.Error().Msgf("I dont think you can get an NS not from a linklocalnet address")
	}

	// While we are here, lets update the arp table with the source of this request. Why not!
	n.arpNotify.AddArpEntry(ipsrc, pkt.Eth.SrcMAC, pkt.FromInterface.IfName)

	// Check if its to me
	if !ns.TargetAddress.Equal(pkt.FromInterface.IPv4Addr) {
		return
	}
	log.Debug().Interface("NeighborSolicitation", pkt).Msg("NeighborSolicitation full packet")
	log.Info().Interface("NeighborSolicitation", ns).Msg("NeighborSolicitation input")

	// Don't drop the TTL, or it will fail.
	// Flip the packet around, and send it pack. Shortcut to generating an ICMP packet.
	pkt.Ip6.DstIP = pkt.Ip6.SrcIP
	pkt.Ip6.SrcIP = pkt.FromInterface.IPv4Addr

	pkt.Eth.DstMAC = pkt.Eth.SrcMAC
	pkt.Eth.SrcMAC = pkt.FromInterface.IfHWAddr

	icmp.TypeCode = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborAdvertisement, 0) // zero code according to RFC 4443

	buffer := gopacket.NewSerializeBuffer()
	opts := []layers.ICMPv6Option{
		{Type: layers.ICMPv6OptTargetAddress, Data: pkt.Eth.SrcMAC},
	}
	icmp6reply := layers.ICMPv6NeighborAdvertisement{TargetAddress: ns.TargetAddress, Flags: 0xd0, Options: opts} // d0 == Router + Solicited + Override.
	// icmp.Payload = gopacket.Payload(icmp6reply)
	_ = icmp.SetNetworkLayerForChecksum(pkt.Ip6)
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, pkt.Eth, pkt.Ip6, icmp, &icmp6reply)

	if err != nil {
		log.Error().Err(err).Msgf("failed to serialize packet %s", err)
		return
	}
	common.PrintPacket(buffer.Bytes(), zerolog.DebugLevel)

	if err = pkt.FromInterface.Callback.SendBytes(buffer.Bytes()); err != nil {
		log.Error().Err(err).Msgf("failed to send NeighborAdvertisement %s", err)
	}

	n.arpNotify.AddArpEntry(pkt.Ip6.DstIP, pkt.Eth.DstMAC, pkt.FromInterface.IfName)

}

// sendICMPv6EchoResponse sends an ICMPv6 Echo Response packet back to the source of the request.
// Unforunately, gopacket doesnt encode OR decode the icmp data (or the payload) so we have to do it manually.
// There is a pr in with gopacket to decode it, but not encode it.
// To do this, i construct the new eth/ip/icmp packet, turn it into a byte array, append the old payload (as the new payload would be stripped anyway), then
// update the checksum. Because I dont know how many layers are before the ICMP layer, i have to do a bit of
// arthmatic to work it out.  The final packet length doesnt change, so we can just send it back.
func sendICMPv6EchoResponse(icmp *layers.ICMPv6, pkt *Packet) (err error) {
	// Drop the TTL. This will mean anything onwards should have the TTL down.
	log.Debug().Msgf("=====================================input pkt for %s ------ =====================================", pkt)
	pkt.Ip6.HopLimit -= 1
	// Flip the packet around, and send it pack. Shortcut to generating an ICMP packet.
	oldDstIp := pkt.Ip6.DstIP
	pkt.Ip6.DstIP = pkt.Ip6.SrcIP
	pkt.Ip6.SrcIP = oldDstIp

	oldDstMac := pkt.Eth.DstMAC
	pkt.Eth.DstMAC = pkt.Eth.SrcMAC
	pkt.Eth.SrcMAC = oldDstMac
	icmpData := icmp.BaseLayer.Payload[4:] // golang considers the payload to include the seq?

	icmp.TypeCode = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoReply, 0) // zero code according to RFC 4443
	_ = icmp.SetNetworkLayerForChecksum(pkt.Ip6)

	// Create the new packet
	buf := gopacket.NewSerializeBuffer()
	err = gopacket.SerializePacket(buf, gopacket.SerializeOptions{FixLengths: false, ComputeChecksums: false}, pkt)
	if err != nil {
		log.Error().Err(err).Msgf("Failed to serialise packet? this shouldnt happen %s", pkt)
		return
	}
	// Length of everything UP TO the ICMPv6 payload
	headerLen := len(pkt.Packet.Data()) - (len(icmp.BaseLayer.Payload) + len(icmp.BaseLayer.Contents))

	// The start of the new packet (up to the icmp payload), and the old payload (sent back)
	icmpPayload := append(buf.Bytes()[headerLen:], icmpData...)
	common.PrintPacket(buf.Bytes(), zerolog.DebugLevel)

	// Fix the checksum
	csum := common.FixICMPv6Checksum(pkt.Ip6.SrcIP, pkt.Ip6.DstIP, icmpPayload, len(icmp.BaseLayer.Payload)+len(icmp.BaseLayer.Contents))
	binary.BigEndian.PutUint16(icmpPayload[2:4], csum)

	fullPacket := append(buf.Bytes()[:headerLen], icmpPayload...)

	err = pkt.FromInterface.Callback.SendBytes(fullPacket)
	if err != nil {
		log.Error().Err(err).Msgf("Failed to send packet %s", err)
	}
	return
}
