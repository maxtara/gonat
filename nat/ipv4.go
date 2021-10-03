/*
Package nat implements a simple NAPT (Network Address Port Translation)

*/
package nat

import (
	"bytes"
	"fmt"
	"gonat/common"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/rs/zerolog/log"
)

// AcceptPkt4 decides what to do with an ipv4 packet.
func (n *Nat) AcceptPkt4(pkt *Packet) {
	ipv4, _ := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	pkt.Ip4 = ipv4
	ipsrc, ipdst := pkt.IPs()
	// Not from/to our the recieving interface. Probably broadcast, otherwise, maybe you likely have done something wrong
	if !(pkt.FromInterface.IPv4Network.Contains(ipsrc) || pkt.FromInterface.IPv4Network.Contains(ipdst)) {

		// Check for DHCP here, only if its enabled on this interface.
		if ipdst.Equal(BroadCast) && pkt.FromInterface.DHCPEnabled {
			log.Debug().Msgf("DHCP packet recieved - %v", pkt)
			// check if its DHCP UDP
			if ipv4.Protocol == layers.IPProtocolUDP {
				udp, _ := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
				if dhcpPacket, ok := pkt.Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4); ok {

					req, err := pkt.FromInterface.DHCPHandler.Handle(dhcpPacket.Contents, ipsrc, int(udp.DstPort))
					if err != nil {
						log.Error().Err(err).Msgf("Error handling DHCP packet: %v", err)
						return
					}
					log.Info().Msgf("Handled DHCP Packet correctly - %+v", pkt.FromInterface.DHCPHandler)
					err = sendDHCPResponse(pkt, udp, req)
					if err != nil {
						log.Error().Err(err).Msgf("Error sending DHCP response: %v", err)
					}
					return
				}
			}
		}
		// Not from our subnets or a broadcast
		log.Warn().Msgf("Packet on %s appears to be from other subnet, not yet supported. %s  does not contain either  %s not %s - dropping", pkt.FromInterface.IfName, pkt.FromInterface.IPv4Network, ipsrc, ipdst)
		return
	} else if MultiCast.Contains(ipdst) {
		log.Debug().Msgf("Dropping multicast packet for now -")
		return
	} else if ipv4.TTL == 0 {
		log.Debug().Msgf("Dropping packet with TTL 0, sending Time Exceeded back")
		if err := sendICMPPacketReverse(pkt, layers.ICMPv4TypeTimeExceeded, layers.ICMPv4CodeTTLExceeded); err != nil {
			log.Error().Err(err).Msgf("failed to send packet %s", err)
		}
		return

	} else if pkt.FromInterface.NatEnabled && (ipv4.Flags&layers.IPv4DontFragment == layers.IPv4DontFragment) {
		// rfc4787 - REQ-13
		lenPkt := len(pkt.Data())
		if lenPkt > n.defaultGateway.MTU {
			log.Warn().Msg("Fragmentation bit set, and too big!. Why? Could be GSO/GRO/TSO. Turn em off")
			if err := sendICMPPacketReverse(pkt, layers.ICMPv4TypeDestinationUnreachable, layers.ICMPv4CodeFragmentationNeeded); err != nil {
				log.Error().Err(err).Msgf("failed to send packet %s", err)
			}
			return
		}
	}
	// Check for ip fragmentation. If so, wait for more defrags, then continue
	// Looking at the code, this looks threadsafe, but i havnt tested it
	if ipv4.Flags&layers.IPv4MoreFragments == layers.IPv4MoreFragments || ipv4.FragOffset > 0 {
		log.Debug().Msgf("Got a fragmented IP packet, attempting to defrag it")
		ipv4Out, err := n.ip4defrager.DefragIPv4(ipv4)
		if err != nil {
			log.Error().Err(err).Msgf("failed to defrag the pkt %s", err)
			return
		} else if ipv4Out == nil {
			return
		}
		buffer := gopacket.NewSerializeBuffer()
		err = gopacket.SerializeLayers(buffer, common.Options,
			pkt.Eth,
			ipv4Out,
			gopacket.Payload(ipv4Out.Payload),
		)
		if err != nil {
			log.Error().Err(err).Msgf("failed to serialize the defragmented packet %s", err)
			return
		}

		pkt.Packet = gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
		log.Info().Msgf("Successfully defragged the pkt, congrats! New length is %d", len(pkt.Packet.Data()))
		// Update the helper vars/pointers in this func
		ipv4, _ = pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		ipsrc, ipdst = pkt.IPs()
	}

	// ICMP code here.
	// If its adressed to myself, pretty easy to handle
	if ipv4.Protocol == layers.IPProtocolICMPv4 {
		icmp, _ := pkt.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
		if ipdst.Equal(pkt.FromInterface.IPv4Addr) {
			// Make sure its a request to
			if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoRequest {
				if err := sendICMPv4EchoResponse(icmp, pkt); err != nil {
					log.Error().Err(err).Msgf("failed to send packet %s", err)
				}
				return // Sent packet or error'd. Dont NAT, return.
			} else if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoReply {
				log.Debug().Msgf("Got an ICMP response to %s->%s. Going to pass through to NAT, as its probably a clients packet", ipsrc, ipdst)

			} else {
				// Currently tested on ICMPv4TypeTimeExceeded and ICMPv4TypeDestinationUnreachable.
				err := n.handleOtherICMP(icmp, pkt)
				if err != nil {
					log.Error().Err(err).Msgf("failed to handle other ICMP message %s", err)
				}
				return

			}
		} else if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoRequest || icmp.TypeCode.Type() == layers.ICMPv4TypeEchoReply { //pkt.FromInterface.IPv4Network.Contains(ipsrc) &&
			log.Debug().Msgf("Got an ICMP packet from %s->%s. Going to pass through to NAT, as its probably a clients packet", ipsrc, ipdst)
		} else {
			log.Debug().Msgf("Got an ICMP response to %s:%s. Code=%s", ipsrc, ipdst, icmp.TypeCode)
			err := n.handleOtherICMP(icmp, pkt)
			if err != nil {
				log.Error().Err(err).Msgf("failed to handle other ICMP message %s", err)
			}

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
	// If the default gateway is ipv4, then we can NAT
	if common.IsIPv4(n.defaultGateway.IPv4Addr) {
		// Probably a NAT'able packet from here on
		// Drop the TTL. This will mean anything onwards should have the TTL down.
		ipv4.TTL -= 1
		if err := n.natPacket(pkt, pkt.Eth); err != nil {
			log.Error().Err(err).Msgf("failed to NAT packet %s", pkt)
		}
	}
}

// handleOtherICMP - Handles an ICMP message. Mostly REQ-4 on rfc5508
// Parse the ICMP payload (if there is one there).Then, check if it relates to an entry in our NAT table.
// We need to un-nat the IP level, and un-nat the TCP/UDP level if there is one.
// Then, we need to recreate a new ICMP packet (only way i can get editing the payload in gopacket working), and forward on - if its in our NAT table
// This function is a bit cumbersom and difficult to follow, and has only been tested in a small capacity,
func (n *Nat) handleOtherICMP(icmp *layers.ICMPv4, pkt *Packet) (err error) {

	payload := icmp.Payload
	outpkt := gopacket.NewPacket(payload, layers.LayerTypeIPv4, gopacket.Default)
	log.Debug().Interface("InputPacket", pkt).Interface("outpkt", outpkt).Msgf("Handing Other ICMP")

	if outpkt == nil {
		return ErrICMPFailure
	}
	newip, _ := outpkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if newip == nil {
		return ErrICMPFailure
	}

	var srcport, dstport uint16
	udp, _ := outpkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if udp != nil {
		srcport = uint16(udp.SrcPort)
		dstport = uint16(udp.DstPort)
		_ = udp.SetNetworkLayerForChecksum(pkt.Ip4)
	}
	tcp, _ := outpkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if tcp != nil {
		srcport = uint16(tcp.SrcPort)
		dstport = uint16(tcp.DstPort)
		_ = tcp.SetNetworkLayerForChecksum(pkt.Ip4)

	}
	icmpNew, _ := outpkt.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if icmpNew != nil {
		srcport = uint16(icmpNew.Seq)
	}

	natkey := NatKey{SrcPort: dstport, DstPort: srcport, SrcIP: newip.DstIP.String(), DstIP: newip.SrcIP.String(), Protocol: newip.Protocol}
	forwardEntry := n.table.Get(natkey)
	if forwardEntry == nil {
		log.Warn().Msgf("Recieved a ICMP unreachable message, but no entry in the nat table, possibly a bug. %s", natkey)
		return nil
	}

	toInterface := forwardEntry.Inf
	pkt.Eth.DstMAC = forwardEntry.DstMac
	pkt.Eth.SrcMAC = toInterface.IfHWAddr
	// Set embeded IP layer to the reverse of the expected packet
	newip.SrcIP = forwardEntry.DstIP
	newip.DstIP = forwardEntry.SrcIP
	// rfc5508 - REQ-7. This gets both Traceroutes and hairpinned ICMP errors working
	pkt.Ip4.DstIP = newip.SrcIP

	pkt.Ip4.TTL -= 1
	buffer := gopacket.NewSerializeBuffer()
	if tcp != nil {
		tcp.SrcPort = layers.TCPPort(forwardEntry.DstPort)

	} else if udp != nil {
		udp.SrcPort = layers.UDPPort(forwardEntry.DstPort)

	}
	err = gopacket.SerializeLayers(buffer, PktSerialisationOptions, pkt.Eth, pkt.Ip4, icmp, gopacket.Payload(common.ConvertPacket(outpkt)))

	if err != nil {
		log.Error().Err(err).Msgf("failed to serialize packet %s", err)
		return
	}

	log.Debug().Interface("InputPacket", pkt).Interface("outpkt", outpkt).Interface("natkey", natkey).Msgf("Handing Other ICMP (end)")

	if err = toInterface.Callback.SendBytes(buffer.Bytes()); err != nil {
		log.Error().Err(err).Msgf("failed to send packet %s", err)
	}
	return
}

func sendICMPPacketReverse(pkt *Packet, icmpType, icmpCode uint8) error {
	buf, err := common.CreateICMPPacket(pkt.Eth.DstMAC, pkt.Eth.SrcMAC, pkt.Ip4.DstIP, pkt.Ip4.SrcIP, icmpType, icmpCode)
	if err != nil {
		return fmt.Errorf("failed to create ICMP packet %w", err)
	}
	return pkt.FromInterface.Callback.SendBytes(buf)
}

func sendICMPv4EchoResponse(icmp *layers.ICMPv4, pkt *Packet) (err error) {
	// Drop the TTL. This will mean anything onwards should have the TTL down.
	pkt.Ip4.TTL -= 1
	// Flip the packet around, and send it pack. Shortcut to generating an ICMP packet.
	oldDstIp := pkt.Ip4.DstIP
	pkt.Ip4.DstIP = pkt.Ip4.SrcIP
	pkt.Ip4.SrcIP = oldDstIp

	oldDstMac := pkt.Eth.DstMAC
	pkt.Eth.DstMAC = pkt.Eth.SrcMAC
	pkt.Eth.SrcMAC = oldDstMac

	icmp.TypeCode = layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, layers.ICMPv4CodeNet)

	return pkt.FromInterface.Callback.Send(pkt)

}

func sendDHCPResponse(pkt *Packet, udp *layers.UDP, content []byte) (err error) {
	// Set layer 2
	pkt.Eth.DstMAC = pkt.Eth.SrcMAC
	pkt.Eth.SrcMAC = pkt.FromInterface.IfHWAddr

	// Set layer 3
	pkt.Ip4.SrcIP = pkt.FromInterface.IPv4Addr

	// Set layer 4
	oldIp := udp.DstPort
	udp.DstPort = udp.SrcPort
	udp.SrcPort = oldIp

	_ = udp.SetNetworkLayerForChecksum(pkt.Ip4)

	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, PktSerialisationOptions, pkt.Eth, pkt.Ip4, udp, gopacket.Payload(content))
	if err != nil {
		log.Error().Err(err).Msgf("failed to serialize packet %s", err)
		return
	}
	return pkt.FromInterface.Callback.SendBytes(buffer.Bytes())
}

func sendARPResponse(arp *layers.ARP, pkt *Packet) (err error) {
	// Generate ARP response
	arp.Operation = layers.ARPReply
	// Swap the protocol addresses
	old := arp.SourceProtAddress
	arp.SourceProtAddress = arp.DstProtAddress
	arp.DstProtAddress = old
	// src moves to dst. Dst is set
	arp.DstHwAddress = arp.SourceHwAddress
	arp.SourceHwAddress = pkt.FromInterface.IfHWAddr
	// Same for the ethernet level. Already swapped, so set them to same as the arp entry
	pkt.Eth.SrcMAC = arp.SourceHwAddress
	pkt.Eth.DstMAC = arp.DstHwAddress
	log.Info().Msgf("ARP Request to me, send this as my reply: %+v", arp)

	// Double checking there are no ZERO byte MAC addresses. Can cause some pain
	if bytes.Equal(arp.DstHwAddress, zeroHWAddr) ||
		bytes.Equal(arp.SourceHwAddress, zeroHWAddr) ||
		bytes.Equal(pkt.FromInterface.IfHWAddr, zeroHWAddr) {
		log.Fatal().Msgf("ARP Response has invalid data. %v", pkt)
	} else {
		err = pkt.FromInterface.Callback.Send(pkt)
	}
	return
}

func (n *Nat) doArp(dst net.IP, intf *Interface) (err error) {
	log.Info().Msgf("Doing an ARP request for %s from %s", dst, intf.IfName)
	// Send ARP request
	eth := &layers.Ethernet{
		SrcMAC:       intf.IfHWAddr,
		DstMAC:       net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType: layers.LinkTypeEthernet,
		Protocol: layers.EthernetTypeIPv4,

		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         1, // ARP Request,
		SourceHwAddress:   intf.IfHWAddr,
		DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		SourceProtAddress: intf.IPv4Addr.To4(),
		DstProtAddress:    dst.To4(),
	}
	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer,
		PktSerialisationOptions,
		eth,
		arp,
	)
	if err != nil {
		return
	}
	pkt := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	log.Debug().Msgf("======= Sending %v", pkt)
	err = intf.Callback.SendBytes(buffer.Bytes())
	if err != nil {
		return
	}
	return
}

// getEthAddr - get the Ethernet address of the ip
// 1. Check the ARP table
// 2. If not found, send ARP request on all interfaces that contains the ip
// 3. Then wait for ARP reply
func (n *Nat) getEthAddr(ip net.IP) (ArpEntry, error) {

	mac, ok := n.arpNotify.GetArpEntry(ip)
	if !ok {
		log.Warn().Msgf("failed to find gateway ARP entry for %s. Waiting", ip)

		for _, intVal := range n.interfaces {
			// log.Debug().Msgf("Checking %+v for %s. Waiting", intVal, ip)
			if intVal.IPv4Network.Contains(ip) {
				if err := n.doArp(ip, &intVal); err != nil {
					return EmptyArpEntry, err
				}
			}
		}

		// Wait for either the ARP response, or a timeout.
		mac, ok := n.arpNotify.WaitForArp(ip)
		if !ok {
			return EmptyArpEntry, fmt.Errorf("ARP entry not there, even after waiting. Bad news")

		}
		log.Info().Msgf("Got ARP entry for %s - %s after waiting", ip, mac)
		return mac, nil
	}

	return mac, nil
}
