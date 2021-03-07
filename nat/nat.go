package nat

import (
	"bytes"
	"errors"
	"fmt"
	"gonat/common"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"

	"github.com/rs/zerolog/log"
)

var (
	_, ZeroSlashZero, _ = net.ParseCIDR("0.0.0.0/0")
	_, MultiCast, _     = net.ParseCIDR("224.0.0.0/4")
	BroadCast           = net.ParseIP("255.255.255.255")
	ZeroAddress         = net.ParseIP("0.0.0.0")
	ErrICMPFailure      = errors.New("icmp failure")
	ErrARPFailure       = errors.New("arp failure")
	ErrNATFailure       = errors.New("nat failure")
	zeroHWAddr          = []byte{0, 0, 0, 0, 0, 0}
	srcPortMin          = 30000
	srcPortMax          = 60000
)

// type Interface struct {
// 	If       Interface
// 	Callback Dest
// }

type Nat struct {
	table               Nattable
	interfaces          map[string]Interface
	internalRoutes      []net.IPNet
	defaultGateway      Interface
	arpNotify           ARPNotify
	ip4defrager         *ip4defrag.IPv4Defragmenter
	nextSrcPort         uint16
	srcPortLock         sync.Mutex
	portForwardingTable map[PortForwardingKey]PortForwardingEntry
}

func CreateNat(defaultGateway Interface, lans []Interface, pfs []PFRule) (n *Nat) {
	rand.Seed(time.Now().UnixNano())
	randInt := rand.Intn(srcPortMax-srcPortMin) + srcPortMin
	n = &Nat{
		defaultGateway:      defaultGateway,
		ip4defrager:         ip4defrag.NewIPv4Defragmenter(),
		interfaces:          make(map[string]Interface),
		internalRoutes:      make([]net.IPNet, len(lans)),
		table:               Nattable{table: make(map[NatKey]*NatEntry), lock: sync.RWMutex{}},
		arpNotify:           ARPNotify{},
		nextSrcPort:         uint16(randInt),
		srcPortLock:         sync.Mutex{},
		portForwardingTable: make(map[PortForwardingKey]PortForwardingEntry),
	}
	for _, pf := range pfs {
		rangePorts := pf.ExternalPortEnd - pf.ExternalPortStart
		var protocol layers.IPProtocol
		if pf.Protocol == "tcp" {
			protocol = layers.IPProtocolTCP
		} else {
			protocol = layers.IPProtocolUDP
		}
		for i := uint16(0); i <= rangePorts; i++ {
			key := PortForwardingKey{
				ExternalPort: pf.ExternalPortStart + i,
				Protocol:     protocol,
			}
			n.portForwardingTable[key] = PortForwardingEntry{
				InternalPort: pf.InternalPortStart + i,
				InternalIP:   net.ParseIP(pf.InternalIP),
			}
			log.Debug().Msgf("port forwarding rule %v:%v", key, n.portForwardingTable[key])
		}
	}

	for _, r := range lans {
		n.interfaces[r.IfName] = r
		n.internalRoutes = append(n.internalRoutes, r.IPv4Network)
	}
	n.interfaces[defaultGateway.IfName] = defaultGateway
	go n.table.StartGarbageCollector()
	n.arpNotify.Init()
	return
}

// AcceptPkt decides what to do with a packet. I'm assuming all the packet layers are correct, so don't use the lazy option of gopacket
// I _think_ this is safe, and gopacket will throw an error before even getting here, TODO - test
func (n *Nat) AcceptPkt(pkt gopacket.Packet, ifName string) {

	eth := pkt.LinkLayer().(*layers.Ethernet)
	// From ipset
	fromInterface, ok := n.interfaces[ifName]
	if !ok {
		log.Fatal().Msgf("Could not find interface %s.", ifName)
		return
	}

	if eth.EthernetType == layers.EthernetTypeIPv4 {
		ipv4, _ := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		ipsrc, ipdst := common.GetIP(pkt.NetworkLayer())
		// Not from or two our interfaces - probably broadcast - routing isnt supported currently
		if !(fromInterface.IPv4Network.Contains(ipsrc) || fromInterface.IPv4Network.Contains(ipdst)) {

			// Check for DHCP here, only if its enabled on this interface.
			if ipdst.Equal(BroadCast) && fromInterface.DHCPEnabled {
				log.Debug().Msgf("DHCP packet recieved - %v", pkt)
				// check if its DHCP UDP
				if ipv4.Protocol == layers.IPProtocolUDP {
					udp, _ := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
					if dhcpPacket, ok := pkt.Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4); ok {

						req, err := fromInterface.DHCPHandler.Handle(dhcpPacket.Contents, ipsrc, int(udp.DstPort))
						if err != nil {
							log.Error().Err(err).Msgf("Error handling DHCP packet: %v", err)
							return
						}
						log.Info().Msgf("Handled DHCP Packet correctly - %+v", fromInterface.DHCPHandler)
						err = sendDHCPResponse(eth, ipv4, udp, &fromInterface, req)
						if err != nil {
							log.Error().Err(err).Msgf("Error sending DHCP response: %v", err)
						}
						return
					}
				}
			}
			// Not from our subnets or a broadcast
			log.Warn().Msgf("Packet on %s appears to be from other subnet, not yet supported. %s  does not contain either  %s not %s - dropping.\n", ifName, fromInterface.IPv4Network, ipsrc, ipdst)
			return
		}

		if MultiCast.Contains(ipdst) {
			log.Debug().Msgf("Dropping multicast packet for now -")
			return
		}

		if ipv4.TTL == 0 {
			log.Debug().Msgf("Dropping packet with TTL 0, sending Time Exceeded back")
			if err := sendICMPPacketReverse(ipv4, eth, &fromInterface, layers.ICMPv4TypeTimeExceeded, layers.ICMPv4CodeTTLExceeded); err != nil {
				log.Error().Err(err).Msgf("failed to send packet %s", err)
			}
			return

		} else if fromInterface.NatEnabled && (ipv4.Flags&layers.IPv4DontFragment == layers.IPv4DontFragment) {
			// rfc4787 - REQ-13
			lenPkt := len(pkt.Data())
			if lenPkt > n.defaultGateway.MTU {
				if err := sendICMPPacketReverse(ipv4, eth, &fromInterface, layers.ICMPv4TypeDestinationUnreachable, layers.ICMPv4CodeFragmentationNeeded); err != nil {
					log.Error().Err(err).Msgf("failed to send packet %s", err)
				}
				return
			}
		}

		if ipv4.Flags&layers.IPv4MoreFragments == layers.IPv4MoreFragments || ipv4.FragOffset > 0 {
			log.Info().Msgf("Got a fragmented IP packet, attempting to defrag it")
			ipv4Out, err := n.ip4defrager.DefragIPv4(ipv4)
			if err != nil {
				log.Error().Err(err).Msgf("failed to defrag the pkt %s", err)
				return
			} else if ipv4Out == nil {
				return
			}
			buffer := gopacket.NewSerializeBuffer()
			err = gopacket.SerializeLayers(buffer, common.Options,
				eth,
				ipv4Out,
				gopacket.Payload(ipv4Out.Payload),
			)
			if err != nil {
				log.Error().Err(err).Msgf("failed to serialize the defragmented packet %s", err)
				return
			}

			pktNew := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

			log.Info().Msgf("Successfully defragged the pkt, congrats! New length is - %v", pktNew)
			pkt = pktNew
			ipv4, _ = pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			ipsrc, ipdst = common.GetIP(pkt.NetworkLayer())
		}

		// Check if its icmp, and its addressed to ourself
		if ipv4.Protocol == layers.IPProtocolICMPv4 {
			icmp, _ := pkt.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
			if ipdst.Equal(fromInterface.IPv4Addr) {
				// Make sure its a request to
				if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoRequest {
					if err := sendICMPEchoResponse(ipv4, icmp, eth, pkt, &fromInterface); err != nil {
						log.Error().Err(err).Msgf("failed to send packet %s", err)
					}
					return // Sent packet or error'd. Dont NAT, return.
				} else if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoReply {
					log.Debug().Msgf("Got an ICMP response to %s:%s. Going to pass through to NAT, as its probably a clients packet - %s", ipsrc, ipdst, icmp.TypeCode)

				} else {
					// Currently tested on ICMPv4TypeTimeExceeded and ICMPv4TypeDestinationUnreachable.
					err := n.handleOtherICMP(eth, ipv4, icmp, pkt, &fromInterface)
					if err != nil {
						log.Error().Err(err).Msgf("failed to handle other ICMP message %s", err)
					}
					return

				}
			} else {
				log.Debug().Msgf("Got an ICMP response to %s:%s. Code=%s", ipsrc, ipdst, icmp.TypeCode)
				err := n.handleOtherICMP(eth, ipv4, icmp, pkt, &fromInterface)
				if err != nil {
					log.Error().Err(err).Msgf("failed to handle other ICMP message %s", err)
				}

			}
		}

		// Check if its from AND to a LAN interface
		// Im assuming its faster to just loop over internalRoutes, instead of implementing a ipnetwork tree object, as
		// most of the time there will only be one LAN network, at most a few.
		if fromInterface.NatEnabled {
			for _, route := range n.internalRoutes {
				if route.Contains(ipdst) {
					log.Debug().Msgf("Packet to %s:%s is internal. Sending straight out the right interface", ipsrc, ipdst)
					n.routeInternally(ipv4, eth, pkt)
					return
				}
			}
		}

		// Probably a NAT'able packet from here on
		if err := n.natPacket(pkt, ipv4, eth, &fromInterface); err != nil {
			log.Error().Err(err).Msgf("failed to NAT packet %s", pkt)
		}
		return

	} else if eth.EthernetType == layers.EthernetTypeIPv6 {
		// TODO. ignoring ipv6 for now - who uses it _anyway_?
	} else if eth.EthernetType == layers.EthernetTypeARP {
		arp, _ := pkt.Layer(layers.LayerTypeARP).(*layers.ARP)
		log.Debug().Msgf("Arg message receieved-  %+v", arp)

		if fromInterface.IPv4Addr.Equal(arp.DstProtAddress) && arp.Operation == 1 { // 1 is ARPRequest
			if err := sendARPResponse(arp, eth, pkt, &fromInterface); err != nil {
				log.Error().Err(err).Msgf("failed to send packet %s", err)
			}
			return // Sent packet or error'd. Dont NAT, return.

		} else {
			// Else, some other ARP message. Lets just update the ARP table from the messages regardless of who its for. No possible poising issue here. updateArpTable checks for zero byte macs
			log.Debug().Msgf("ARP message seen. Updating table. %v:%v, %v:%v", arp.SourceHwAddress, arp.SourceProtAddress, arp.DstHwAddress, arp.DstProtAddress)
			n.updateArpTable(arp.SourceHwAddress, arp.SourceProtAddress, fromInterface.IfName)
			n.updateArpTable(arp.DstHwAddress, arp.DstProtAddress, fromInterface.IfName)
		}
	} else {
		log.Info().Msgf("Some other pkt type - %d. Currently unsupported - %s", eth.EthernetType, pkt)
	}
}

// handleOtherICMP - Handles an ICMP message. Mostly REQ-4 on rfc5508
// Parse the ICMP payload (if there is one there).Then, check if it relates to an entry in our NAT table.
// We need to un-nat the IP level, and un-nat the TCP/UDP level if there is one.
// Then, we need to recreate a new ICMP packet (only way i can get editing the payload in gopacket working), and forward on - if its in our NAT table
// This function is a bit cumbersom and difficult to follow, and has only been tested in a small capacity,
func (n *Nat) handleOtherICMP(eth *layers.Ethernet, ipv4 *layers.IPv4, icmp *layers.ICMPv4, pkt gopacket.Packet, fromInterface *Interface) (err error) {

	payload := icmp.Payload
	outpkt := gopacket.NewPacket(payload, layers.LayerTypeIPv4, gopacket.Default)
	log.Info().Msgf("=====================================Input pkts ------ =====================================\n%v\n%v", pkt, outpkt)

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
		udp.SetNetworkLayerForChecksum(ipv4)
	}
	tcp, _ := outpkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if tcp != nil {
		srcport = uint16(tcp.SrcPort)
		dstport = uint16(tcp.DstPort)
		tcp.SetNetworkLayerForChecksum(ipv4)

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
	eth.DstMAC = forwardEntry.DstMac
	eth.SrcMAC = toInterface.IfHWAddr
	// Set embeded IP layer to the reverse of the expected packet
	newip.SrcIP = forwardEntry.DstIP
	newip.DstIP = forwardEntry.SrcIP
	// rfc5508 - REQ-7. This gets both Traceroutes and hairpinned ICMP errors working
	ipv4.DstIP = newip.SrcIP

	ipv4.TTL -= 1
	buffer := gopacket.NewSerializeBuffer()
	if tcp != nil {
		tcp.SrcPort = layers.TCPPort(forwardEntry.DstPort)

	} else if udp != nil {
		udp.SrcPort = layers.UDPPort(forwardEntry.DstPort)

	}
	err = gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ipv4, icmp, gopacket.Payload(common.ConvertPacket(outpkt)))

	if err != nil {
		log.Error().Err(err).Msgf("failed to serialize packet %s", err)
		return
	}

	log.Info().Msgf("=====================================output pkts for %s ------ =====================================\n%v\n%v", natkey, pkt, outpkt)
	toInterface.Callback.SendBytes(buffer.Bytes())
	return
}

func (n *Nat) routeInternally(ipv4 *layers.IPv4, eth *layers.Ethernet, pkt gopacket.Packet) (err error) {
	arpEntry, err := n.getEthAddr(ipv4.DstIP)
	if err != nil {
		log.Error().Err(err).Msgf("Failed to get eth addr for %s", ipv4.DstIP)
		return
	}
	eth.DstMAC = arpEntry.Mac
	toInterface, ok := n.interfaces[arpEntry.IntName]
	if !ok {
		log.Error().Msgf("Interface %s not found", arpEntry.IntName)
		return
	}
	eth.SrcMAC = toInterface.IfHWAddr

	return toInterface.Callback.Send(pkt)

}

func sendICMPPacketReverse(ipv4 *layers.IPv4, eth *layers.Ethernet, fromInterface *Interface, icmpType, icmpCode uint8) error {
	buf, err := common.CreateICMPPacket(eth.DstMAC, eth.SrcMAC, ipv4.DstIP, ipv4.SrcIP, icmpType, icmpCode)
	if err != nil {
		return err
	}
	return fromInterface.Callback.SendBytes(buf)
}

func sendICMPEchoResponse(ipv4 *layers.IPv4, icmp *layers.ICMPv4, eth *layers.Ethernet, pkt gopacket.Packet, fromInterface *Interface) (err error) {
	// Flip the packet around, and send it pack. Shortcut to generating an ICMP packet.
	oldEth := ipv4.DstIP
	ipv4.DstIP = ipv4.SrcIP
	// Drop the TTL. This will mean anything onwards should have the TTL down.
	ipv4.TTL -= 1

	ipv4.SrcIP = oldEth
	icmp.TypeCode = layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, layers.ICMPv4CodeNet)

	oldIP := eth.DstMAC
	eth.DstMAC = eth.SrcMAC
	eth.SrcMAC = oldIP

	return fromInterface.Callback.Send(pkt)

}

func sendDHCPResponse(eth *layers.Ethernet, ipv4 *layers.IPv4, udp *layers.UDP, fromInterface *Interface, content []byte) (err error) {
	// Set layer 2
	eth.DstMAC = eth.SrcMAC
	eth.SrcMAC = fromInterface.IfHWAddr

	// Set layer 3
	ipv4.SrcIP = fromInterface.IPv4Addr

	// Set layer 4
	oldIp := udp.DstPort
	udp.DstPort = udp.SrcPort
	udp.SrcPort = oldIp

	udp.SetNetworkLayerForChecksum(ipv4)

	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ipv4, udp, gopacket.Payload(content))
	if err != nil {
		log.Error().Err(err).Msgf("failed to serialize packet %s", err)
		return
	}
	return fromInterface.Callback.SendBytes(buffer.Bytes())
}

func sendARPResponse(arp *layers.ARP, eth *layers.Ethernet, pkt gopacket.Packet, fromInterface *Interface) (err error) {
	// Generate ARP response
	arp.Operation = layers.ARPReply
	// Swap the protocol addresses
	old := arp.SourceProtAddress
	arp.SourceProtAddress = arp.DstProtAddress
	arp.DstProtAddress = old
	// src moves to dst. Dst is set
	arp.DstHwAddress = arp.SourceHwAddress
	arp.SourceHwAddress = fromInterface.IfHWAddr
	// Same for the ethernet level. Already swapped, so set them to same as the arp entry
	eth.SrcMAC = arp.SourceHwAddress
	eth.DstMAC = arp.DstHwAddress
	log.Info().Msgf("ARP Request to me, send this as my reply: %+v", arp)

	// Double checking there are no ZERO byte MAC addresses. Can cause some pain
	if bytes.Equal(arp.DstHwAddress, zeroHWAddr) ||
		bytes.Equal(arp.SourceHwAddress, zeroHWAddr) ||
		bytes.Equal(fromInterface.IfHWAddr, zeroHWAddr) {
		log.Fatal().Msgf("ARP Response has invalid data. %v", pkt)
	} else {
		err = fromInterface.Callback.Send(pkt)
	}
	return
}

// natPacket - I'm going to blindly trust that the layer4 protocol will decode. Trusting that gopacket when lazy=false
func (n *Nat) natPacket(pkt gopacket.Packet, ipv4 *layers.IPv4, eth *layers.Ethernet, fromInterface *Interface) (err error) {
	var srcport, dstport uint16
	var tcp *layers.TCP
	var udp *layers.UDP
	var icmp *layers.ICMPv4
	var toInterface *Interface
	originalSourceIP := ipv4.SrcIP
	protocol := ipv4.Protocol
	// Drop the TTL. This will mean anything onwards should have the TTL down.
	ipv4.TTL -= 1

	if protocol == layers.IPProtocolTCP {
		// Get actual TCP data from this layer
		tcp, _ = pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
		srcport = uint16(tcp.SrcPort)
		dstport = uint16(tcp.DstPort)
		tcp.SetNetworkLayerForChecksum(ipv4)
	} else if protocol == layers.IPProtocolUDP {
		// Get actual UDP data from this layer
		udp, _ = pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
		srcport = uint16(udp.SrcPort)
		dstport = uint16(udp.DstPort)
		udp.SetNetworkLayerForChecksum(ipv4)
	} else if protocol == layers.IPProtocolICMPv4 {
		icmp, _ = pkt.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
		srcport = uint16(icmp.Seq)
	} else if ipv4.Protocol == layers.IPProtocolIGMP {
		log.Debug().Msgf("Trying to NAT IGMP. Going to pass this through, TODO - investigate")
	} else {
		log.Warn().Msgf("Trying to NAT unsupported protocol. You better hope a layer 2/3 NAT works. - %s", pkt)
	}
	log.Debug().Msgf("Input packet - %s==(%s:%d->%s:%d)", fromInterface.IfName, ipv4.SrcIP, srcport, ipv4.DstIP, dstport)
	// Unique Tuple for this packet
	natkey := NatKey{SrcPort: srcport, DstPort: dstport, SrcIP: ipv4.SrcIP.String(), DstIP: ipv4.DstIP.String(), Protocol: protocol}
	// Decide if we should nat the packet. First check if we would NAT this packet anyway
	forwardEntry := n.table.Get(natkey)

	if forwardEntry != nil {
		// Already natted previously - keep the same NAT
		log.Debug().Msgf("Already NAT'e'd %s. Using old entry %v", natkey, forwardEntry)

		ipv4.DstIP = forwardEntry.DstIP
		ipv4.SrcIP = forwardEntry.SrcIP
		toInterface = forwardEntry.Inf
		eth.DstMAC = forwardEntry.DstMac
		if tcp != nil {
			tcp.SrcPort = layers.TCPPort(forwardEntry.SrcPort)
			tcp.DstPort = layers.TCPPort(forwardEntry.DstPort)
		} else if udp != nil {
			udp.SrcPort = layers.UDPPort(forwardEntry.SrcPort)
			udp.DstPort = layers.UDPPort(forwardEntry.DstPort)
		} else if icmp != nil {
			icmp.Seq = uint16(forwardEntry.SrcPort)
		}
	} else {
		// Not natted previously - find a new NAT if
		// 1. we're on a NAT enabled port
		// 2. the dst port is in the port forward table.

		// If its addresssed to me (non WAN interface), then its probably DNS.
		if dstport == 53 && fromInterface.NatEnabled && ipv4.DstIP.Equal(fromInterface.IPv4Addr) {
			// DNS - TODO
			log.Warn().Msgf("Recieved DNS packet addressed to me on %s. Not currently supported.", fromInterface.IfName)
		}

		originalSrcPort := srcport
		originalDstPort := dstport
		originalDstIp := ipv4.DstIP
		var expectedDstIP net.IP
		if !fromInterface.NatEnabled || n.defaultGateway.IPv4Addr.Equal(ipv4.DstIP) {

			// Hairpin
			if fromInterface.NatEnabled && n.defaultGateway.IPv4Addr.Equal(ipv4.DstIP) {
				ipv4.SrcIP = n.defaultGateway.IPv4Addr
			}

			// Unseen packet on the non nat interface.
			// Check if the packet is in the port forward table
			pfkey := PortForwardingKey{ExternalPort: dstport, Protocol: protocol}
			entry, ok := n.portForwardingTable[pfkey]
			if !ok {
				log.Debug().Msgf("Dropping pkt %s on %s as its not in the port forwarding table", natkey, fromInterface.IfName)
				return
			}
			log.Info().Msgf("New packet matches port forwarding rule: %+v  ---- %+v", pfkey, entry)
			ipv4.DstIP = entry.InternalIP
			tmp, errTmp := n.getEthAddr(entry.InternalIP)
			if errTmp != nil {
				log.Error().Err(err).Msgf("Failed to get MAC address for %s", entry.InternalIP)
				return
			}
			toInterfaceTmp := n.interfaces[tmp.IntName]
			toInterface = &toInterfaceTmp
			eth.DstMAC = tmp.Mac
			expectedDstIP = ipv4.SrcIP
			dstport = entry.InternalPort

			if protocol == layers.IPProtocolTCP {
				tcp.DstPort = layers.TCPPort(entry.InternalPort)
			} else if protocol == layers.IPProtocolUDP {
				udp.DstPort = layers.UDPPort(entry.InternalPort)
			}

			// } else if n.defaultGateway.IPv4Addr.Equal(ipv4.DstIP) {
			// 	log.Info().Msg("Hairpinned packet session initiated")
			// 	return
		} else {
			ipv4.SrcIP = n.defaultGateway.IPv4Addr
			toInterface = &n.defaultGateway
			expectedDstIP = toInterface.IPv4Addr
			tmp, errTmp := n.getEthAddr(toInterface.IPv4Gateway)
			if errTmp != nil {
				log.Error().Err(err).Msgf("Failed to get MAC address for %s", toInterface.IPv4Gateway)
				return
			}
			eth.DstMAC = tmp.Mac

		}

		// New NAT
		// Create reverse entry key. If its TCP or UDP, find a source port that matches the RFC
		// holds a reference to a key of the forward direction.
		reverseEntry := &NatEntry{SrcPort: originalDstPort, DstPort: originalSrcPort, SrcIP: originalDstIp, Inf: fromInterface, DstIP: originalSourceIP, DstMac: eth.SrcMAC, ReverseKey: &natkey}
		reverseKey := n.chooseSrcPort(dstport, srcport, &ipv4.DstIP, &expectedDstIP, &protocol, reverseEntry, 0)
		srcport = reverseKey.DstPort
		if tcp != nil {
			tcp.SrcPort = layers.TCPPort(srcport)
		} else if udp != nil {
			udp.SrcPort = layers.UDPPort(srcport)
		} else if icmp != nil {
			icmp.Seq = uint16(srcport)
		}
		// Create new forward entries. hold a reference to a key of the reverse direction.
		forwardEntry = &NatEntry{SrcPort: srcport, SrcIP: ipv4.SrcIP, Inf: toInterface, DstPort: dstport, DstIP: ipv4.DstIP, DstMac: eth.DstMAC, ReverseKey: reverseKey}
		log.Debug().Msgf("New NAT (forward) for %s - %s", fromInterface.IfName, natkey)

	}

	// NAT Layer 2
	eth.SrcMAC = toInterface.IfHWAddr

	// Update packet contents
	log.Debug().Msgf("Spitted on %s packet =  (%v)", toInterface.IfName, pkt)

	// Send packet
	err = toInterface.Callback.Send(pkt)
	if err != nil {
		return
	}

	// Consider TCP flags. This doesnt need to be done above, as only a SYN can create a reverse NAT entry.
	if tcp != nil {
		n.trackTCPSimple(forwardEntry, tcp)
	}
	// Update NAT table for sent packet - so next packet can use the same tuple.
	n.table.Store(natkey, forwardEntry)
	// log.Info().Msgf("Redo NAT for %s - %v %v", toInterface.IfName, natkey, forwardEntry)

	return
}

// chooseSrcPort. Tries to pick a source port to use. Try the actual source port first (called 'port preservation' in the RFC).
// If that fails, pick a port in the same range (0-1023 or 1024-65535 - rfc4787 REQ3), and keep parity (rfc4787 REQ4)
func (n *Nat) chooseSrcPort(p1, selectPort uint16, i1, i2 *net.IP, prot *layers.IPProtocol, entry *NatEntry, recursionCount int) (tryKey *NatKey) {
	tryKey = &NatKey{SrcPort: p1, DstPort: selectPort, SrcIP: i1.String(), DstIP: i2.String(), Protocol: *prot}
	n.table.lock.Lock()

	_, ok := n.table.table[*tryKey]
	// Entry not in table, safe to create then return
	// I think its safe to re-use the same id for ICMP - i think this happens in some cases (DestUnreach).
	if !ok || *prot == layers.IPProtocolICMPv4 {
		n.table.table[*tryKey] = entry
		n.table.lock.Unlock()
		log.Debug().Msgf("New NAT (reverse) for %s - %s", entry.Inf.IfName, tryKey)

		return
	}
	// Entry already in table, try to find a port in the same range, and keep parity
	log.Warn().Msgf("key %v already in the nat table, this should be very uncommon, and could be a sign of a bug. Incrementing %d", *tryKey, selectPort)

	// Wrap source port to keep it in the correct range, and correct parity, before incrementing via two and recusing.
	if selectPort >= 1021 && selectPort <= 1023 {
		selectPort -= 1018
	} else if selectPort >= 65533 && selectPort <= 65535 {
		selectPort -= 64510
	}

	if recursionCount > 10 {
		log.Warn().Msgf("Recursive limit exceeded, definately a big issue.")
		return nil
	}

	n.table.lock.Unlock()
	return n.chooseSrcPort(p1, selectPort+2, i1, i2, prot, entry, recursionCount+1)
}

// trackTCPSimple - I implemented the actual 3 or 4 way handshake (trackTCP)
// But realised it was easier and more efficient to wait for both FINs.
// Once i see a FIN from both directions, close both ends.
// Technically, the FIN might not make it, i dont think this is too much of an issue
// Worst case scenario, we will just
// leave one end in a LAST_ACK state and the other in a FINWAIT_2 or TIME_WAIT.
// Being middleware - i can't guarentee the last ACK made it anyway - but when in CLOSE state
// I set the timeout to a short period of time regardless
func (n *Nat) trackTCPSimple(forwardEntry *NatEntry, tcp *layers.TCP) {
	if tcp.FIN {
		// If already closed (possibly a RST), ignore FIN
		if forwardEntry.TcpState.State == TCPClosed {
			return
		}
		other := n.table.Get(*forwardEntry.ReverseKey)
		forwardEntry.TcpState.State = TCPTimeWait
		if other.TcpState.State == TCPTimeWait {
			log.Debug().Msgf("TCP Connection closed %v", forwardEntry)
			forwardEntry.TcpState.State = TCPClosed
			other.TcpState.State = TCPClosed
		}

	} else if tcp.RST {
		other := n.table.Get(*forwardEntry.ReverseKey)
		forwardEntry.TcpState.State = TCPClosed
		other.TcpState.State = TCPClosed
	}
}

//lint:ignore U1000 See trackTCP comment
func (n *Nat) trackTCP(forwardEntry *NatEntry, tcp *layers.TCP) {
	// If we've already seen our first FIN
	if forwardEntry.TcpState.State >= 4 {

		// First, find who initiated/received
		var initiator, reciever *NatEntry
		if forwardEntry.TcpState.Initiator {
			initiator = forwardEntry
			reciever = n.table.Get(*forwardEntry.ReverseKey)
		} else {
			initiator = n.table.Get(*forwardEntry.ReverseKey)
			reciever = forwardEntry
		}

		// 2nd packet in 4 way handshake
		if initiator.TcpState.State == TCPFinWait1 && reciever.TcpState.State == TCPCloseWait {
			// Is this actually the ACK for a FIN, or just an unrelated ACK (more data which was on its way).
			if tcp.ACK && tcp.Ack == initiator.TcpState.FinackSequence {

				// Three way handshake
				if tcp.FIN {
					initiator.TcpState.State = TCPTimeWait
					reciever.TcpState.State = TCPLastAck
					initiator.TcpState.FinackSequence = tcp.Seq
				} else { // Full 4 way.
					initiator.TcpState.State = TCPFinWait2
					reciever.TcpState.State = TCPCloseWait // should be already set, but for clarity
				}
			}
		} else if initiator.TcpState.State == TCPFinWait2 && reciever.TcpState.State == TCPCloseWait {
			// Already seen an ACK for the FIN, this is a second FIN.
			if tcp.FIN {
				initiator.TcpState.State = TCPTimeWait
				reciever.TcpState.State = TCPLastAck // should be already set, but for clarity
				initiator.TcpState.FinackSequence = tcp.Seq

			}
		} else if initiator.TcpState.State == TCPTimeWait && reciever.TcpState.State == TCPLastAck {
			// Is this actually the ACK for a FIN, or just an unrelated ACK (more data which was on its way).
			if tcp.ACK && tcp.Ack == initiator.TcpState.FinackSequence {
				initiator.TcpState.State = TCPClosed
				reciever.TcpState.State = TCPClosed

			}
		}

	} else if tcp.FIN { // our first FIN
		forwardEntry.TcpState.FinackSequence = tcp.Seq
		forwardEntry.TcpState.Initiator = true
		receiverEntry := n.table.Get(*forwardEntry.ReverseKey)
		forwardEntry.TcpState.State = TCPFinWait1
		receiverEntry.TcpState.State = TCPCloseWait
		receiverEntry.TcpState.Initiator = false
	}
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
			return EmptyArpEntry, fmt.Errorf("ARP entry not there, even after waiting. Bad news ")
		}
		log.Info().Msgf("Got ARP entry for %s - %s after waiting", ip, mac)
		return mac, nil
	}

	return mac, nil
}

func (n *Nat) updateArpTable(mac net.HardwareAddr, ip net.IP, interfaceName string) {

	// If mac is not 0:0:0:0:0:0, then update ARP table.
	if !bytes.Equal(mac, []byte{0, 0, 0, 0, 0, 0}) {
		n.arpNotify.AddArpEntry(ip, mac, interfaceName)
	}
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
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth,
		arp,
	)
	if err != nil {
		return
	}
	pkt := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	log.Debug().Msgf("======= Sending %v", pkt)
	err = intf.Callback.Send(pkt)
	if err != nil {
		return
	}
	return
}
