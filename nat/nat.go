package nat

import (
	"bytes"
	"errors"
	"fmt"
	"gonat/dhcp"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
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

type IfSet struct {
	If       Interface
	Callback Dest
}

type Nat struct {
	table               Nattable
	interfaces          map[string]IfSet
	defaultGateway      IfSet
	arpNotify           ARPNotify
	dhcp                dhcp.DHCPHandler
	nextSrcPort         uint16
	srcPortLock         sync.Mutex
	portForwardingTable map[uint16]*PortForwardingRule
}

func CreateNat(defaultGateway IfSet, lans []IfSet, pfs []PortForwardingRule) (n *Nat) {
	rand.Seed(time.Now().UnixNano())
	randInt := rand.Intn(srcPortMax-srcPortMin) + srcPortMin
	n = &Nat{
		defaultGateway:      defaultGateway,
		interfaces:          make(map[string]IfSet),
		dhcp:                dhcp.NewDHCPHandler(),
		table:               Nattable{},
		arpNotify:           ARPNotify{},
		nextSrcPort:         uint16(randInt),
		srcPortLock:         sync.Mutex{},
		portForwardingTable: make(map[uint16]*PortForwardingRule),
	}
	for _, pf := range pfs {
		for i := pf.ExternalPortStart; i <= pf.ExternalPortEnd; i++ {
			n.portForwardingTable[i] = &pf
		}
	}

	for _, r := range lans {
		n.interfaces[r.If.IfName] = r
	}
	n.interfaces[defaultGateway.If.IfName] = defaultGateway
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

		// Not from or two our interfaces - probably broadcast - routing isnt supported currently
		if !(fromInterface.If.IPv4Network.Contains(ipv4.SrcIP) || fromInterface.If.IPv4Network.Contains(ipv4.DstIP)) {

			// Check for DHCP here, only if its enabled on this interface.
			if ipv4.DstIP.Equal(BroadCast) && fromInterface.If.DHCPEnabled {
				log.Info().Msgf("Broadcast packet - %v", pkt)
				// check if its DHCP UDP
				if ipv4.Protocol == layers.IPProtocolUDP {
					udp, _ := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
					if dhcpPacket, ok := pkt.Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4); ok {

						req, err := n.dhcp.Handle(dhcpPacket.Contents, ipv4.SrcIP, int(udp.DstPort))
						if err != nil {
							log.Error().Err(err).Msgf("Error handling DHCP packet: %v", err)
							return
						}
						log.Info().Msgf("Handled DHCP Packet correctly - %+v", n.dhcp)
						err = sendDHCPResponse(eth, ipv4, udp, fromInterface, req)
						if err != nil {
							log.Error().Err(err).Msgf("Error sending DHCP response: %v", err)
						}
						return
					}
				}
			}
			// Not from our subnets or a broadcast
			log.Warn().Msgf("Packet on %s appears to be from other subnet, not yet supported. %s  does not contain either  %s not %s - dropping.\n", ifName, fromInterface.If.IPv4Network, ipv4.SrcIP, ipv4.DstIP)
			return
		}

		if MultiCast.Contains(ipv4.DstIP) {
			log.Debug().Msgf("Dropping multicast packet for now -")
			return
		}

		// Check if its icmp, and its addressed to ourself
		if ipv4.Protocol == layers.IPProtocolICMPv4 {
			icmp, _ := pkt.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
			if ipv4.DstIP.Equal(fromInterface.If.IPv4Addr) {
				// Make sure its a request to
				if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoRequest {
					if err := sendICMPResponse(ipv4, icmp, eth, pkt, fromInterface); err != nil {
						log.Error().Err(err).Msgf("failed to send packet %s", err)
					}
					return // Sent packet or error'd. Dont NAT, return.
				} else if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoReply {
					log.Debug().Msgf("Got an ICMP response to %s:%s. Going to pass through to NAT, as its probably a clients packet - %s", ipv4.SrcIP, ipv4.DstIP, icmp.TypeCode)

				} else {
					log.Warn().Msgf("ICMP message sent to me, but not a request? ,Code=%s", icmp.TypeCode)
					return
				}
			} else {
				log.Debug().Msgf("Got an ICMP response to %s:%s. Code=%s", ipv4.SrcIP, ipv4.DstIP, icmp.TypeCode)
			}
		}

		// Probably a NAT'able packet from here on
		if err := n.natPacket(pkt, ipv4, eth, fromInterface); err != nil {
			log.Error().Err(err).Msgf("failed to NAT packet %s", pkt)
		}
		return

	} else if eth.EthernetType == layers.EthernetTypeIPv6 {
		// TODO. ignoring ipv6 for now - who uses it _anyway_?
	} else if eth.EthernetType == layers.EthernetTypeARP {
		arp, _ := pkt.Layer(layers.LayerTypeARP).(*layers.ARP)
		log.Debug().Msgf("Arg message receieved-  %+v", arp)

		if fromInterface.If.IPv4Addr.Equal(arp.DstProtAddress) && arp.Operation == 1 { // 1 is ARPRequest
			if err := sendARPResponse(arp, eth, pkt, fromInterface); err != nil {
				log.Error().Err(err).Msgf("failed to send packet %s", err)
			}
			return // Sent packet or error'd. Dont NAT, return.

		} else {
			// Else, some other ARP message. Lets just update the ARP table from the messages regardless of who its for. No possible poising issue here. updateArpTable checks for zero byte macs
			log.Debug().Msgf("ARP message seen. Updating table. %v:%v, %v:%v", arp.SourceHwAddress, arp.SourceProtAddress, arp.DstHwAddress, arp.DstProtAddress)
			n.updateArpTable(arp.SourceHwAddress, arp.SourceProtAddress)
			n.updateArpTable(arp.DstHwAddress, arp.DstProtAddress)
		}
	} else {
		log.Info().Msgf("Some other pkt type - %d. Currently unsupported - %s", eth.EthernetType, pkt)
	}
}
func sendICMPResponse(ipv4 *layers.IPv4, icmp *layers.ICMPv4, eth *layers.Ethernet, pkt gopacket.Packet, fromInterface IfSet) (err error) {
	// Flip the packet around, and send it pack. Shortcut to generating an ICMP packet.
	oldEth := ipv4.DstIP
	ipv4.DstIP = ipv4.SrcIP
	ipv4.SrcIP = oldEth
	icmp.TypeCode = layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, layers.ICMPv4CodeNet)

	oldIP := eth.DstMAC
	eth.DstMAC = eth.SrcMAC
	eth.SrcMAC = oldIP

	return fromInterface.Callback.Send(pkt)

}

func sendDHCPResponse(eth *layers.Ethernet, ipv4 *layers.IPv4, udp *layers.UDP, fromInterface IfSet, content []byte) (err error) {
	// Set layer 2
	eth.DstMAC = eth.SrcMAC
	eth.SrcMAC = fromInterface.If.IfHWAddr

	// Set layer 3
	ipv4.SrcIP = fromInterface.If.IPv4Addr

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

func sendARPResponse(arp *layers.ARP, eth *layers.Ethernet, pkt gopacket.Packet, fromInterface IfSet) (err error) {
	// Generate ARP response
	arp.Operation = layers.ARPReply
	// Swap the protocol addresses
	old := arp.SourceProtAddress
	arp.SourceProtAddress = arp.DstProtAddress
	arp.DstProtAddress = old
	// src moves to dst. Dst is set
	arp.DstHwAddress = arp.SourceHwAddress
	arp.SourceHwAddress = fromInterface.If.IfHWAddr
	// Same for the ethernet level. Already swapped, so set them to same as the arp entry
	eth.SrcMAC = arp.SourceHwAddress
	eth.DstMAC = arp.DstHwAddress
	log.Info().Msgf("ARP Request to me, send this as my reply: %+v", arp)

	// Double checking there are no ZERO byte MAC addresses. Can cause some pain
	if bytes.Equal(arp.DstHwAddress, zeroHWAddr) ||
		bytes.Equal(arp.SourceHwAddress, zeroHWAddr) ||
		bytes.Equal(fromInterface.If.IfHWAddr, zeroHWAddr) {
		log.Fatal().Msgf("ARP Response has invalid data. %v", pkt)
	} else {
		err = fromInterface.Callback.Send(pkt)
	}
	return
}

// natPacket - I'm going to blindly trust that the layer4 protocol will decode. Trusting that gopacket when lazy=false
func (n *Nat) natPacket(pkt gopacket.Packet, ipv4 *layers.IPv4, eth *layers.Ethernet, fromInterface IfSet) (err error) {
	var srcport, dstport uint16
	var tcp *layers.TCP
	var udp *layers.UDP
	var toInterface *IfSet
	originalSourceIP := ipv4.SrcIP
	protocol := ipv4.Protocol

	if protocol == layers.IPProtocolTCP {
		// Get actual TCP data from this layer
		tcpLayer := pkt.Layer(layers.LayerTypeTCP)
		tcp, _ = tcpLayer.(*layers.TCP)
		srcport = uint16(tcp.SrcPort)
		dstport = uint16(tcp.DstPort)
		tcp.SetNetworkLayerForChecksum(ipv4)
	} else if protocol == layers.IPProtocolUDP {
		// Get actual UDP data from this layer
		udpLayer := pkt.Layer(layers.LayerTypeUDP)
		udp, _ = udpLayer.(*layers.UDP)
		srcport = uint16(udp.SrcPort)
		dstport = uint16(udp.DstPort)
		udp.SetNetworkLayerForChecksum(ipv4)
	} else if protocol == layers.IPProtocolICMPv4 {
		log.Debug().Msgf("ICMP packet entering NAT.")
	} else if ipv4.Protocol == layers.IPProtocolIGMP {
		log.Debug().Msgf("Trying to NAT IGMP. Going to pass this through, TODO - investigate")
	} else {
		log.Warn().Msgf("Trying to NAT unsupported protocol. You better hope a layer 2/3 NAT works. - %s", pkt)
	}
	log.Debug().Msgf("Input packet - %s==(%s:%d->%s:%d)", fromInterface.If.IfName, ipv4.SrcIP, srcport, ipv4.DstIP, dstport)
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
		}

	} else if fromInterface.If.NatEnabled {

		// If its addresssed to me, then its probably DNS
		if ipv4.DstIP.Equal(fromInterface.If.IPv4Addr) {
			if dstport == 53 {
				// DNS, change the DST ip.
				log.Warn().Msgf("Recieved DNS packet addressed to me on %s. Not currently supported.", fromInterface.If.IfName)
			}
		}

		// If its TCP, only NAT when SYN is set
		if tcp != nil && !tcp.SYN {
			log.Error().Msgf("Will not initiate a NAT when the TCP SYN flag is not set %s", pkt)
			return
		}

		// New NAT
		ipv4.SrcIP = n.defaultGateway.If.IPv4Addr
		toInterface = &n.defaultGateway
		eth.DstMAC, err = n.getEthAddr(toInterface.If.IPv4Gateway, toInterface)
		if err != nil {
			log.Error().Err(err).Msgf("Failed to get MAC address for %s", toInterface.If.IPv4Gateway)
			return
		}

		expectedSrcPort := srcport
		if tcp != nil || udp != nil {
			n.srcPortLock.Lock()
			srcport = n.nextSrcPort
			n.nextSrcPort += 1
			if int(n.nextSrcPort) > srcPortMax {
				n.nextSrcPort = uint16(srcPortMin)
			}
			n.srcPortLock.Unlock()
			if tcp != nil {
				tcp.SrcPort = layers.TCPPort(srcport)
			} else {
				udp.SrcPort = layers.UDPPort(srcport)
			}

		}

		// Create reverse entry key
		reverseKey := NatKey{SrcPort: dstport, DstPort: srcport, SrcIP: ipv4.DstIP.String(), DstIP: toInterface.If.IPv4Addr.String(), Protocol: protocol}

		// Create both entries. Each hold a reference to a key of the reverse direction.
		forwardEntry = &NatEntry{SrcPort: srcport, SrcIP: ipv4.SrcIP, Inf: toInterface, DstPort: dstport, DstIP: ipv4.DstIP, DstMac: eth.DstMAC, ReverseKey: &reverseKey}
		reverseEntry := &NatEntry{SrcPort: dstport, DstPort: expectedSrcPort, SrcIP: ipv4.DstIP, Inf: &fromInterface, DstIP: originalSourceIP, DstMac: eth.SrcMAC, ReverseKey: &natkey}
		n.table.Store(reverseKey, reverseEntry)
		log.Debug().Msgf("New NAT (forward) for %s - %s", fromInterface.If.IfName, natkey)
		log.Debug().Msgf("New NAT (reverse) for %s - %s", fromInterface.If.IfName, reverseKey)
	} else if !fromInterface.If.NatEnabled {
		// Check if the packet is in the port forward table
		return
	} else {
		return
	}

	// NAT Layer 2
	eth.SrcMAC = toInterface.If.IfHWAddr

	// Update packet contents
	log.Debug().Msgf("Spitted on %s packet =  (%v)", toInterface.If.IfName, pkt)

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
	// log.Info().Msgf("Redo NAT for %s - %v %v", toInterface.If.IfName, natkey, forwardEntry)

	return
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

func (n *Nat) getEthAddr(ip net.IP, ifset *IfSet) (net.HardwareAddr, error) {

	mac, ok := n.arpNotify.GetArpEntry(ip)
	if !ok {
		log.Warn().Msgf("failed to find gateway ARP entry for %s. Waiting", ip)
		if err := n.doArp(ip, ifset.If.IfHWAddr, ifset.If.IPv4Addr); err != nil {
			return nil, err
		}

		// Wait for either the ARP response, or a timeout.
		mac, ok := n.arpNotify.WaitForArp(ip)
		if !ok {
			return nil, fmt.Errorf("ARP entry not there, even after waiting. Bad news ")
		}
		log.Info().Msgf("Got ARP entry for %s - %s after waiting", ip, mac)
		return mac, nil
	}

	return mac, nil
}

func (n *Nat) updateArpTable(mac net.HardwareAddr, ip net.IP) {

	// If mac is not 0:0:0:0:0:0, then update ARP table.
	if !bytes.Equal(mac, []byte{0, 0, 0, 0, 0, 0}) {
		n.arpNotify.AddArpEntry(ip, mac)
	}
}
func (n *Nat) doArp(dst net.IP, srcMac net.HardwareAddr, srcip net.IP) (err error) {
	log.Info().Msgf("Doing an ARP request for %s from %s:%s", dst, srcMac, srcip)
	// Send ARP request
	eth := &layers.Ethernet{
		SrcMAC:       srcMac,
		DstMAC:       net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType: layers.LinkTypeEthernet,
		Protocol: layers.EthernetTypeIPv4,

		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         1, // ARP Request,
		SourceHwAddress:   srcMac,
		DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		SourceProtAddress: srcip.To4(),
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
	err = n.defaultGateway.Callback.Send(pkt)
	if err != nil {
		return
	}
	return
}
