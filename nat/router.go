/*
Package nat implements a simple NAPT (Network Address Port Translation)

*/
package nat

import (
	"errors"
	"fmt"
	"gonat/common"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"

	"github.com/rs/zerolog/log"
)

// Constants used in the package
var (
	_, ZeroSlashZero, _     = net.ParseCIDR("0.0.0.0/0")
	_, MultiCast, _         = net.ParseCIDR("224.0.0.0/4")
	BroadCast               = net.ParseIP("255.255.255.255")
	ZeroAddress             = net.ParseIP("0.0.0.0")
	ErrICMPFailure          = errors.New("icmp failure")
	ErrARPFailure           = errors.New("arp failure")
	ErrNATFailure           = errors.New("nat failure")
	zeroHWAddr              = []byte{0, 0, 0, 0, 0, 0}
	PktSerialisationOptions = gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
)

// Nat stores the state of the NAT
type Nat struct {
	// Main NAT table. Mapping of tuples, to output tuples
	table Nattable
	// Router Interfaces
	interfaces map[string]Interface
	// Internal routes. Minor optimisation to store the routes here, when I am routing internally.
	internalRoutes []net.IPNet
	// Only one default gateway currently
	defaultGateway Interface
	// ARP handler/cache
	arpNotify ARPNotify
	// ipv4 defragmentation handler
	ip4defrager *ip4defrag.IPv4Defragmenter
	// port forwarding table. All good NATs have port forwarding
	portForwardingTable map[PortForwardingKey]PortForwardingEntry
}

// CreateNat - Create the nat, given a default gateway, list of LAN devices and list of port forwarding rules
func CreateNat(defaultGateway Interface, lans []Interface, pfs []PFRule) (n *Nat) {
	n = &Nat{
		defaultGateway:      defaultGateway,
		ip4defrager:         ip4defrag.NewIPv4Defragmenter(),
		interfaces:          make(map[string]Interface),
		internalRoutes:      make([]net.IPNet, len(lans)),
		table:               Nattable{table: make(map[NatKey]*NatEntry), lock: sync.RWMutex{}},
		arpNotify:           ARPNotify{},
		portForwardingTable: make(map[PortForwardingKey]PortForwardingEntry),
	}
	for _, pf := range pfs {
		rangePorts := pf.ExternalPortEnd - pf.ExternalPortStart
		protocol, _ := common.String2IPProto(pf.Protocol)
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

// AcceptPkt decides what to do with a packet.
func (n *Nat) AcceptPkt(pkt Packet, ifName string) {

	// I _think_ this is safe, and gopacket will throw an error before even getting here, TODO - test
	ethTmp := pkt.LinkLayer().(*layers.Ethernet)
	pkt.Eth = ethTmp

	// Get a reference to the interface we recieved this pkt on. Store it with the packet
	fromInterfacetmp, ok := n.interfaces[ifName]
	if !ok {
		log.Fatal().Msgf("Could not find interface %s.", ifName)
		return
	}
	pkt.FromInterface = &fromInterfacetmp
	if pkt.Eth.EthernetType == layers.EthernetTypeIPv4 {
		n.AcceptPkt4(&pkt)
		return
	} else if pkt.Eth.EthernetType == layers.EthernetTypeIPv6 {
		n.AcceptPkt6(&pkt)
		return

	} else if pkt.Eth.EthernetType == layers.EthernetTypeARP {
		arp, _ := pkt.Layer(layers.LayerTypeARP).(*layers.ARP)
		log.Debug().Msgf("Arg message receieved-  %+v", arp)

		if pkt.FromInterface.IPv4Addr.Equal(arp.DstProtAddress) && arp.Operation == 1 { // 1 is ARPRequest
			if err := sendARPResponse(arp, &pkt); err != nil {
				log.Error().Err(err).Msgf("failed to send packet %s", err)
			}
			return

		} else {
			// Else, some other ARP message. Lets just update the ARP table from the messages regardless of who its for. No possible poising issue here. updateArpTable checks for zero byte macs
			log.Debug().Msgf("ARP message seen. Updating table. %v:%v, %v:%v", arp.SourceHwAddress, arp.SourceProtAddress, arp.DstHwAddress, arp.DstProtAddress)
			n.arpNotify.AddArpEntry(arp.SourceProtAddress, arp.SourceHwAddress, pkt.FromInterface.IfName)
			n.arpNotify.AddArpEntry(arp.DstProtAddress, arp.DstHwAddress, pkt.FromInterface.IfName)

		}
	} else {
		log.Info().Msgf("Some other pkt type - %d. Currently unsupported - %s", pkt.Eth.EthernetType, pkt)
	}
}

// routeInternally - routes a packet to another LAN interface
func (n *Nat) routeInternally(pkt *Packet) (err error) {
	dstIP := pkt.DstIP()
	arpEntry, err := n.getEthAddr(dstIP)
	if err != nil {
		log.Error().Err(err).Msgf("Failed to get eth addr for %s", dstIP)
		return
	}
	pkt.Eth.DstMAC = arpEntry.Mac
	toInterface, ok := n.interfaces[arpEntry.IntName]
	if !ok {
		log.Error().Msgf("Interface %s not found", arpEntry.IntName)
		return
	}
	pkt.Eth.SrcMAC = toInterface.IfHWAddr

	return toInterface.Callback.Send(pkt)

}

// natPacket - handles a packet that is destined for a NAT entry
// The NAT code is kept seperate here, so conversion to ipv6+ipv4 can be neater. I'll need to make a new interface to gopacket.Packet first.
func (n *Nat) natPacket(pkt *Packet, eth *layers.Ethernet) (err error) {
	var toInterface *Interface
	// Update internal layer4 state of packet
	pkt.SetLayer4()
	srcport, dstport := pkt.Ports()
	originalSourceIP, originalDstIp := pkt.IPs()
	protocol := pkt.Protocol()

	log.Debug().Msgf("Input packet - %s==(%s:%d->%s:%d)", pkt.FromInterface.IfName, originalSourceIP, srcport, originalDstIp, dstport)
	// Unique Tuple for this packet
	natkey := NatKey{SrcPort: srcport, DstPort: dstport, SrcIP: originalSourceIP.String(), DstIP: originalDstIp.String(), Protocol: protocol}
	// Decide if we should nat the packet. First check if we have a NAT entry for this tuple already - in which case just send it out acording to the entry
	forwardEntry := n.table.Get(natkey)

	if forwardEntry != nil {
		log.Debug().Msgf("Already NAT'e'd %s. Using old entry %v", natkey, forwardEntry)

		pkt.SetIPs(forwardEntry.SrcIP, forwardEntry.DstIP)
		toInterface = forwardEntry.Inf
		eth.DstMAC = forwardEntry.DstMac
		pkt.SetPorts(forwardEntry.SrcPort, forwardEntry.DstPort)
	} else {
		// Not natted previously - find a new NAT if
		// 1. we're on a NAT enabled port, or
		// 2. the dst port is in the port forward table.

		// If its addresssed to me (non WAN interface), then its probably DNS.
		if dstport == 53 && pkt.FromInterface.NatEnabled && originalDstIp.Equal(pkt.FromInterface.IPv4Addr) {
			// DNS - TODO
			log.Warn().Msgf("Recieved DNS packet addressed to me on %s. Not currently supported.", pkt.FromInterface.IfName)
		}

		originalSrcPort := srcport
		originalDstPort := dstport
		originalDstIp := pkt.DstIP()
		var expectedDstIP net.IP
		if !pkt.FromInterface.NatEnabled || n.defaultGateway.IPv4Addr.Equal(originalDstIp) {

			// Hairpin
			if pkt.FromInterface.NatEnabled && n.defaultGateway.IPv4Addr.Equal(originalDstIp) {
				pkt.SetIPs(n.defaultGateway.IPv4Addr, originalDstIp)
			}

			// Unseen packet on the non nat interface.
			// Check if the packet is in the port forward table
			pfkey := PortForwardingKey{ExternalPort: dstport, Protocol: protocol}
			entry, ok := n.portForwardingTable[pfkey]
			if !ok {
				str := common.LogSimpleNDPI(pkt, pkt.SrcIP(), originalDstIp, srcport, dstport, protocol)
				log.Debug().Msgf("Dropping pkt %s. Not in forwarding table", str)
				return
			}
			log.Info().Msgf("New packet matches port forwarding rule: %+v  ---- %+v", pfkey, entry)
			pkt.SetIPs(pkt.SrcIP(), entry.InternalIP)
			tmp, errTmp := n.getEthAddr(entry.InternalIP)
			if errTmp != nil {
				log.Error().Err(err).Msgf("Failed to get MAC address for %s", entry.InternalIP)
				return
			}
			toInterfaceTmp := n.interfaces[tmp.IntName]
			toInterface = &toInterfaceTmp
			eth.DstMAC = tmp.Mac
			expectedDstIP = pkt.SrcIP()
			dstport = entry.InternalPort

			pkt.SetDstPort(entry.InternalPort)

		} else {
			pkt.SetIPs(n.defaultGateway.IPv4Addr, originalDstIp)
			toInterface = &n.defaultGateway
			expectedDstIP = toInterface.IPv4Addr
			tmp, errTmp := n.getEthAddr(toInterface.IPv4Gateway)
			if errTmp != nil {
				log.Error().Err(errTmp).Msgf("Failed to get MAC address for gateway %s ", toInterface.IPv4Gateway)
				return
			}
			eth.DstMAC = tmp.Mac

		}

		// New NAT
		// Create reverse entry key. If its TCP or UDP, find a source port that matches the RFC
		// holds a reference to a key of the forward direction.
		reverseEntry := &NatEntry{SrcPort: originalDstPort, DstPort: originalSrcPort, SrcIP: originalDstIp, Inf: pkt.FromInterface, DstIP: originalSourceIP, DstMac: eth.SrcMAC, ReverseKey: &natkey}
		tmpDstIP := pkt.DstIP()
		reverseKey := n.chooseSrcPort(dstport, srcport, &tmpDstIP, &expectedDstIP, &protocol, reverseEntry, 0)

		srcport = reverseKey.DstPort
		pkt.SetSrcPort(srcport)
		// Create new forward entries. hold a reference to a key of the reverse direction.
		forwardEntry = &NatEntry{SrcPort: srcport, SrcIP: pkt.SrcIP(), Inf: toInterface, DstPort: dstport, DstIP: pkt.DstIP(), DstMac: eth.DstMAC, ReverseKey: reverseKey}
		log.Debug().Msgf("New NAT (forward) for %s - %s", pkt.FromInterface.IfName, natkey)

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
	if pkt.Tcp != nil {
		n.trackTCPSimple(forwardEntry, pkt.Tcp)
	}
	// Update NAT table for sent packet - so next packet can use the same tuple.
	n.table.Store(natkey, forwardEntry)

	return
}

// chooseSrcPort. Tries to pick a source port to use. Try the actual source port first (called 'port preservation' in the RFC).
// If that fails, pick a port in the same range (0-1023 or 1024-65535 - rfc4787 REQ3), and keep parity (rfc4787 REQ4)
func (n *Nat) chooseSrcPort(p1, selectPort uint16, i1, i2 *net.IP, prot *layers.IPProtocol, entry *NatEntry, recursionCount int) (tryKey *NatKey) {

	tryKey = &NatKey{SrcPort: p1, DstPort: selectPort, SrcIP: i1.String(), DstIP: i2.String(), Protocol: *prot}
	n.table.lock.Lock()

	_, ok := n.table.table[*tryKey]
	// Entry not in table, safe to create then return
	if !ok {
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
		n.table.lock.Unlock()
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
			// log.Debug().Msgf("Checking %+v for %s. Waiting", intVal.IPv4Network, ip)
			if intVal.IPv4Network.Contains(ip) {
				if common.IsIPv4(ip) {
					if err := n.doArp(ip, &intVal); err != nil {
						return EmptyArpEntry, err
					}
				} else {
					if err := n.doNS(ip, &intVal); err != nil {
						return EmptyArpEntry, err
					}
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
