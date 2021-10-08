package nat

import (
	"gonat/common"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

var (
	lan1gateway6     = net.ParseIP("fd00::1")   // 10.0.0.1  	 ---
	lan2gateway6     = net.ParseIP("fd00::2:1") // 192.168.1.1   ---
	client1IP6       = net.ParseIP("fd00::2")   // 10.0.0.2  	 ---
	client2IP6       = net.ParseIP("fd00::2:2") // 192.168.1.2   ---
	googleIP6        = net.ParseIP("2600::")    // 8.8.8.8  	 ---
	wangw6           = net.ParseIP("2001::1")   // 172.31.45.1   ---
	wanclient6       = net.ParseIP("2001::88")  // 172.20.112.88 ---
	lan1gateway6Mask = net.CIDRMask(64, 128)    // net.CIDRMask(8, 32)
	wan6Mask         = net.CIDRMask(64, 128)    // net.CIDRMask(12, 32)
)

func TestNAT6(t *testing.T) {
	globalTestHolder = t
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr}).Level(zerolog.DebugLevel)
	pkt := CreatePacket6IPTCP(t, client1IP6, googleIP6, 2222, 443, common.TCPFlags{SYN: true})
	IPv6, _ := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	eth := pkt.LinkLayer().(*layers.Ethernet)

	fromInterface := Interface{
		IfName:      "veth1",
		IfHWAddr:    h1w,
		IPv4Addr:    lan1gateway6,
		IPv4Netmask: lan1gateway6Mask,
		IPv4Network: net.IPNet{IP: lan1gateway6, Mask: lan1gateway6Mask},
		// IPv6Gateway: lan1gateway6, // not used in this ipset
		NatEnabled: true,
		MTU:        65535,
		Callback:   testCallback{ifno: 0},
	}
	gwSet := Interface{
		IfName:      "eth0",
		IfHWAddr:    h2w,
		IPv4Addr:    wanclient6,
		IPv4Netmask: wan6Mask,
		IPv4Network: net.IPNet{IP: wanclient6, Mask: wan6Mask},
		IPv4Gateway: wangw6,
		NatEnabled:  false,
		MTU:         65535,
		Callback:    testCallback{ifno: 1},
	}
	fromInterfaceAlternative := Interface{
		IfName:      "eth2",
		IfHWAddr:    h3w,
		IPv4Addr:    lan2gateway6,
		IPv4Netmask: lan1gateway6Mask,
		IPv4Network: net.IPNet{IP: lan2gateway6, Mask: lan1gateway6Mask},
		// IPv6Gateway: lan2gateway6, // not used in this ipset
		NatEnabled: true,
		Callback:   testCallback{ifno: 2},
		MTU:        65535,
	}

	n := CreateNat(gwSet, []Interface{fromInterface, fromInterfaceAlternative}, []PFRule{})
	t.Logf("yay %v", n)
	wg := &sync.WaitGroup{}
	t.Log("############### TEST 1. Testing Neighbour Sol/Adv #################")
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil

	wg.Add(1)
	go func() {
		defer wg.Done()
		pkt.FromInterface = &fromInterface
		pkt.Ip6 = IPv6
		err := n.natPacket(&pkt, eth)
		require.Nil(t, err)
		require.NotNil(t, globalPacketHolder[1])
		require.Nil(t, globalPacketHolder[0])
	}()
	// After 100ms, should be holding for NS Request. No packet recieved.
	time.Sleep(100 * time.Millisecond)
	require.NotNil(t, globalPacketHolder[1]) // Should be the ns request
	require.Equal(t, layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborSolicitation, 0), globalPacketHolder[1].Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6).TypeCode)
	globalPacketHolder[1] = nil
	require.Nil(t, globalPacketHolder[0])
	t.Logf("Adding hw entry for %s", wangw6)
	n.arpNotify.AddArpEntry(wangw6, h1w, "eth0")
	// wg.Wait()

	t.Log("############### TEST 2. Testing standard TCP three way handshake #################")
	n.table.DeleteAll()
	testThreeWayHandShakeWithPort6(t, n, uint16(2000), uint16(2000))

	t.Log("############### TEST 3 - PING #################")
	pkt = CreateICMPPacketTest6(t, client1IP6, googleIP6, layers.ICMPv6TypeEchoRequest, 0)
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	n.AcceptPkt(pkt, "veth1")
	require.Nil(t, globalPacketHolder[0])
	require.NotNil(t, globalPacketHolder[1])
	srcipout, dstipout := decodeIPPacket6(t, globalPacketHolder[1])

	require.Equal(t, srcipout, wanclient6)
	require.Equal(t, dstipout, googleIP6)

	// Create the reverse packet
	t.Log("############### TEST 3. PING return #################")
	pkt = CreateICMPPacketTest6(t, googleIP6, wanclient6, layers.ICMPv6TypeEchoReply, 1)
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	n.AcceptPkt(pkt, "eth0")
	require.NotNil(t, globalPacketHolder[0])
	require.Nil(t, globalPacketHolder[1])

	srcipout, dstipout = decodeIPPacket6(t, globalPacketHolder[0])

	require.Equal(t, srcipout, googleIP6)
	require.Equal(t, dstipout, client1IP6)

	t.Log("############### TEST 4. Port forwarding. Drop packet with no rule #################")
	n.table.DeleteAll()
	pkt = CreatePacket6IPTCP(t, googleIP6, wanclient6, 4444, 5555, common.TCPFlags{SYN: true})
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	n.AcceptPkt(pkt, "eth0")
	require.Nil(t, globalPacketHolder[0])
	require.Nil(t, globalPacketHolder[1])

	t.Log("############### TEST 4. Port forwarding. Forward the packet. SYN #################")
	n.table.DeleteAll()
	n.portForwardingTable[PortForwardingKey{ExternalPort: 5555, Protocol: layers.IPProtocolTCP}] = PortForwardingEntry{InternalIP: client1IP6, InternalPort: 4444}
	pkt = CreatePacket6IPTCP(t, googleIP6, wanclient6, 3333, 5555, common.TCPFlags{SYN: true})
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil

	wg = &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		n.AcceptPkt(pkt, "eth0")
		require.NotNil(t, globalPacketHolder[0])
		require.Nil(t, globalPacketHolder[1])
	}()
	// After 100ms, should be holding for NS. No packet recieved.
	time.Sleep(100 * time.Millisecond)

	require.NotNil(t, globalPacketHolder[0]) // Should be the NS Request
	require.Equal(t, layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborSolicitation, 0), globalPacketHolder[0].Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6).TypeCode)
	globalPacketHolder[0] = nil
	t.Logf("Adding hw entry for %s", wangw6)
	n.arpNotify.AddArpEntry(client1IP6, h2w, "veth1")
	wg.Wait()

	srcipout, dstipout, srcportout, dstportout := decodeTCPPacket6(t, globalPacketHolder[0])

	require.Equal(t, srcipout, googleIP6)
	require.Equal(t, dstipout, client1IP6)
	// require.Equal(t, srcportout, uint16(3333)) - src port is dynamic
	require.Equal(t, dstportout, uint16(4444))
	t.Log("############### TEST 4. Port forwarding. SYN-ACK #################")

	pkt = CreatePacket6IPTCP(t, client1IP6, googleIP6, 4444, srcportout, common.TCPFlags{SYN: true, ACK: true})
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	n.AcceptPkt(pkt, "veth1")
	require.NotNil(t, globalPacketHolder[1])
	require.Nil(t, globalPacketHolder[0])

	srcipout, dstipout, srcportout, dstportout = decodeTCPPacket6(t, globalPacketHolder[1])

	require.Equal(t, srcipout, wanclient6)
	require.Equal(t, dstipout, googleIP6)
	require.Equal(t, srcportout, uint16(5555))
	require.Equal(t, dstportout, uint16(3333))

	t.Log("############### TEST 4. Packet ACK #################")
	pkt = CreatePacket6IPTCP(t, googleIP6, wanclient6, 3333, 5555, common.TCPFlags{SYN: true, ACK: true})
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	n.AcceptPkt(pkt, "eth0")
	require.NotNil(t, globalPacketHolder[0])
	require.Nil(t, globalPacketHolder[1])

	srcipout, dstipout, _, dstportout = decodeTCPPacket6(t, globalPacketHolder[0])

	require.Equal(t, srcipout, googleIP6)
	require.Equal(t, dstipout, client1IP6)
	// require.Equal(t, srcportout, uint16(3333)) - src port is dynamic
	require.Equal(t, dstportout, uint16(4444))

	t.Log("############### TEST 5. Testing standard three way handshake with an allocated port. #################")
	n.table.DeleteAll()
	n.table.table[NatKey{
		SrcPort:  443,
		DstPort:  2000,
		SrcIP:    googleIP6.String(),
		DstIP:    wanclient6.String(),
		Protocol: layers.IPProtocolTCP,
	}] = &NatEntry{
		LastSeen:   time.Now(),
		SrcPort:    1,
		DstPort:    1,
		SrcIP:      wanclient6,
		DstIP:      wanclient6,
		Inf:        &fromInterface,
		DstMac:     h2w,
		ReverseKey: &NatKey{},
		TcpState:   TCPCloseState{},
	}
	testThreeWayHandShakeWithPort6(t, n, uint16(2000), uint16(2002))
	t.Log("############### TEST 6. Testing standard three way handshake with an allocated port, in the 1024 boundy. #################")
	n.table.DeleteAll()
	n.table.table[NatKey{
		SrcPort:  443,
		DstPort:  1023,
		SrcIP:    googleIP6.String(),
		DstIP:    wanclient6.String(),
		Protocol: layers.IPProtocolTCP,
	}] = &NatEntry{
		LastSeen:   time.Now(),
		SrcPort:    1,
		DstPort:    1,
		SrcIP:      wanclient6,
		DstIP:      wanclient6,
		Inf:        &fromInterface,
		DstMac:     h2w,
		ReverseKey: &NatKey{},
		TcpState:   TCPCloseState{},
	}
	testThreeWayHandShakeWithPort6(t, n, uint16(1023), uint16(7))
	t.Log("############### TEST 7. Testing standard three way handshake with an allocated port, in the 65535 boundy. #################")
	n.table.DeleteAll()
	n.table.table[NatKey{
		SrcPort:  443,
		DstPort:  65535,
		SrcIP:    googleIP6.String(),
		DstIP:    wanclient6.String(),
		Protocol: layers.IPProtocolTCP,
	}] = &NatEntry{
		LastSeen:   time.Now(),
		SrcPort:    1,
		DstPort:    1,
		SrcIP:      wanclient6,
		DstIP:      wanclient6,
		Inf:        &fromInterface,
		DstMac:     h2w,
		ReverseKey: &NatKey{},
		TcpState:   TCPCloseState{},
	}
	testThreeWayHandShakeWithPort6(t, n, uint16(65535), uint16(1027))
	t.Log("############### TEST 8. Hairpin TCP. Same interface #################")
	n.table.DeleteAll()
	n.portForwardingTable[PortForwardingKey{ExternalPort: 5555, Protocol: layers.IPProtocolTCP}] = PortForwardingEntry{InternalIP: client1IP6, InternalPort: 4444}

	pkt = CreatePacket6IPTCP(t, client1IP6, wanclient6, 2223, 5555, common.TCPFlags{SYN: true})
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	globalPacketHolder[2] = nil

	n.AcceptPkt(pkt, "veth1")
	require.NotNil(t, globalPacketHolder[0])
	require.Nil(t, globalPacketHolder[1])
	require.Nil(t, globalPacketHolder[2])

	srcipout, dstipout, srcportout, dstportout = decodeTCPPacket6(t, globalPacketHolder[0])

	require.Equal(t, srcipout, wanclient6)
	require.Equal(t, dstipout, client1IP6)
	require.Equal(t, srcportout, uint16(2223))
	require.Equal(t, dstportout, uint16(4444))
	t.Log("############### TEST 8. Hairpin TCP. Other LAN interface. SYN #################")
	n.table.DeleteAll()
	n.portForwardingTable[PortForwardingKey{ExternalPort: 5555, Protocol: layers.IPProtocolTCP}] = PortForwardingEntry{InternalIP: client1IP6, InternalPort: 4444}

	pkt = CreatePacket6IPTCP(t, client2IP6, wanclient6, 2223, 5555, common.TCPFlags{SYN: true})
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	globalPacketHolder[2] = nil

	n.AcceptPkt(pkt, "eth2")
	require.NotNil(t, globalPacketHolder[0])
	require.Nil(t, globalPacketHolder[1])
	require.Nil(t, globalPacketHolder[2])

	srcipout, dstipout, srcportout, dstportout = decodeTCPPacket6(t, globalPacketHolder[0])

	require.Equal(t, srcipout, wanclient6)
	require.Equal(t, dstipout, client1IP6)
	require.Equal(t, srcportout, uint16(2223))
	require.Equal(t, dstportout, uint16(4444))
	t.Log("############### TEST 8. Hairpin TCP. Other LAN interface. SYN-ACK #################")
	pkt = CreatePacket6IPTCP(t, client1IP6, wanclient6, 4444, 2223, common.TCPFlags{SYN: true, ACK: true})
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	globalPacketHolder[2] = nil

	n.AcceptPkt(pkt, "veth1")
	require.Nil(t, globalPacketHolder[0])
	require.Nil(t, globalPacketHolder[1])
	require.NotNil(t, globalPacketHolder[2])

	srcipout, dstipout, srcportout, dstportout = decodeTCPPacket6(t, globalPacketHolder[2])

	require.Equal(t, srcipout, wanclient6)
	require.Equal(t, dstipout, client2IP6)
	require.Equal(t, srcportout, uint16(5555))
	require.Equal(t, dstportout, uint16(2223))

}

func testThreeWayHandShakeWithPort6(t *testing.T, n *Nat, srcport, expectedSrcPort uint16) {
	t.Log("############### SYN #################")
	pkt := CreatePacket6IPTCP(t, client1IP6, googleIP6, srcport, 443, common.TCPFlags{SYN: true})
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	n.AcceptPkt(pkt, "veth1")
	require.NotNil(t, globalPacketHolder[1])
	require.Nil(t, globalPacketHolder[0])

	srcipout, dstipout, srcportout, dstportout := decodeTCPPacket6(t, globalPacketHolder[1])

	require.Equal(t, srcipout, wanclient6)
	require.Equal(t, dstipout, googleIP6)
	require.Equal(t, srcportout, uint16(expectedSrcPort))
	require.Equal(t, dstportout, uint16(443))

	// Create the reverse packet
	t.Log("############### Packet return  SYN-ACK #################")
	pkt = CreatePacket6IPTCP(t, googleIP6, wanclient6, 443, srcportout, common.TCPFlags{SYN: true, ACK: true})
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	n.AcceptPkt(pkt, "eth0")
	require.NotNil(t, globalPacketHolder[0])
	require.Nil(t, globalPacketHolder[1])

	srcipout, dstipout, srcportout, dstportout = decodeTCPPacket6(t, globalPacketHolder[0])

	require.Equal(t, srcipout, googleIP6)
	require.Equal(t, dstipout, client1IP6)
	require.Equal(t, srcportout, uint16(443))
	require.Equal(t, dstportout, uint16(srcport))

	t.Log("############### Packet ACK #################")
	pkt = CreatePacket6IPTCP(t, client1IP6, googleIP6, srcport, 443, common.TCPFlags{ACK: true})
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	n.AcceptPkt(pkt, "veth1")
	require.NotNil(t, globalPacketHolder[1])
	require.Nil(t, globalPacketHolder[0])

	srcipout, dstipout, srcportout, dstportout = decodeTCPPacket6(t, globalPacketHolder[1])

	require.Equal(t, srcipout, wanclient6)
	require.Equal(t, dstipout, googleIP6)
	require.Equal(t, srcportout, uint16(expectedSrcPort)) //(t, srcportout, uint16(2000))
	require.Equal(t, dstportout, uint16(443))
	t.Log("############### Packet return  FIN #################")
	pkt = CreatePacket6IPTCP(t, googleIP6, wanclient6, 443, srcportout, common.TCPFlags{FIN: true})
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	n.AcceptPkt(pkt, "eth0")
	require.NotNil(t, globalPacketHolder[0])
	require.Nil(t, globalPacketHolder[1])

	srcipout, dstipout, srcportout, dstportout = decodeTCPPacket6(t, globalPacketHolder[0])

	require.Equal(t, srcipout, googleIP6)
	require.Equal(t, dstipout, client1IP6)
	require.Equal(t, srcportout, uint16(443))
	require.Equal(t, dstportout, uint16(srcport))
}

func decodeTCPPacket6(t *testing.T, pkt gopacket.Packet) (src, dst net.IP, srcport, dstport uint16) {
	IPv6 := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	tcp := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	return IPv6.SrcIP, IPv6.DstIP, uint16(tcp.SrcPort), uint16(tcp.DstPort)
}
func decodeIPPacket6(t *testing.T, pkt gopacket.Packet) (src, dst net.IP) {
	IPv6 := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	return IPv6.SrcIP, IPv6.DstIP
}

//////////////////// TEST PACKET CREATION

func CreatePacket6IPTCP(t require.TestingT, src, dst net.IP, srcport, dstport uint16, flgas common.TCPFlags) (packet Packet) {

	ethernetLayer := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x0F, 0xAA, 0xFA, 0xAA, 0x00},
		DstMAC:       net.HardwareAddr{0x00, 0x0D, 0xBD, 0xBD, 0x00, 0xBD},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ipLayer := &layers.IPv6{
		SrcIP:      src,
		DstIP:      dst,
		Version:    6,
		HopLimit:   64,
		NextHeader: layers.IPProtocolTCP,
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(srcport),
		DstPort: layers.TCPPort(dstport),
		FIN:     flgas.FIN,
		SYN:     flgas.SYN,
		RST:     flgas.RST,
		PSH:     flgas.PSH,
		ACK:     flgas.ACK,
		URG:     flgas.URG,
		ECE:     flgas.ECE,
		CWR:     flgas.CWR,
		NS:      flgas.NS,
	}
	_ = tcpLayer.SetNetworkLayerForChecksum(ipLayer)
	// And create the packet with the layers
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, common.Options,
		ethernetLayer,
		ipLayer,
		tcpLayer,
		gopacket.Payload(rawBytes),
	)
	require.Nil(t, err)
	pkt := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	return Packet{Packet: pkt}
}

func CreateICMPPacketTest6(t require.TestingT, src, dst net.IP, icmpType, icmpCode uint8) (packet Packet) {
	buffer, err := common.CreateICMP6Packet(net.HardwareAddr{0x00, 0x0F, 0xAA, 0xFA, 0xAA, 0x00}, net.HardwareAddr{0x00, 0x0D, 0xBD, 0xBD, 0x00, 0xBD}, src, dst, icmpType, icmpCode)

	require.Nil(t, err)
	pkt := gopacket.NewPacket(buffer, layers.LayerTypeEthernet, gopacket.Default)
	return Packet{Packet: pkt}
}

func CreatePacket6(t require.TestingT) (packet Packet) {
	return CreatePacket6IPTCP(t, googleIP6, googleIP6, 2222, 2222, common.TCPFlags{})
}
func CreatePacket6TCP(t require.TestingT, srcport, dstport uint16) (packet Packet) {
	return CreatePacket6IPTCP(t, googleIP6, googleIP6, srcport, dstport, common.TCPFlags{})
}
func CreatePacket6IP(t require.TestingT, src, dst net.IP) (packet Packet) {
	return CreatePacket6IPTCP(t, src, dst, 2222, 2222, common.TCPFlags{})
}
