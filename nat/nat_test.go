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
	h1w, _      = net.ParseMAC("00:15:5d:67:be:9a")
	h2w, _      = net.ParseMAC("00:15:5d:67:be:9b")
	h3w, _      = net.ParseMAC("00:15:5d:67:be:9c")
	lan1gateway = net.ParseIP("10.0.0.1")
	lan2gateway = net.ParseIP("192.168.1.1")
	client1IP   = net.ParseIP("10.0.0.2")
	client2IP   = net.ParseIP("192.168.1.2")
	googleIP    = net.ParseIP("8.8.8.8")
	wangw       = net.ParseIP("172.31.45.1")
	wanclient   = net.ParseIP("172.20.112.88")
	rawBytes    = []byte{0, 1, 2, 3, 4}
)

type testCallback struct {
	ifno               int
	globalPacketHolder *[3]gopacket.Packet
	lock               sync.RWMutex
	globalTestHolder   *testing.T
}

func (n *testCallback) Send(pkt *Packet) (err error) {
	n.lock.Lock()
	defer n.lock.Unlock()
	require.Nil(n.globalTestHolder, n.globalPacketHolder[n.ifno])
	n.globalPacketHolder[n.ifno] = pkt
	return
}
func (n *testCallback) SendBytes(buf []byte) (err error) {
	n.lock.Lock()
	defer n.lock.Unlock()
	require.Nil(n.globalTestHolder, n.globalPacketHolder[n.ifno])
	pkt := gopacket.NewPacket(buf, layers.LayerTypeEthernet, gopacket.Default)
	n.globalPacketHolder[n.ifno] = pkt
	return
}

func TestNAT(t *testing.T) {
	globalPacketHolder := &[3]gopacket.Packet{}
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr}).Level(zerolog.DebugLevel)
	pkt := CreatePacketIPTCP(t, client1IP, googleIP, 2222, 443, common.TCPFlags{SYN: true})
	ipv4, _ := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	eth := pkt.LinkLayer().(*layers.Ethernet)

	fromInterface := Interface{
		IfName:      "veth1",
		IfHWAddr:    h1w,
		IPv4Addr:    lan1gateway,
		IPv4Netmask: net.CIDRMask(8, 32),
		IPv4Network: net.IPNet{IP: lan1gateway, Mask: net.CIDRMask(8, 32)},
		// IPv4Gateway: lan1gateway, // not used in this ipset
		NatEnabled: true,
		Callback:   &testCallback{ifno: 0, globalPacketHolder: globalPacketHolder, globalTestHolder: t},
	}
	gwSet := Interface{
		IfName:      "eth0",
		IfHWAddr:    h2w,
		IPv4Addr:    wanclient,
		IPv4Netmask: net.CIDRMask(12, 32),
		IPv4Network: net.IPNet{IP: wanclient, Mask: net.CIDRMask(12, 32)},
		IPv4Gateway: wangw,
		NatEnabled:  false,

		Callback: &testCallback{ifno: 1, globalPacketHolder: globalPacketHolder, globalTestHolder: t},
	}
	fromInterfaceAlternative := Interface{
		IfName:      "eth2",
		IfHWAddr:    h3w,
		IPv4Addr:    lan2gateway,
		IPv4Netmask: net.CIDRMask(8, 32),
		IPv4Network: net.IPNet{IP: lan2gateway, Mask: net.CIDRMask(8, 32)},
		// IPv4Gateway: lan2gateway, // not used in this ipset
		NatEnabled: true,
		Callback:   &testCallback{ifno: 2, globalPacketHolder: globalPacketHolder, globalTestHolder: t},
	}

	n := CreateNat(gwSet, []Interface{fromInterface, fromInterfaceAlternative}, []PFRule{})
	t.Logf("yay %v", n)

	t.Log("############### TEST 1. Testing ARP #################")
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		pkt.FromInterface = &fromInterface
		pkt.Ip4 = ipv4
		err := n.natPacket(&pkt, eth)
		require.Nil(t, err)
		require.NotNil(t, globalPacketHolder[1])
		require.Nil(t, globalPacketHolder[0])
	}()
	// After 100ms, should be holding for arp. No packet recieved.
	time.Sleep(100 * time.Millisecond)
	require.NotNil(t, globalPacketHolder[1]) // Should be the ARP request
	require.Equal(t, uint16(layers.ARPRequest), globalPacketHolder[1].Layer(layers.LayerTypeARP).(*layers.ARP).Operation)
	globalPacketHolder[1] = nil
	require.Nil(t, globalPacketHolder[0])
	t.Logf("Adding arp entry for %s", wangw)
	n.arpNotify.AddArpEntry(wangw, h1w, "eth0")
	wg.Wait()

	t.Log("############### TEST 2. Testing standard TCP three way handshake #################")
	n.table.DeleteAll()
	testThreeWayHandShakeWithPort(t, n, uint16(2000), uint16(2000), globalPacketHolder)

	t.Log("############### TEST 3 - PING #################")
	pkt = CreateICMPPacketTest(t, client1IP, googleIP, layers.ICMPv4TypeEchoRequest, 0)
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	n.AcceptPkt(pkt, "veth1")
	require.Nil(t, globalPacketHolder[0])
	require.NotNil(t, globalPacketHolder[1])
	srcipout, dstipout := decodeIPPacket(t, globalPacketHolder[1])

	require.Equal(t, srcipout.To4(), wanclient.To4())
	require.Equal(t, dstipout.To4(), googleIP.To4())

	// Create the reverse packet
	t.Log("############### TEST 3. PING return #################", globalPacketHolder)
	pkt = CreateICMPPacketTest(t, googleIP, wanclient, layers.ICMPv4TypeEchoReply, 1)
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	n.AcceptPkt(pkt, "eth0")
	require.NotNil(t, globalPacketHolder[0])
	require.Nil(t, globalPacketHolder[1])

	srcipout, dstipout = decodeIPPacket(t, globalPacketHolder[0])

	require.Equal(t, srcipout.To4(), googleIP.To4())
	require.Equal(t, dstipout.To4(), client1IP.To4())

	t.Log("############### TEST 4. Port forwarding. Drop packet with no rule #################")
	n.table.DeleteAll()
	pkt = CreatePacketIPTCP(t, googleIP, wanclient, 4444, 5555, common.TCPFlags{SYN: true})
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	n.AcceptPkt(pkt, "eth0")
	require.Nil(t, globalPacketHolder[0])
	require.Nil(t, globalPacketHolder[1])

	t.Log("############### TEST 4. Port forwarding. Forward the packet. SYN #################")
	n.table.DeleteAll()
	n.portForwardingTable[PortForwardingKey{ExternalPort: 5555, Protocol: layers.IPProtocolTCP}] = PortForwardingEntry{InternalIP: client1IP, InternalPort: 4444}
	pkt = CreatePacketIPTCP(t, googleIP, wanclient, 3333, 5555, common.TCPFlags{SYN: true})
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
	// After 100ms, should be holding for arp. No packet recieved.
	time.Sleep(100 * time.Millisecond)

	require.NotNil(t, globalPacketHolder[0]) // Should be the ARP request
	require.Equal(t, uint16(layers.ARPRequest), globalPacketHolder[0].Layer(layers.LayerTypeARP).(*layers.ARP).Operation)
	globalPacketHolder[0] = nil
	t.Logf("Adding arp entry for %s", wangw)
	n.arpNotify.AddArpEntry(client1IP, h2w, "veth1")
	wg.Wait()

	srcipout, dstipout, srcportout, dstportout := decodeTCPPacket(t, globalPacketHolder[0])

	require.Equal(t, srcipout.To4(), googleIP.To4())
	require.Equal(t, dstipout.To4(), client1IP.To4())
	// require.Equal(t, srcportout, uint16(3333)) - src port is dynamic
	require.Equal(t, dstportout, uint16(4444))
	t.Log("############### TEST 4. Port forwarding. SYN-ACK #################")

	pkt = CreatePacketIPTCP(t, client1IP.To4(), googleIP, 4444, srcportout, common.TCPFlags{SYN: true, ACK: true})
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	n.AcceptPkt(pkt, "veth1")
	require.NotNil(t, globalPacketHolder[1])
	require.Nil(t, globalPacketHolder[0])

	srcipout, dstipout, srcportout, dstportout = decodeTCPPacket(t, globalPacketHolder[1])

	require.Equal(t, srcipout.To4(), wanclient.To4())
	require.Equal(t, dstipout.To4(), googleIP.To4())
	require.Equal(t, srcportout, uint16(5555))
	require.Equal(t, dstportout, uint16(3333))

	t.Log("############### TEST 4. Packet ACK #################")
	pkt = CreatePacketIPTCP(t, googleIP, wanclient, 3333, 5555, common.TCPFlags{SYN: true, ACK: true})
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	n.AcceptPkt(pkt, "eth0")
	require.NotNil(t, globalPacketHolder[0])
	require.Nil(t, globalPacketHolder[1])

	srcipout, dstipout, _, dstportout = decodeTCPPacket(t, globalPacketHolder[0])

	require.Equal(t, srcipout.To4(), googleIP.To4())
	require.Equal(t, dstipout.To4(), client1IP.To4())
	// require.Equal(t, srcportout, uint16(3333)) - src port is dynamic
	require.Equal(t, dstportout, uint16(4444))

	t.Log("############### TEST 5. Testing standard three way handshake with an allocated port. #################")
	n.table.DeleteAll()
	n.table.table[NatKey{
		SrcPort:  443,
		DstPort:  2000,
		SrcIP:    googleIP.String(),
		DstIP:    wanclient.String(),
		Protocol: layers.IPProtocolTCP,
	}] = &NatEntry{
		LastSeen:   time.Now(),
		SrcPort:    1,
		DstPort:    1,
		SrcIP:      wanclient,
		DstIP:      wanclient,
		Inf:        &fromInterface,
		DstMac:     h2w,
		ReverseKey: &NatKey{},
		TcpState:   TCPCloseState{},
	}
	testThreeWayHandShakeWithPort(t, n, uint16(2000), uint16(2002), globalPacketHolder)
	t.Log("############### TEST 6. Testing standard three way handshake with an allocated port, in the 1024 boundy. #################")
	n.table.DeleteAll()
	n.table.table[NatKey{
		SrcPort:  443,
		DstPort:  1023,
		SrcIP:    googleIP.String(),
		DstIP:    wanclient.String(),
		Protocol: layers.IPProtocolTCP,
	}] = &NatEntry{
		LastSeen:   time.Now(),
		SrcPort:    1,
		DstPort:    1,
		SrcIP:      wanclient,
		DstIP:      wanclient,
		Inf:        &fromInterface,
		DstMac:     h2w,
		ReverseKey: &NatKey{},
		TcpState:   TCPCloseState{},
	}
	testThreeWayHandShakeWithPort(t, n, uint16(1023), uint16(7), globalPacketHolder)
	t.Log("############### TEST 7. Testing standard three way handshake with an allocated port, in the 65535 boundy. #################")
	n.table.DeleteAll()
	n.table.table[NatKey{
		SrcPort:  443,
		DstPort:  65535,
		SrcIP:    googleIP.String(),
		DstIP:    wanclient.String(),
		Protocol: layers.IPProtocolTCP,
	}] = &NatEntry{
		LastSeen:   time.Now(),
		SrcPort:    1,
		DstPort:    1,
		SrcIP:      wanclient,
		DstIP:      wanclient,
		Inf:        &fromInterface,
		DstMac:     h2w,
		ReverseKey: &NatKey{},
		TcpState:   TCPCloseState{},
	}
	testThreeWayHandShakeWithPort(t, n, uint16(65535), uint16(1027), globalPacketHolder)
	t.Log("############### TEST 8. Hairpin TCP. Same interface #################")
	n.table.DeleteAll()
	n.portForwardingTable[PortForwardingKey{ExternalPort: 5555, Protocol: layers.IPProtocolTCP}] = PortForwardingEntry{InternalIP: client1IP, InternalPort: 4444}

	pkt = CreatePacketIPTCP(t, client1IP, wanclient, 2223, 5555, common.TCPFlags{SYN: true})
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	globalPacketHolder[2] = nil

	n.AcceptPkt(pkt, "veth1")
	require.NotNil(t, globalPacketHolder[0])
	require.Nil(t, globalPacketHolder[1])
	require.Nil(t, globalPacketHolder[2])

	srcipout, dstipout, srcportout, dstportout = decodeTCPPacket(t, globalPacketHolder[0])

	require.Equal(t, srcipout.To4(), wanclient.To4())
	require.Equal(t, dstipout.To4(), client1IP.To4())
	require.Equal(t, srcportout, uint16(2223))
	require.Equal(t, dstportout, uint16(4444))
	t.Log("############### TEST 8. Hairpin TCP. Other LAN interface. SYN #################")
	n.table.DeleteAll()
	n.portForwardingTable[PortForwardingKey{ExternalPort: 5555, Protocol: layers.IPProtocolTCP}] = PortForwardingEntry{InternalIP: client1IP, InternalPort: 4444}

	pkt = CreatePacketIPTCP(t, client2IP, wanclient, 2223, 5555, common.TCPFlags{SYN: true})
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	globalPacketHolder[2] = nil

	n.AcceptPkt(pkt, "eth2")
	require.NotNil(t, globalPacketHolder[0])
	require.Nil(t, globalPacketHolder[1])
	require.Nil(t, globalPacketHolder[2])

	srcipout, dstipout, srcportout, dstportout = decodeTCPPacket(t, globalPacketHolder[0])

	require.Equal(t, srcipout.To4(), wanclient.To4())
	require.Equal(t, dstipout.To4(), client1IP.To4())
	require.Equal(t, srcportout, uint16(2223))
	require.Equal(t, dstportout, uint16(4444))
	t.Log("############### TEST 8. Hairpin TCP. Other LAN interface. SYN-ACK #################")
	pkt = CreatePacketIPTCP(t, client1IP, wanclient, 4444, 2223, common.TCPFlags{SYN: true, ACK: true})
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	globalPacketHolder[2] = nil

	n.AcceptPkt(pkt, "veth1")
	require.Nil(t, globalPacketHolder[0])
	require.Nil(t, globalPacketHolder[1])
	require.NotNil(t, globalPacketHolder[2])

	srcipout, dstipout, srcportout, dstportout = decodeTCPPacket(t, globalPacketHolder[2])

	require.Equal(t, srcipout.To4(), wanclient.To4())
	require.Equal(t, dstipout.To4(), client2IP.To4())
	require.Equal(t, srcportout, uint16(5555))
	require.Equal(t, dstportout, uint16(2223))

}

func testThreeWayHandShakeWithPort(t *testing.T, n *Nat, srcport, expectedSrcPort uint16, globalPacketHolder *[3]gopacket.Packet) {
	t.Log("############### SYN #################")
	pkt := CreatePacketIPTCP(t, client1IP, googleIP, srcport, 443, common.TCPFlags{SYN: true})
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	n.AcceptPkt(pkt, "veth1")
	require.NotNil(t, globalPacketHolder[1])
	require.Nil(t, globalPacketHolder[0])

	srcipout, dstipout, srcportout, dstportout := decodeTCPPacket(t, globalPacketHolder[1])

	require.Equal(t, srcipout.To4(), wanclient.To4())
	require.Equal(t, dstipout.To4(), googleIP.To4())
	require.Equal(t, srcportout, uint16(expectedSrcPort))
	require.Equal(t, dstportout, uint16(443))

	// Create the reverse packet
	t.Log("############### Packet return  SYN-ACK #################")
	pkt = CreatePacketIPTCP(t, googleIP, wanclient, 443, srcportout, common.TCPFlags{SYN: true, ACK: true})
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	n.AcceptPkt(pkt, "eth0")
	require.NotNil(t, globalPacketHolder[0])
	require.Nil(t, globalPacketHolder[1])

	srcipout, dstipout, srcportout, dstportout = decodeTCPPacket(t, globalPacketHolder[0])

	require.Equal(t, srcipout.To4(), googleIP.To4())
	require.Equal(t, dstipout.To4(), client1IP.To4())
	require.Equal(t, srcportout, uint16(443))
	require.Equal(t, dstportout, uint16(srcport))

	t.Log("############### Packet ACK #################")
	pkt = CreatePacketIPTCP(t, client1IP, googleIP, srcport, 443, common.TCPFlags{ACK: true})
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	n.AcceptPkt(pkt, "veth1")
	require.NotNil(t, globalPacketHolder[1])
	require.Nil(t, globalPacketHolder[0])

	srcipout, dstipout, srcportout, dstportout = decodeTCPPacket(t, globalPacketHolder[1])

	require.Equal(t, srcipout.To4(), wanclient.To4())
	require.Equal(t, dstipout.To4(), googleIP.To4())
	require.Equal(t, srcportout, uint16(expectedSrcPort)) //(t, srcportout, uint16(2000))
	require.Equal(t, dstportout, uint16(443))
	t.Log("############### Packet return  FIN #################")
	pkt = CreatePacketIPTCP(t, googleIP, wanclient, 443, srcportout, common.TCPFlags{FIN: true})
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	n.AcceptPkt(pkt, "eth0")
	require.NotNil(t, globalPacketHolder[0])
	require.Nil(t, globalPacketHolder[1])

	srcipout, dstipout, srcportout, dstportout = decodeTCPPacket(t, globalPacketHolder[0])

	require.Equal(t, srcipout.To4(), googleIP.To4())
	require.Equal(t, dstipout.To4(), client1IP.To4())
	require.Equal(t, srcportout, uint16(443))
	require.Equal(t, dstportout, uint16(srcport))
}

func decodeTCPPacket(t *testing.T, pkt gopacket.Packet) (src, dst net.IP, srcport, dstport uint16) {
	ipv4 := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcp := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	return ipv4.SrcIP, ipv4.DstIP, uint16(tcp.SrcPort), uint16(tcp.DstPort)
}
func decodeIPPacket(t *testing.T, pkt gopacket.Packet) (src, dst net.IP) {
	ipv4 := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	return ipv4.SrcIP, ipv4.DstIP
}

//////////////////// TEST PACKET CREATION

func CreatePacketIPTCP(t require.TestingT, src, dst net.IP, srcport, dstport uint16, flgas common.TCPFlags) (packet Packet) {

	ethernetLayer := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x0F, 0xAA, 0xFA, 0xAA, 0x00},
		DstMAC:       net.HardwareAddr{0x00, 0x0D, 0xBD, 0xBD, 0x00, 0xBD},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipLayer := &layers.IPv4{
		SrcIP:      src,
		DstIP:      dst,
		Version:    4,
		TOS:        0,
		Id:         0,
		Flags:      0,
		FragOffset: 0,
		TTL:        64,
		Protocol:   layers.IPProtocolTCP,
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

func CreateICMPPacketTest(t require.TestingT, src, dst net.IP, icmpType, icmpCode uint8) (packet Packet) {
	buffer, err := common.CreateICMPPacket(net.HardwareAddr{0x00, 0x0F, 0xAA, 0xFA, 0xAA, 0x00}, net.HardwareAddr{0x00, 0x0D, 0xBD, 0xBD, 0x00, 0xBD}, src, dst, icmpType, icmpCode)

	require.Nil(t, err)
	pkt := gopacket.NewPacket(buffer, layers.LayerTypeEthernet, gopacket.Default)
	return Packet{Packet: pkt}
}

func CreatePacket(t require.TestingT) (packet Packet) {
	return CreatePacketIPTCP(t, googleIP, googleIP, 2222, 2222, common.TCPFlags{})
}
func CreatePacketTCP(t require.TestingT, srcport, dstport uint16) (packet Packet) {
	return CreatePacketIPTCP(t, googleIP, googleIP, srcport, dstport, common.TCPFlags{})
}
func CreatePacketIP(t require.TestingT, src, dst net.IP) (packet Packet) {
	return CreatePacketIPTCP(t, src, dst, 2222, 2222, common.TCPFlags{})
}
