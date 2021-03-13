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
	h1w, _             = net.ParseMAC("00:15:5d:67:be:9a")
	h2w, _             = net.ParseMAC("00:15:5d:67:be:9b")
	h3w, _             = net.ParseMAC("00:15:5d:67:be:9c")
	lan1gateway        = net.ParseIP("10.0.0.1")
	lan2gateway        = net.ParseIP("192.168.1.1")
	client1IP          = net.ParseIP("10.0.0.2")
	client2IP          = net.ParseIP("192.168.1.2")
	googleIP           = net.ParseIP("8.8.8.8")
	wangw              = net.ParseIP("172.31.45.1")
	wanclient          = net.ParseIP("172.20.112.88")
	globalPacketHolder [3]gopacket.Packet
	lock               sync.RWMutex
	globalTestHolder   *testing.T
)

type testCallback struct {
	ifno int
}

func (n testCallback) Send(pkt gopacket.Packet, i int) (err error) {
	lock.Lock()
	defer lock.Unlock()
	require.Nil(globalTestHolder, globalPacketHolder[n.ifno])
	globalPacketHolder[n.ifno] = pkt
	return
}
func (n testCallback) SendBytes(buf []byte) (err error) {
	require.Nil(globalTestHolder, buf)
	return
}

func TestNAT(t *testing.T) {
	globalTestHolder = t
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr}).Level(zerolog.DebugLevel)

	pkt := common.CreatePacketIPTCP(t, client1IP, googleIP, 2222, 443, common.TCPFlags{SYN: true})
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
		Callback:   testCallback{ifno: 0},
	}
	gwSet := Interface{
		IfName:      "eth0",
		IfHWAddr:    h2w,
		IPv4Addr:    wanclient,
		IPv4Netmask: net.CIDRMask(12, 32),
		IPv4Network: net.IPNet{IP: wanclient, Mask: net.CIDRMask(12, 32)},
		IPv4Gateway: wangw,
		NatEnabled:  false,

		Callback: testCallback{ifno: 1},
	}
	fromInterfaceAlternative := Interface{
		IfName:      "eth2",
		IfHWAddr:    h3w,
		IPv4Addr:    lan2gateway,
		IPv4Netmask: net.CIDRMask(8, 32),
		IPv4Network: net.IPNet{IP: lan2gateway, Mask: net.CIDRMask(8, 32)},
		// IPv4Gateway: lan2gateway, // not used in this ipset
		NatEnabled: true,
		Callback:   testCallback{ifno: 2},
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
		err := n.natPacket(pkt, ipv4, eth, &fromInterface, 0)
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
	testThreeWayHandShakeWithPort(t, n, uint16(2000), uint16(2000))

	t.Log("############### TEST 3 - PING #################")
	pkt = common.CreateICMPPacketTest(t, client1IP, googleIP, layers.ICMPv4TypeEchoRequest, 0)
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	n.AcceptPkt(pkt, "veth1")
	require.Nil(t, globalPacketHolder[0])
	require.NotNil(t, globalPacketHolder[1])
	srcipout, dstipout := decodeIPPacket(t, globalPacketHolder[1])

	require.Equal(t, srcipout.To4(), wanclient.To4())
	require.Equal(t, dstipout.To4(), googleIP.To4())

	// Create the reverse packet
	t.Log("############### TEST 3. PING return #################")
	pkt = common.CreateICMPPacketTest(t, googleIP, wanclient, layers.ICMPv4TypeEchoReply, 1)
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
	pkt = common.CreatePacketIPTCP(t, googleIP, wanclient, 4444, 5555, common.TCPFlags{SYN: true})
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	n.AcceptPkt(pkt, "eth0")
	require.Nil(t, globalPacketHolder[0])
	require.Nil(t, globalPacketHolder[1])

	t.Log("############### TEST 4. Port forwarding. Forward the packet. SYN #################")
	n.table.DeleteAll()
	n.portForwardingTable[PortForwardingKey{ExternalPort: 5555, Protocol: layers.IPProtocolTCP}] = PortForwardingEntry{InternalIP: client1IP, InternalPort: 4444}
	pkt = common.CreatePacketIPTCP(t, googleIP, wanclient, 3333, 5555, common.TCPFlags{SYN: true})
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

	pkt = common.CreatePacketIPTCP(t, client1IP.To4(), googleIP, 4444, srcportout, common.TCPFlags{SYN: true, ACK: true})
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
	pkt = common.CreatePacketIPTCP(t, googleIP, wanclient, 3333, 5555, common.TCPFlags{SYN: true, ACK: true})
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
	testThreeWayHandShakeWithPort(t, n, uint16(2000), uint16(2002))
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
	testThreeWayHandShakeWithPort(t, n, uint16(1023), uint16(7))
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
	testThreeWayHandShakeWithPort(t, n, uint16(65535), uint16(1027))
	t.Log("############### TEST 8. Hairpin TCP. Same interface #################")
	n.table.DeleteAll()
	n.portForwardingTable[PortForwardingKey{ExternalPort: 5555, Protocol: layers.IPProtocolTCP}] = PortForwardingEntry{InternalIP: client1IP, InternalPort: 4444}

	pkt = common.CreatePacketIPTCP(t, client1IP, wanclient, 2223, 5555, common.TCPFlags{SYN: true})
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

	pkt = common.CreatePacketIPTCP(t, client2IP, wanclient, 2223, 5555, common.TCPFlags{SYN: true})
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
	pkt = common.CreatePacketIPTCP(t, client1IP, wanclient, 4444, 2223, common.TCPFlags{SYN: true, ACK: true})
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

func testThreeWayHandShakeWithPort(t *testing.T, n *Nat, srcport, expectedSrcPort uint16) {
	t.Log("############### SYN #################")
	pkt := common.CreatePacketIPTCP(t, client1IP, googleIP, srcport, 443, common.TCPFlags{SYN: true})
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
	pkt = common.CreatePacketIPTCP(t, googleIP, wanclient, 443, srcportout, common.TCPFlags{SYN: true, ACK: true})
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
	pkt = common.CreatePacketIPTCP(t, client1IP, googleIP, srcport, 443, common.TCPFlags{ACK: true})
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
	pkt = common.CreatePacketIPTCP(t, googleIP, wanclient, 443, srcportout, common.TCPFlags{FIN: true})
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
