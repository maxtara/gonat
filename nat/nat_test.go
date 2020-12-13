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
	hw, _              = net.ParseMAC("00:15:5d:67:be:9c")
	h2w, _             = net.ParseMAC("00:15:5d:67:be:9d")
	iptest             = net.ParseIP("10.0.0.1")
	ip2                = net.ParseIP("10.0.0.2")
	ipgw               = net.ParseIP("172.31.45.1")
	ip1                = net.ParseIP("172.20.112.88")
	globalPacketHolder [2]gopacket.Packet
	lock               sync.RWMutex
	globalTestHolder   *testing.T
	testChat           = make(chan string)
)

type nattest struct {
	ifno int
}

func (n nattest) Send(pkt gopacket.Packet) (err error) {
	lock.Lock()
	defer lock.Unlock()
	require.Nil(globalTestHolder, globalPacketHolder[n.ifno])
	globalPacketHolder[n.ifno] = pkt
	return
}
func (n nattest) SendBytes(buf []byte) (err error) {
	require.Nil(globalTestHolder, buf)
	return
}

func TestSimple(t *testing.T) {
	globalTestHolder = t
	close(testChat)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr}).Level(zerolog.DebugLevel)

	pkt := common.CreatePacketIPTCP(t, ip2, net.IPv4(8, 8, 8, 8), 2222, 443, common.TCPFlags{SYN: true})
	ipv4, _ := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	eth := pkt.LinkLayer().(*layers.Ethernet)

	fromInterface := Interface{
		IfName:      "veth1",
		IfHWAddr:    hw,
		IPv4Addr:    iptest,
		IPv4Netmask: net.CIDRMask(8, 32),
		IPv4Network: net.IPNet{IP: iptest, Mask: net.CIDRMask(8, 32)},
		IPv4Gateway: iptest, // not used in this ipset
		NatEnabled:  true,
		Callback:    nattest{ifno: 0},
	}
	gwSet := Interface{
		IfName:      "eth0",
		IfHWAddr:    hw,
		IPv4Addr:    ip1,
		IPv4Netmask: net.CIDRMask(12, 32),
		IPv4Network: net.IPNet{IP: ip1, Mask: net.CIDRMask(12, 32)},
		IPv4Gateway: ipgw,
		NatEnabled:  false,

		Callback: nattest{ifno: 1},
	}
	n := CreateNat(gwSet, []Interface{fromInterface}, []PFRule{})
	t.Logf("yay %v", n)

	t.Log("############### TEST 1. Testing ARP #################")
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := n.natPacket(pkt, ipv4, eth, &fromInterface)
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
	t.Logf("Adding arp entry for %s", ipgw)
	n.arpNotify.AddArpEntry(ipgw, hw, "eth0")
	wg.Wait()

	t.Log("############### TEST 2 SYN #################")
	n.table.DeleteAll()
	pkt = common.CreatePacketIPTCP(t, ip2, net.IPv4(8, 8, 8, 8), 2222, 443, common.TCPFlags{SYN: true})
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	n.AcceptPkt(pkt, "veth1")
	require.NotNil(t, globalPacketHolder[1])
	require.Nil(t, globalPacketHolder[0])

	srcipout, dstipout, srcportout, dstportout := decodeTCPPacket(t, globalPacketHolder[1])

	require.Equal(t, srcipout.To4(), ip1.To4())
	require.Equal(t, dstipout.To4(), net.IPv4(8, 8, 8, 8).To4())
	require.GreaterOrEqual(t, srcportout, uint16(srcPortMin)) //(t, srcportout, uint16(2000))
	require.LessOrEqual(t, srcportout, uint16(srcPortMax))    //(t, srcportout, uint16(2000))
	require.Equal(t, dstportout, uint16(443))

	// Create the reverse packet
	t.Log("############### TEST 2. Packet return  SYN-ACK #################")
	pkt = common.CreatePacketIPTCP(t, net.IPv4(8, 8, 8, 8), ip1, 443, srcportout, common.TCPFlags{SYN: true, ACK: true})
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	n.AcceptPkt(pkt, "eth0")
	require.NotNil(t, globalPacketHolder[0])
	require.Nil(t, globalPacketHolder[1])

	srcipout, dstipout, srcportout, dstportout = decodeTCPPacket(t, globalPacketHolder[0])

	require.Equal(t, srcipout.To4(), net.IPv4(8, 8, 8, 8).To4())
	require.Equal(t, dstipout.To4(), ip2.To4())
	require.Equal(t, srcportout, uint16(443))
	require.Equal(t, dstportout, uint16(2222))

	t.Log("############### TEST 2. Packet ACK #################")
	pkt = common.CreatePacketIPTCP(t, ip2, net.IPv4(8, 8, 8, 8), 2222, 443, common.TCPFlags{ACK: true})
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	n.AcceptPkt(pkt, "veth1")
	require.NotNil(t, globalPacketHolder[1])
	require.Nil(t, globalPacketHolder[0])

	srcipout, dstipout, srcportout, dstportout = decodeTCPPacket(t, globalPacketHolder[1])

	require.Equal(t, srcipout.To4(), ip1.To4())
	require.Equal(t, dstipout.To4(), net.IPv4(8, 8, 8, 8).To4())
	require.GreaterOrEqual(t, srcportout, uint16(srcPortMin)) //(t, srcportout, uint16(2000))
	require.LessOrEqual(t, srcportout, uint16(srcPortMax))    //(t, srcportout, uint16(2000))
	require.Equal(t, dstportout, uint16(443))
	t.Log("############### TEST 2. Packet return  FIN #################")
	pkt = common.CreatePacketIPTCP(t, net.IPv4(8, 8, 8, 8), ip1, 443, srcportout, common.TCPFlags{FIN: true})
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	n.AcceptPkt(pkt, "eth0")
	require.NotNil(t, globalPacketHolder[0])
	require.Nil(t, globalPacketHolder[1])

	srcipout, dstipout, srcportout, dstportout = decodeTCPPacket(t, globalPacketHolder[0])

	require.Equal(t, srcipout.To4(), net.IPv4(8, 8, 8, 8).To4())
	require.Equal(t, dstipout.To4(), ip2.To4())
	require.Equal(t, srcportout, uint16(443))
	require.Equal(t, dstportout, uint16(2222))

	t.Log("############### TEST 3 - PING #################")
	pkt = common.CreateICMPPacket(t, ip2, net.IPv4(8, 8, 8, 8), true)
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	n.AcceptPkt(pkt, "veth1")
	require.Nil(t, globalPacketHolder[0])
	require.NotNil(t, globalPacketHolder[1])
	srcipout, dstipout = decodeIPPacket(t, globalPacketHolder[1])

	require.Equal(t, srcipout.To4(), ip1.To4())
	require.Equal(t, dstipout.To4(), net.IPv4(8, 8, 8, 8).To4())

	// Create the reverse packet
	t.Log("############### TEST 3. PING return #################")
	pkt = common.CreateICMPPacket(t, net.IPv4(8, 8, 8, 8), ip1, false)
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	n.AcceptPkt(pkt, "eth0")
	require.NotNil(t, globalPacketHolder[0])
	require.Nil(t, globalPacketHolder[1])

	srcipout, dstipout = decodeIPPacket(t, globalPacketHolder[0])

	require.Equal(t, srcipout.To4(), net.IPv4(8, 8, 8, 8).To4())
	require.Equal(t, dstipout.To4(), ip2.To4())

	t.Log("############### TEST 4. Port forwarding. Drop packet with no rule #################")
	n.table.DeleteAll()
	pkt = common.CreatePacketIPTCP(t, net.IPv4(8, 8, 8, 8), ip1, 4444, 5555, common.TCPFlags{SYN: true})
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	n.AcceptPkt(pkt, "eth0")
	require.Nil(t, globalPacketHolder[0])
	require.Nil(t, globalPacketHolder[1])

	t.Log("############### TEST 4. Port forwarding. Forward the packet. SYN #################")
	n.table.DeleteAll()
	n.portForwardingTable[PortForwardingKey{ExternalPort: 5555, Protocol: layers.IPProtocolTCP}] = PortForwardingEntry{InternalIP: ip2, InternalPort: 4444}
	pkt = common.CreatePacketIPTCP(t, net.IPv4(8, 8, 8, 8), ip1, 3333, 5555, common.TCPFlags{SYN: true})
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
	t.Logf("Adding arp entry for %s", ipgw)
	n.arpNotify.AddArpEntry(ip2, h2w, "veth1")
	wg.Wait()

	srcipout, dstipout, srcportout, dstportout = decodeTCPPacket(t, globalPacketHolder[0])

	require.Equal(t, srcipout.To4(), net.IPv4(8, 8, 8, 8).To4())
	require.Equal(t, dstipout.To4(), ip2.To4())
	// require.Equal(t, srcportout, uint16(3333)) - src port is dynamic
	require.Equal(t, dstportout, uint16(4444))
	t.Log("############### TEST 4. Port forwarding. SYN-ACK #################")

	pkt = common.CreatePacketIPTCP(t, ip2.To4(), net.IPv4(8, 8, 8, 8), 4444, srcportout, common.TCPFlags{SYN: true, ACK: true})
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	n.AcceptPkt(pkt, "veth1")
	require.NotNil(t, globalPacketHolder[1])
	require.Nil(t, globalPacketHolder[0])

	srcipout, dstipout, srcportout, dstportout = decodeTCPPacket(t, globalPacketHolder[1])

	require.Equal(t, srcipout.To4(), ip1.To4())
	require.Equal(t, dstipout.To4(), net.IPv4(8, 8, 8, 8).To4())
	require.Equal(t, srcportout, uint16(5555))
	require.Equal(t, dstportout, uint16(3333))

	t.Log("############### TEST 2. Packet ACK #################")
	pkt = common.CreatePacketIPTCP(t, net.IPv4(8, 8, 8, 8), ip1, 3333, 5555, common.TCPFlags{SYN: true, ACK: true})
	globalPacketHolder[0] = nil
	globalPacketHolder[1] = nil
	n.AcceptPkt(pkt, "eth0")
	require.NotNil(t, globalPacketHolder[0])
	require.Nil(t, globalPacketHolder[1])

	srcipout, dstipout, _, dstportout = decodeTCPPacket(t, globalPacketHolder[0])

	require.Equal(t, srcipout.To4(), net.IPv4(8, 8, 8, 8).To4())
	require.Equal(t, dstipout.To4(), ip2.To4())
	// require.Equal(t, srcportout, uint16(3333)) - src port is dynamic
	require.Equal(t, dstportout, uint16(4444))

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
