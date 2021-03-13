package common

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
)

var (
	// FixLengths is required. Not sure why, I didnt think i was changing the packet length. But UDP breaks if you don't.
	Options   gopacket.SerializeOptions = gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	rawBytes                            = []byte{0, 1, 2, 3, 4}
	ip1test                             = net.IPv4(5, 6, 7, 8)
	ip2test                             = net.IPv4(8, 1, 1, 1)
	porttest1                           = uint16(12345)
	porttest2                           = uint16(9876)
)

func CreatePacket(t require.TestingT) (packet gopacket.Packet) {
	return CreatePacketIPTCP(t, ip1test, ip2test, porttest1, porttest2, TCPFlags{})
}
func CreatePacketTCP(t require.TestingT, srcport, dstport uint16) (packet gopacket.Packet) {
	return CreatePacketIPTCP(t, ip1test, ip2test, srcport, dstport, TCPFlags{})
}
func CreatePacketIP(t require.TestingT, src, dst net.IP) (packet gopacket.Packet) {
	return CreatePacketIPTCP(t, src, dst, porttest1, porttest2, TCPFlags{})
}

type TCPFlags struct {
	FIN bool
	SYN bool
	RST bool
	PSH bool
	ACK bool
	URG bool
	ECE bool
	CWR bool
	NS  bool
}

func CreatePacketIPTCP(t require.TestingT, src, dst net.IP, srcport, dstport uint16, flgas TCPFlags) (packet gopacket.Packet) {

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
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)
	// And create the packet with the layers
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, Options,
		ethernetLayer,
		ipLayer,
		tcpLayer,
		gopacket.Payload(rawBytes),
	)
	require.Nil(t, err)
	packet = gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	return
}

func CreateICMPPacket(srcmac, dstmac net.HardwareAddr, src, dst net.IP, icmpType, icmpCode uint8) ([]byte, error) {

	ethernetLayer := &layers.Ethernet{
		SrcMAC:       srcmac,
		DstMAC:       dstmac,
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
		Protocol:   layers.IPProtocolICMPv4,
	}
	icmpLayer := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(icmpType, icmpCode)}
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, Options,
		ethernetLayer,
		ipLayer,
		icmpLayer,
		gopacket.Payload(rawBytes),
	)
	if err != nil {
		log.Error().Err(err).Msg("Error serializing ICMP packet")
		return nil, err
	}
	return buffer.Bytes(), err
}

func CreateICMPPacketTest(t require.TestingT, src, dst net.IP, icmpType, icmpCode uint8) (packet gopacket.Packet) {
	buffer, err := CreateICMPPacket(net.HardwareAddr{0x00, 0x0F, 0xAA, 0xFA, 0xAA, 0x00}, net.HardwareAddr{0x00, 0x0D, 0xBD, 0xBD, 0x00, 0xBD}, src, dst, icmpType, icmpCode)

	require.Nil(t, err)
	packet = gopacket.NewPacket(buffer, layers.LayerTypeEthernet, gopacket.Default)
	return
}

func ConvertPacket(pkt gopacket.Packet) []byte {
	buf := gopacket.NewSerializeBuffer()
	return ConvertPacketRuse(pkt, &buf)
}

func ConvertPacketRuse(pkt gopacket.Packet, buf *gopacket.SerializeBuffer) []byte {
	err := gopacket.SerializePacket(*buf, Options, pkt)
	if err != nil {
		log.Error().Err(err).Msgf("Failed to serialise packet? this shouldnt happen %s", pkt)
	}

	return (*buf).Bytes()
}

func GetIP(flow gopacket.NetworkLayer) (net.IP, net.IP) {
	f := flow.NetworkFlow()
	return net.IP(f.Src().Raw()), net.IP(f.Dst().Raw())
}
