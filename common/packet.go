package common

import (
	"net"

	"github.com/google/gopacket"
	"github.com/rs/zerolog/log"
)

var (
	// FixLengths is required. Not sure why, I didnt think i was changing the packet length. But UDP breaks if you don't.
	Options gopacket.SerializeOptions = gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
)

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

func GetIPs(flow gopacket.NetworkLayer) (net.IP, net.IP) {
	f := flow.NetworkFlow()
	return net.IP(f.Src().Raw()), net.IP(f.Dst().Raw())
}
func GetSrcIP(flow gopacket.NetworkLayer) net.IP {
	f := flow.NetworkFlow()
	return net.IP(f.Src().Raw())
}
func GetDstIP(flow gopacket.NetworkLayer) net.IP {
	f := flow.NetworkFlow()
	return net.IP(f.Dst().Raw())
}
