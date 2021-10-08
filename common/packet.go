package common

import (
	"encoding/binary"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
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

func PrintPacket(buf []byte, lvl zerolog.Level) {
	if lvl >= log.Logger.GetLevel() {
		pkt := gopacket.NewPacket(buf, layers.LayerTypeEthernet, gopacket.Default)
		log.Info().Msgf("%v", pkt)
	}
}

func FixICMPv6Checksum(src, dst, b []byte, lengthIcmp int) uint16 {

	/*
		The checksum is the 16-bit one's complement of the one's complement
		sum of the entire ICMPv6 message, starting with the ICMPv6 message
		type field, and prepended with a "pseudo-header" of IPv6 header
		fields, as specified in [IPv6, Section 8.1].  The Next Header value
		used in the pseudo-header is 58.  (The inclusion of a pseudo-header
		in the ICMPv6 checksum is a change from IPv4; see [IPv6] for the
		rationale for this change.)

		For computing the checksum, the checksum field is first set to zero.

			[IPv6, Section 8.1]
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		+                         Source Address                        +
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		+                      Destination Address                      +
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|                   Upper-Layer Packet Length                   |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|                      zero                     |  Next Header  |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


	*/

	b[2] = 0
	b[3] = 0
	lenbs := make([]byte, 4)
	binary.BigEndian.PutUint32(lenbs, uint32(lengthIcmp))
	var data []byte
	data = append(src, dst...)
	data = append(data, lenbs...)
	data = append(data, []byte{0, 0, 0, 0x3a}...)
	data = append(data, b...)

	csum := uint32(0)
	// to handle odd lengths, we loop to length - 1, incrementing by 2, then
	// handle the last byte specifically by checking against the original
	// length.
	length := len(data) - 1
	for i := 0; i < length; i += 2 {
		// For our test packet, doing this manually is about 25% faster
		// (740 ns vs. 1000ns) than doing it by calling binary.BigEndian.Uint16.
		csum += uint32(data[i]) << 8
		csum += uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		csum += uint32(data[length]) << 8
	}
	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return ^uint16(csum)

}

// ICMPv6OptPrefixInfo creates an ICMPv6 option for prefix info RS
func ICMPv6OptPrefixInfo(prefix net.IP, prefixLen int, validLifetime, preferredLifetime uint32, onlink, autonomous, router bool) []byte {
	flags := byte(0)
	if onlink {
		flags |= 0x80
	}
	if autonomous {
		flags |= 0x40
	}
	if router {
		flags |= 0x20
	}
	bs := [30]byte{}
	if prefixLen > 128 {
		log.Fatal().Msgf("Invalid prefix length %d. ipv6 prefix must be 128 or less", prefixLen)
	}
	bs[0] = byte(prefixLen)
	bs[1] = flags
	binary.BigEndian.PutUint32(bs[2:6], validLifetime)
	binary.BigEndian.PutUint32(bs[6:10], preferredLifetime)
	if len(prefix) != 16 {
		log.Fatal().Msgf("Invalid IP - %s. Dont think this will happen", prefix)
	}
	copy(bs[14:], prefix)
	return bs[:]
}

// ICMPv6OptDns creates a DNS option for an ICMPv6 RA.
func ICMPv6OptDNS(server net.IP, lifetime uint32) []byte {
	bs := [22]byte{}
	binary.BigEndian.PutUint32(bs[2:6], lifetime)
	if len(server) != 16 {
		log.Fatal().Msgf("Invalid IP - %s. Dont think this will happen", server)
	}
	copy(bs[6:], server)
	return bs[:]
}

// ICMPv6OptMTU create an ICMPv6 option for MTU
func ICMPv6OptMTU(mtu uint32) []byte {
	bs := [6]byte{}
	binary.BigEndian.PutUint32(bs[2:6], mtu)
	return bs[:]
}

// ICMPv6OptRouteInformation defined in rfc4191. Flags don't do much, I suspect I'll always want medium priority
func ICMPv6OptRouteInformation(prefix net.IPNet, lifetime uint32) []byte {
	bs := make([]byte, 6) // 6 is minimum
	flags := byte(0)
	prefixlen, _ := prefix.Mask.Size()
	bs[0] = byte(prefixlen)
	bs[1] = flags

	binary.BigEndian.PutUint32(bs[2:6], lifetime)

	if prefixlen > 0 && prefixlen <= 64 {
		bs = append(bs, prefix.IP[:8]...)
	} else if prefixlen > 64 && prefixlen <= 128 {
		bs = append(bs, prefix.IP[:16]...)
	}

	return bs[:]
}
