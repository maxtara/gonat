/*
common holds common unitility functions.
Gopacket stuff, ip address utils, Ethernet utils etc
*/
package common

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog/log"
)

var (
	ErrNoInterfaceFound = errors.New("could not find interface with that name")
)

func GetMacAddr(name string) (string, error) {
	ifas, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, ifa := range ifas {
		if ifa.Name == name {
			return ifa.HardwareAddr.String(), nil
		}

	}
	return "", ErrNoInterfaceFound
}

func GetMacMTU(name string) (int, error) {
	ifas, err := net.Interfaces()
	if err != nil {
		return -1, err
	}
	for _, ifa := range ifas {
		if ifa.Name == name {
			return ifa.MTU, nil
		}

	}
	return -1, ErrNoInterfaceFound
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
		gopacket.Payload([]byte{0}),
	)
	if err != nil {
		log.Error().Err(err).Msg("Error serializing ICMP packet")
		return nil, err
	}
	return buffer.Bytes(), err
}

func LogSimpleNDPI(pkt gopacket.Packet, src, dst net.IP, srcp, dstp uint16, protocol layers.IPProtocol) (str string) {
	srvc1 := GetProtoByNumber(int(srcp))
	srvc2 := GetProtoByNumber(int(dstp))
	str = fmt.Sprintf("%s:%d -> %s:%d %s (%v)(%v)", src, srcp, dst, dstp, protocol, srvc1, srvc2)
	if srcp == 9999 && dstp == 9999 {
		str += "(GoogleHome)"
	}
	return str
}

func String2IPProto(str string) (layers.IPProtocol, error) {
	switch str {
	case "tcp":
		return layers.IPProtocolTCP, nil
	case "udp":
		return layers.IPProtocolUDP, nil
	case "icmp":
		return layers.IPProtocolICMPv4, nil
	case "ipv6":
		return layers.IPProtocolIPv6, nil
	case "ipv4":
		return layers.IPProtocolIPv4, nil
	default:
		return 0, errors.New("unknown protocol")
	}
}

// IsIPv4 returns true if the address is an ipv4 address.
// I wish this was nicer in golang, but it seems both 'ip.to4() == nil' and 'len(ip) == 16' dont always work
func IsIPv4(ip net.IP) bool {
	return strings.Count(ip.String(), ":") < 2
}
