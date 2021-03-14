package common

import (
	"errors"
	"net"

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
