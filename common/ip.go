package common

import (
	"encoding/binary"
	"fmt"
	"net"
)

func Ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		panic(fmt.Sprintf("IPV4 only. %s", ip))
	}
	return binary.BigEndian.Uint32(ip)
}

func Int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}
