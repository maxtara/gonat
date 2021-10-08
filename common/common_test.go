package common

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestICMPv6Opts(t *testing.T) {
	out := []byte("\x40\xc0\x00\x00\x1a\x49\x00\x00\x0c\x38\x00\x00\x00\x00\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	in := ICMPv6OptPrefixInfo(net.ParseIP("fd00::"), 64, 6729, 3128, true, true, false)
	require.Equal(t, out, in)
	out = []byte("\x00\x00\x00\x00\x04\xb0\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01")
	in = ICMPv6OptDNS(net.ParseIP("fd00::1"), 1200)
	require.Equal(t, out, in)
	out = []byte("\x00\x00\x00\x00\x05\xd4")
	in = ICMPv6OptMTU(uint32(1492))
	require.Equal(t, out, in)

	out = []byte("\x00\x00\x00\x00\x07\x08")
	_, cidr, _ := net.ParseCIDR("::/0")
	in = ICMPv6OptRouteInformation(*cidr, uint32(1800))
	require.Equal(t, out, in)

	out = []byte("\x38\x00\x00\x00\x07\x08\x20\x01\x44\xb8\x41\xe1\xcc\x00")
	_, cidr2, _ := net.ParseCIDR("2001:44b8:41e1:cc00::/56")
	in = ICMPv6OptRouteInformation(*cidr2, uint32(1800))
	require.Equal(t, out, in)

}
