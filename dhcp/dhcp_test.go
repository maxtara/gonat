package dhcp

import (
	"net"
	"testing"

	dhcp "github.com/krolaw/dhcp4"
)

func TestSimple(t *testing.T) {
	testip, testNet, _ := net.ParseCIDR("172.15.0.2/24")

	hand := NewDHCPHandler(testip, dhcp.IPAdd(testip, 1), testip, *testNet, 100)
	t.Logf("%s", hand)
	// TODO
}
