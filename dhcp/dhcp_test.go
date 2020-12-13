package dhcp

import (
	"net"
	"testing"
)

func TestSimple(t *testing.T) {
	testip, testNet, _ := net.ParseCIDR("172.15.0.2/24")

	hand := NewDHCPHandler(testip, *testNet, 100)
	t.Logf("%s", hand)
	// TODO
}
