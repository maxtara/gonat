package dhcp

import (
	"errors"

	dhcp "github.com/krolaw/dhcp4"

	"math/rand"
	"net"
	"time"
)

var (
	ErrDHCPParse = errors.New("Error parsing DHCP packet")
)

// Example using DHCP with a single network interface device
func NewDHCPHandler() DHCPHandler {
	serverIP := net.IP{10, 00, 0, 1}
	return DHCPHandler{
		ip:            serverIP,
		leaseDuration: 2 * time.Hour,
		start:         net.IP{10, 0, 0, 3},
		leaseRange:    50,
		leases:        make(map[int]lease, 100),
		options: dhcp.Options{
			dhcp.OptionSubnetMask:       []byte{255, 0, 0, 0},
			dhcp.OptionRouter:           []byte(serverIP),               // Presuming Server is also your router
			dhcp.OptionDomainNameServer: []byte{0x08, 0x08, 0x08, 0x08}, // Presuming Server is also your DNS server
		},
	}
	// err := dhcp.ListenAndServe(handler)
	// if err != nil {
	// 	log.Fatal().Err(err).Msg("Error starting dhcpserver")
	// }
	// // log.Fatal(dhcp.Serve(dhcp.NewUDP4BoundListener("eth0",":67"), handler)) // Select interface on multi interface device - just linux for now
	// // log.Fatal(dhcp.Serve(dhcp.NewUDP4FilterListener("en0",":67"), handler)) // Work around for other OSes
}

type lease struct {
	nic    string    // Client's CHAddr
	expiry time.Time // When the lease expires
}

type DHCPHandler struct {
	ip            net.IP        // Server IP to use
	options       dhcp.Options  // Options to send to DHCP Clients
	start         net.IP        // Start of IP range to distribute
	leaseRange    int           // Number of IPs to distribute (starting from start)
	leaseDuration time.Duration // Lease period
	leases        map[int]lease // Map to keep track of leases
}

func (h *DHCPHandler) Handle(buffer []byte, ip net.IP, port int) (d dhcp.Packet, err error) {
	n := len(buffer)
	if n < 240 { // Packet too small to be DHCP
		return nil, ErrDHCPParse
	}
	req := dhcp.Packet(buffer[:n])
	if req.HLen() > 16 { // Invalid size
		return nil, ErrDHCPParse
	}
	options := req.ParseOptions()
	var reqType dhcp.MessageType
	if t := options[dhcp.OptionDHCPMessageType]; len(t) != 1 {
		return nil, ErrDHCPParse
	} else {
		reqType = dhcp.MessageType(t[0])
		if reqType < dhcp.Discover || reqType > dhcp.Inform {
			return nil, ErrDHCPParse
		}
	}

	return h.ServeDHCP(req, reqType, options), nil
}

func (h *DHCPHandler) ServeDHCP(p dhcp.Packet, msgType dhcp.MessageType, options dhcp.Options) (d dhcp.Packet) {
	switch msgType {

	case dhcp.Discover:
		free, nic := -1, p.CHAddr().String()
		for i, v := range h.leases { // Find previous lease
			if v.nic == nic {
				free = i
				goto reply
			}
		}
		if free = h.freeLease(); free == -1 {
			return
		}
	reply:
		return dhcp.ReplyPacket(p, dhcp.Offer, h.ip, dhcp.IPAdd(h.start, free), h.leaseDuration,
			h.options.SelectOrderOrAll(options[dhcp.OptionParameterRequestList]))

	case dhcp.Request:
		if server, ok := options[dhcp.OptionServerIdentifier]; ok && !net.IP(server).Equal(h.ip) {
			return nil // Message not for this dhcp server
		}
		reqIP := net.IP(options[dhcp.OptionRequestedIPAddress])
		if reqIP == nil {
			reqIP = net.IP(p.CIAddr())
		}

		if len(reqIP) == 4 && !reqIP.Equal(net.IPv4zero) {
			if leaseNum := dhcp.IPRange(h.start, reqIP) - 1; leaseNum >= 0 && leaseNum < h.leaseRange {
				if l, exists := h.leases[leaseNum]; !exists || l.nic == p.CHAddr().String() {
					h.leases[leaseNum] = lease{nic: p.CHAddr().String(), expiry: time.Now().Add(h.leaseDuration)}
					return dhcp.ReplyPacket(p, dhcp.ACK, h.ip, reqIP, h.leaseDuration,
						h.options.SelectOrderOrAll(options[dhcp.OptionParameterRequestList]))
				}
			}
		}
		return dhcp.ReplyPacket(p, dhcp.NAK, h.ip, nil, 0, nil)

	case dhcp.Release, dhcp.Decline:
		nic := p.CHAddr().String()
		for i, v := range h.leases {
			if v.nic == nic {
				delete(h.leases, i)
				break
			}
		}
	}
	return nil
}

func (h *DHCPHandler) freeLease() int {
	now := time.Now()
	b := rand.Intn(h.leaseRange) // Try random first
	for _, v := range [][]int{[]int{b, h.leaseRange}, []int{0, b}} {
		for i := v[0]; i < v[1]; i++ {
			if l, ok := h.leases[i]; !ok || l.expiry.Before(now) {
				return i
			}
		}
	}
	return -1
}