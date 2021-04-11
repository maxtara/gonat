package nat

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog/log"
)

var (
	ErrEntryNotFound = fmt.Errorf("entry not found")
)

// Socket states
const (
	TCPEstablished uint8 = 0x01
	TCPSynSent     uint8 = 0x02
	TCPSynRecv     uint8 = 0x03
	TCPFinWait1    uint8 = 0x04
	TCPFinWait2    uint8 = 0x05
	TCPTimeWait    uint8 = 0x06
	TCPCloseWait   uint8 = 0x07
	TCPLastAck     uint8 = 0x08
	TCPListen      uint8 = 0x09
	TCPClosing     uint8 = 0x0a
	TCPClosed      uint8 = 0x0b
)

// Nattable - the nat table!
// Key is a classic layer3/layer4 5-tuple.
// Entry is where to send it, and what to set the layer3/layer 4 to.
type Nattable struct {
	table map[NatKey]*NatEntry
	lock  sync.RWMutex
}

// TCPCloseState - We're not going to track the TCP connection state fully (for now at least)
// Only when a FIN is received. At that point State will become FIN_WAIT1 or CLOSE_WAIT
// So if State is < FinWait1 (0x04), do nothing with the packet unless we see a FIN
type TCPCloseState struct {
	State     uint8
	Initiator bool
	// Need to store the FinackSequence, so if we see an ACK we know if its ack'ing a FIN, thus the state will change
	FinackSequence uint32
}

type NatKey struct {
	SrcPort, DstPort uint16
	SrcIP, DstIP     string
	Protocol         layers.IPProtocol
}
type NatEntry struct {
	LastSeen         time.Time
	SrcPort, DstPort uint16 // SrcPort is also used for icmp.Iq
	SrcIP, DstIP     net.IP
	Inf              *Interface
	DstMac           net.HardwareAddr
	ReverseKey       *NatKey
	TcpState         TCPCloseState
}

// StartGarbageCollector - clean up (remove) closed NAT entries.
// This thread is slow, i tried to move more complexity here, to keep the goroutine
// that packets run in smaller. I might also put some stat printing in here
// TODO - context to close nicly
func (n *Nattable) StartGarbageCollector() {
	for now := range time.Tick(time.Second * 30) {
		natTotal := 0
		natDeletedCount := 0
		natTcpClosing := 0
		shortTimeout := now.Add(-time.Minute * 5)
		longTCPTimeout := now.Add(-time.Minute * 124) // Why 124 mins i hear you ask, check out rfc5382-REQ5.
		var timeout time.Time
		n.lock.Lock()
		for k, v := range n.table {
			natTotal += 1
			if v.TcpState.State == TCPClosed {
				natTcpClosing += 1
			}
			if k.Protocol == layers.IPProtocolTCP && v.TcpState.State < TCPFinWait1 {
				timeout = longTCPTimeout
			} else {
				timeout = shortTimeout
			}
			if timeout.After(v.LastSeen) {
				natDeletedCount += 1
				delete(n.table, k)
			}
		}
		n.lock.Unlock()
		log.Info().Msgf("Nat table stats. Deleted = %d, Total = %d. Closed %d", natDeletedCount, natTotal, natTcpClosing)

	}
}
func (n *Nattable) Check(key NatKey) (ok bool) {
	n.lock.RLock()
	defer n.lock.RUnlock()
	_, ok = n.table[key]
	return // Not going to bother checking the timeout. TCP standard just says we must nat for at least 1 hour.
}
func (n *Nattable) Delete(key NatKey) {
	n.lock.Lock()
	defer n.lock.Unlock()
	delete(n.table, key)
}

// TODO. Load for an hour after a SYN-ACK / Return UDP packet?
func (n *Nattable) Store(key NatKey, entry *NatEntry) {
	entry.LastSeen = time.Now()
	n.lock.Lock()
	defer n.lock.Unlock()
	n.table[key] = entry
	old, ok := n.table[*entry.ReverseKey]
	if ok {
		old.LastSeen = time.Now()
	}
}
func (n *Nattable) Get(key NatKey) *NatEntry {
	n.lock.RLock()
	entry, ok := n.table[key]
	n.lock.RUnlock()
	if !ok {
		return nil
	}
	return entry
}

func (n *Nattable) DeleteAll() {
	// Test function and not used in main code, so a shortcut here.
	n.table = make(map[NatKey]*NatEntry)
}

func (k NatKey) Reverse() NatKey {
	return NatKey{
		SrcIP:    k.DstIP,
		DstIP:    k.SrcIP,
		SrcPort:  k.DstPort,
		DstPort:  k.SrcPort,
		Protocol: k.Protocol,
	}
}

func (k NatKey) String() string {
	return fmt.Sprintf("(%s:%d->%s:%d)", k.SrcIP, k.SrcPort, k.DstIP, k.DstPort)
}
func (e NatEntry) String() string {
	return fmt.Sprintf("(%s== %s:%d->%s:%d)", e.Inf.IfName, e.SrcIP, e.SrcPort, e.DstIP, e.DstPort)
}
