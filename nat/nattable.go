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
	SrcPort, DstPort uint16
	SrcIP, DstIP     net.IP
	Inf              *IfSet
	DstMac           net.HardwareAddr
	ReverseKey       *NatKey
	TcpState         TCPCloseState
}

type Nattable struct {
	table sync.Map //map[NatKey]*NatEntry
}

// StartGarbageCollector - clean up (remove) closed NAT entries.
// This thread is slow, i tried to move more complexity here, to keep the goroutine
// that packets run in smaller. I might also put some stat printing in here
// TODO - context to close nicly
func (n *Nattable) StartGarbageCollector() {
	for now := range time.Tick(time.Second * 5) {
		natTotal := 0
		natDeletedCount := 0
		natTcpClosing := 0
		shortTimeout := now.Add(-time.Second * 10)
		longTCPTimeout := now.Add(-time.Hour * 1)
		var timeout time.Time
		n.table.Range(func(key, value interface{}) bool {
			natTotal += 1
			k := key.(NatKey)
			v := value.(*NatEntry)
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
				n.table.Delete(key.(NatKey))
			}
			return true
		})
		log.Info().Msgf("Nat table stats. Deleted = %d, Total = %d. Closed %d", natDeletedCount, natTotal, natTcpClosing)

	}
}
func (n *Nattable) Check(key NatKey) (ok bool) {
	_, ok = n.table.Load(key)
	return // Not going to bother checking the timeout. TCP standard just says we must nat for at least 1 hour.
}
func (n *Nattable) Delete(key NatKey) {
	n.table.Delete(key)
}

// TODO. Load for an hour after a SYN-ACK / Return UDP packet?
func (n *Nattable) Store(key NatKey, entry *NatEntry) {
	entry.LastSeen = time.Now()
	n.table.Store(key, entry)
}
func (n *Nattable) Get(key NatKey) *NatEntry {
	entry, ok := n.table.Load(key)
	if !ok {
		return nil
	}
	return entry.(*NatEntry)
}

func (n *Nattable) DeleteAll() {
	n.table.Range(func(key, value interface{}) bool {
		n.table.Delete(key)
		return true
	})

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

// func (n *Nattable) Get(key NatKey) ([]byte, error) {
// 	entry, ok := n.table[key]
// 	if !ok {
// 		return nil, ErrEntryNotFound
// 	}
// 	return []byte(entry.IfName), nil
// }

// func (n *Nattable) Put(key NatKey, value []byte) error {
// 	return nil
// }

// func (n *Nattable) Delete(key NatKey) error {
// 	return nil
// }

// func (n *Nattable) List() ([]NatKey, error) {
// 	return nil, nil
// }

// func (n *Nattable) Close() error {
// 	return nil
// }

func (k NatKey) String() string {
	return fmt.Sprintf("(%s:%d->%s:%d)", k.SrcIP, k.SrcPort, k.DstIP, k.DstPort)
}
func (e NatEntry) String() string {
	return fmt.Sprintf("(%s== %s:%d->%s:%d)", e.Inf.If.IfName, e.SrcIP, e.SrcPort, e.DstIP, e.DstPort)
}
