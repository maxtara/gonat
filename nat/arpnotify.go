package nat

import (
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// This file handles ARP responses.
// The issue we have is N number of threads can all perform ARP requests
// And the response will always come from another random thread.
// So, we're going to have a single thread that recieves a notification that a ARP response has been received.
// And then we'll check to see if the response is for one of our threads.
// If it is, we'll send a signal to that thread to wake it up.
// If it's not, we'll ignore it.
// The main thing to note is that we're using a single thread to handle all of the ARP responses.

type ArpEntry struct {
	Mac       net.HardwareAddr
	IntName   string
	TimeAdded time.Time
}

var EmptyArpEntry = ArpEntry{}

type ARPNotify struct {
	// The ARP response channel
	arpChan    chan net.IP
	arpWaiters map[string]chan bool
	lock       sync.Mutex
	arpTable   sync.Map // [mac]ArpEntry
}

func (a *ARPNotify) AddArpEntry(ip net.IP, mac net.HardwareAddr, interfaceName string) {
	a.arpTable.Store(ip.String(), ArpEntry{Mac: mac, IntName: interfaceName, TimeAdded: time.Now()})
	a.arpChan <- ip
}

func (a *ARPNotify) GetArpEntry(ip net.IP) (ArpEntry, bool) {
	entry, ok := a.arpTable.Load(ip.String())
	if !ok {
		return ArpEntry{}, false
	}
	return entry.(ArpEntry), true
}

func (a *ARPNotify) Close() {
	close(a.arpChan)
}
func (a *ARPNotify) Init() {
	a.arpChan = make(chan net.IP, 1024)
	a.arpWaiters = make(map[string]chan bool)
	// Wait for a arp entry from a listener
	go func() {
		for {
			ip := <-a.arpChan
			a.lock.Lock()
			if waiter, ok := a.arpWaiters[ip.String()]; ok {
				close(waiter)
			}
			delete(a.arpWaiters, ip.String())
			a.lock.Unlock()
		}
	}()
	// age off the arp table
	go func() {
		for now := range time.Tick(time.Second * 60) {
			shortTimeout := now.Add(-time.Minute * 10)
			a.arpTable.Range(func(key, value interface{}) bool {
				if shortTimeout.After(value.(ArpEntry).TimeAdded) {
					a.arpTable.Delete(key)
				}
				return true
			})
		}

	}()
}

// WaitForArp - if there is an entry in the arp table, return immediately.

func (a *ARPNotify) WaitForArp(ipNet net.IP) (mac ArpEntry, ok bool) {

	mac, ok = a.GetArpEntry(ipNet)
	if ok {
		return
	}

	ip := ipNet.String()
	a.lock.Lock()
	if _, ok := a.arpWaiters[ip]; !ok {
		a.arpWaiters[ip] = make(chan bool)
	}
	// Wait for the chan to close
	a.lock.Unlock()
	log.Debug().Msgf("Waiting for channel for %s", ip)
	select {
	case <-a.arpWaiters[ip]:
		mac, ok = a.GetArpEntry(ipNet)
	case <-time.After(2 * time.Second):
		ok = false
	}
	return

}
