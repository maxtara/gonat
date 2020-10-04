package nat

import (
	"gonat/common"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/rs/zerolog/log"
)

const (
	SnapLen = 65535
)

// Sniffer - yea terrible name i know, you have a sniffer and a spitter. Sniff on one interface, spit out the other.
type Sniffer struct {
	ifName  string
	promisc bool
}

func CreateSniffer(ifName string, promisc bool) Source {
	return Sniffer{ifName: ifName, promisc: promisc}
}

func (s Sniffer) Start(nat *Nat, bpf string) (err error) {

	handle, err := pcap.OpenLive(s.ifName, SnapLen, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()
	err = handle.SetBPFFilter(bpf)
	if err != nil {
		panic(err)
	}
	packetsource := gopacket.NewPacketSource(handle, handle.LinkType())
	// packetsource.NoCopy = true //. Going to modify the pkt in place and send it along. So we better let gopacket copy it.
	packetsource.Lazy = true
	log.Info().Msgf("Started listening on %s with BPF filter %s", s.ifName, bpf)
	for pkt := range packetsource.Packets() {
		errLayer := pkt.ErrorLayer()
		if errLayer == nil {
			// log.Debug().Msgf("Packet received on %s: %v", s.ifName, pkt)
			go nat.AcceptPkt(pkt, s.ifName)
		} else {
			log.Error().Interface("ErrorLayer", errLayer).Msgf("Error decoding a packet on %v", pkt)
		}
	}

	return
}

// Spitter - yea terrible name i know, you have a sniffer and a spitter. Sniff on one interface, spit out the other.
type Spitter struct {
	ifName string
	handle *pcap.Handle
}

func CreateSpitter(ifName string, promisc bool) Dest {
	s := Spitter{ifName: ifName}
	handle, err := pcap.OpenLive(ifName, SnapLen, promisc, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	s.handle = handle
	return s
}

func (s Spitter) Send(pkt gopacket.Packet) (err error) {
	buf := common.ConvertPacket(pkt)
	// log.Debug().Msgf("Writting pkt to interface %s. of len %d\n-----%s", s.ifName, len(pkt.Data()), hex.EncodeToString(pkt.Data()))
	err = s.handle.WritePacketData(buf)
	if err != nil {
		log.Error().Err(err).Msgf("Ouch. This is probably just a too large packet - probably TSO related. Dropping seems to work.")
	}

	return
}

func (s Spitter) SendBytes(buf []byte) (err error) {
	err = s.handle.WritePacketData(buf)
	if err != nil {
		log.Error().Err(err).Msgf("Ouch. This is probably just a too large packet - probably TSO related. Dropping seems to work.")
	}
	return
}
