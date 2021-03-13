package nat

import (
	"gonat/common"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/rs/zerolog/log"
)

const (
	SnapLen        = 65535
	GoRoutineCount = 10
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
	return s.Start5(nat, bpf)
}

// version 1
func (s Sniffer) Start1(nat *Nat, bpf string) (err error) {

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
	packetsource.NoCopy = true //. Going to modify the pkt in place and send it along. So we better let gopacket copy it.
	packetsource.Lazy = true
	log.Info().Msgf("Started listening on %s with BPF filter %s", s.ifName, bpf)

	// ---------- VERSION 1
	for pkt := range packetsource.Packets() {
		errLayer := pkt.ErrorLayer()
		if errLayer == nil {
			log.Debug().Msgf("Packet received on %s: %v", s.ifName, pkt)
			go nat.AcceptPkt(pkt, s.ifName)
		} else {
			log.Error().Interface("ErrorLayer", errLayer).Msgf("Error decoding a packet on %v", pkt)
		}
	}
	return
}

// Version 2
func (s Sniffer) Start2(nat *Nat, bpf string) (err error) {

	handle, err := pcap.OpenLive(s.ifName, SnapLen, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()
	err = handle.SetBPFFilter(bpf)

	if err != nil {
		panic(err)
	}

	log.Info().Msgf("Started listening on %s with BPF filter %s", s.ifName, bpf)

	// ------------ VERSION 2
	lt := handle.LinkType()
	for {
		// pkt, err := packetsource.NextPacket()
		data, ci, _ := handle.ReadPacketData()
		go func(data *[]byte) {
			pkt := gopacket.NewPacket(*data, lt, gopacket.Default)
			m := pkt.Metadata()
			m.CaptureInfo = ci
			m.Truncated = m.Truncated || ci.CaptureLength < ci.Length
			if m.Truncated {
				log.Warn().Msgf("Packet truncated. Capture length %d, Length %d", ci.CaptureLength, ci.Length)
				return
			}
			nat.AcceptPkt(pkt, s.ifName)

		}(&data)
	}
}

// Version 3
func (s Sniffer) Start3(nat *Nat, bpfz string) (err error) {

	iface := s.ifName
	snaplen := 65535
	bufferSize := 8
	filter := bpfz
	count := -1
	addVLAN := false

	szFrame, szBlock, numBlocks, err := afpacketComputeSize(bufferSize, snaplen, os.Getpagesize())
	if err != nil {
		panic(err)
	}
	afpacketHandle, err := newAfpacketHandle(iface, szFrame, szBlock, numBlocks, addVLAN, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	err = afpacketHandle.SetBPFFilter(filter, snaplen)
	if err != nil {
		panic(err)
	}
	source := gopacket.ZeroCopyPacketDataSource(afpacketHandle)
	defer afpacketHandle.Close()

	// lt := handle.LinkType()
	for ; count != 0; count-- {
		data, _, err := source.ZeroCopyReadPacketData()
		if err != nil {
			panic(err)
		}

		go func(data []byte) {
			pkt := gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.Default)
			errLayer := pkt.ErrorLayer()
			if errLayer == nil {
				log.Debug().Msgf("Packet received on %s: %v", s.ifName, pkt)
				go nat.AcceptPkt(pkt, s.ifName)
			} else {
				log.Error().Interface("ErrorLayer", errLayer).Msgf("Error decoding a packet on %v", pkt)
			}

		}(data)

	}
	return
}

// v4
func (s Sniffer) Start4(nat *Nat, bpf string) (err error) {

	handle, err := pcap.OpenLive(s.ifName, SnapLen, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()
	err = handle.SetBPFFilter(bpf)

	if err != nil {
		panic(err)
	}

	log.Info().Msgf("Started listening on %s with BPF filter %s", s.ifName, bpf)

	// ------------ VERSION 4
	lt := handle.LinkType()
	runAsync := func() {
		for {
			data, _, _ := handle.ReadPacketData()
			pkt := gopacket.NewPacket(data, lt, gopacket.Default)
			nat.AcceptPkt(pkt, s.ifName)
		}
	}

	for i := 0; i < GoRoutineCount-1; i++ {
		go runAsync()
	}
	runAsync()
	return
}

// v5
func (s Sniffer) Start5(nat *Nat, bpf string) (err error) {

	handle, err := pcap.OpenLive(s.ifName, SnapLen, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()
	err = handle.SetBPFFilter(bpf)

	if err != nil {
		panic(err)
	}

	log.Info().Msgf("Started listening on %s with BPF filter %s", s.ifName, bpf)

	// ------------ VERSION 5
	var opts = gopacket.DecodeOptions{NoCopy: true, Lazy: true}

	lt := handle.LinkType()
	runAsync := func(i int) {
		for {
			data, _, _ := handle.ReadPacketData()
			pkt := gopacket.NewPacket(data, lt, opts)
			nat.AcceptPktThreaded(pkt, s.ifName, i)
		}
	}

	for i := 0; i < GoRoutineCount-1; i++ {
		go runAsync(i)
	}
	runAsync(GoRoutineCount - 1)
	return
}

// Spitter - yea terrible name i know, you have a sniffer and a spitter. Sniff on one interface, spit out the other.
type Spitter struct {
	ifName string
	handle *pcap.Handle
	bufs   [GoRoutineCount]gopacket.SerializeBuffer
}

func CreateSpitter(ifName string, promisc bool) Dest {
	s := Spitter{ifName: ifName}
	s.bufs = [GoRoutineCount]gopacket.SerializeBuffer{}
	for i := 0; i < GoRoutineCount; i++ {
		s.bufs[i] = gopacket.NewSerializeBuffer()
	}
	handle, err := pcap.OpenLive(ifName, SnapLen, promisc, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	s.handle = handle
	return s
}

func (s Spitter) Send(pkt gopacket.Packet, threadCount int) (err error) {
	buf := common.ConvertPacketRuse(pkt, &s.bufs[threadCount])
	// log.Debug().Msgf("Writting pkt to interface %s. of len %d\n-----%s", s.ifName, len(pkt.Data()), hex.EncodeToString(pkt.Data()))
	err = s.handle.WritePacketData(buf)
	if err != nil {
		log.Error().Err(err).Msgf("Ouch. This is probably just a too large packet - probably TSO related.")
	}
	s.bufs[threadCount].Clear()

	return
}

func (s Spitter) SendBytes(buf []byte) (err error) {
	err = s.handle.WritePacketData(buf)
	if err != nil {
		log.Error().Err(err).Msgf("Ouch. This is probably just a too large packet - probably TSO related.")
	}
	return
}
