package main

import (
	"flag"
	"fmt"
	"gonat/common"
	"gonat/nat"
	"net"
	"os"
	"sync"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	_ "github.com/google/gopacket/layers"
)

func getMacAddr(name string) (string, error) {
	ifas, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, ifa := range ifas {
		if ifa.Name == name {
			return ifa.HardwareAddr.String(), nil
		}

	}
	return "", nat.ErrNoInterfaceFound
}

type interfaceNames []string

func (i *interfaceNames) String() string {
	return fmt.Sprintf("%v", *i)
}

func (i *interfaceNames) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func main() {
	var lanInterfaces interfaceNames
	var portfrules nat.PortForwardingRules
	loglvlStr := flag.String("v", "debug", "debug level")
	flag.Var(&lanInterfaces, "lan", "Name of the LAN interfaces.")
	flag.Var(&portfrules, "pf", "Port Forwarding rules. In the format ip,tcp|udp,externalstart<-end>,internalstart. Eg, 10.0.0.2,tcp,2000,2000, or 10.0.0.2,udp,2000-2001,3000")
	wanIntName := flag.String("wan", "eth1", "Name of WAN interface")
	lanAddrStr := flag.String("lancidr", "10.0.0.1/8", "Network address of LAN interfaces")
	wanAddr := flag.String("wandcidr", "192.168.1.80/24", "Network address WAN interface")
	flag.Parse()
	loglvl, err := zerolog.ParseLevel(*loglvlStr)
	if err != nil {
		panic("Failed to parse log level, try debug")
	}
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr}).Level(loglvl)

	wanSniffer := nat.CreateSniffer(*wanIntName, false)

	wanMac, err := getMacAddr(*wanIntName)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to find devices")
	}

	hwWan, _ := net.ParseMAC(wanMac)

	wanIP, wanCidr, err := net.ParseCIDR(*wanAddr)
	if err != nil || wanIP == nil {
		log.Fatal().Msgf("Failed to parse override address - should be a subnet %s", *wanAddr)
	}

	lanIP, lanAddr, err := net.ParseCIDR(*lanAddrStr)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to find devices")
	}

	var lansets []nat.IfSet
	var lanSources []nat.Source
	listeningStr := ""
	for _, lanInterface := range lanInterfaces {
		s1, if1s := getInterfaces(lanInterface, lanIP, *lanAddr)
		lansets = append(lansets, if1s)
		lanSources = append(lanSources, s1)
		listeningStr += if1s.If.IPv4Addr.String() + " "
	}

	wanInterface := nat.Interface{
		IfName:      *wanIntName,
		IfHWAddr:    hwWan,
		IPv4Addr:    wanIP,
		IPv4Netmask: wanCidr.Mask,
		IPv4Network: *wanCidr,
		IPv4Gateway: common.Int2ip(common.Ip2int(wanIP.Mask(wanCidr.Mask)) + 1), // Assume the gateway is the first address in the subnet,
		NatEnabled:  false,
		DHCPEnabled: false,
	}
	wanInterfaceSet := nat.IfSet{
		If:       wanInterface,
		Callback: nat.CreateSpitter(*wanIntName, false),
	}

	nat := nat.CreateNat(wanInterfaceSet, lansets, portfrules)

	log.Info().Msgf("Starting NAT on (lan) - %s and (wan) - %s\nListening on %s, using %s\nPort Forwarding rules: %+v", lanInterfaces, *wanIntName, listeningStr, wanInterfaceSet.If.IPv4Addr, &portfrules)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go wanSniffer.Start(nat, fmt.Sprintf("ether src not %s", wanInterface.IfHWAddr)) // BPF filter to remove packets sent _from_ gonat
	for i, lanSource := range lanSources {
		wg.Add(1)
		go lanSource.Start(nat, fmt.Sprintf("ether src not %s", lansets[i].If.IfHWAddr)) // BPF filter to remove packets sent _from_ gonat
	}
	wg.Wait()
}

func getInterfaces(if1Name string, ip net.IP, network net.IPNet) (source nat.Source, set nat.IfSet) {

	source = nat.CreateSniffer(if1Name, false)
	spitter1 := nat.CreateSpitter(if1Name, false)
	if1Mac, err := getMacAddr(if1Name)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to find devices")
	}
	hw1, _ := net.ParseMAC(if1Mac)

	if1 := nat.Interface{IfName: if1Name,
		IfHWAddr:    hw1,
		IPv4Addr:    ip,
		IPv4Netmask: network.Mask,
		IPv4Network: network,
		NatEnabled:  true,
		DHCPEnabled: true,
	}
	set = nat.IfSet{If: if1, Callback: spitter1}

	return

}
