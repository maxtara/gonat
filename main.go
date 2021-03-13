package main

import (
	"flag"
	"fmt"
	"gonat/common"
	"gonat/dhcp"
	"gonat/nat"
	"net"
	"os"
	"sync"

	_ "github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

type StaticDHCPEntry struct {
	IP  string `yaml:"ip"`
	MAC string `yaml:"mac"`
}
type DHCPConfig struct {
	Enabled bool   `yaml:"enabled"`
	Start   string `yaml:"start"`
	Count   int    `yaml:"count"`
	DNS     string `yaml:"dns"`
}

type LanInterface struct {
	Name              string            `yaml:"name"`
	Addr              string            `yaml:"addr"`
	DHCPOptions       DHCPConfig        `yaml:"dhcp"`
	StaticDHCPEntries []StaticDHCPEntry `yaml:"staticDhcpEntries"`
}

type Config struct {
	LanInterfaces []LanInterface `yaml:"lan"`
	WanInterface  struct {
		Name string `yaml:"name"`
		Addr string `yaml:"addr"`
	} `yaml:"wan"`
	PFRules []nat.PFRule `yaml:"portForwardingRules"`
}

func main() {
	loglvlStr := flag.String("v", "debug", "debug level")
	configStr := flag.String("c", "config.yaml", "config location")
	flag.Parse()
	loglvl, err := zerolog.ParseLevel(*loglvlStr)
	if err != nil {
		panic("Failed to parse log level, try debug")
	}
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr}).Level(loglvl).With().Timestamp().Logger().With().Caller().Logger()

	// ff, errv := os.Create("cpuprofile")
	// if errv != nil {
	// 	log.Fatal().Err(errv).Msg("Failed to create CPU profile")
	// }
	// pprof.StartCPUProfile(ff)
	// go func() {
	// 	time.Sleep(10 * time.Second)
	// 	pprof.StopCPUProfile()
	// 	log.Warn().Msg("\n\n\n\n\n###########################################CPU PROFILE FINISHED")
	// }()

	f, err := os.Open(*configStr)
	if err != nil {
		log.Fatal().Err(err).Msgf("Failed to open config %s", *configStr)
	}
	defer f.Close()

	var cfg Config
	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&cfg)
	if err != nil {
		log.Fatal().Err(err).Msgf("Failed to parse config '%s'", *configStr)
	}
	log.Debug().Msgf("Config: %+v", cfg)
	wanSniffer := nat.CreateSniffer(cfg.WanInterface.Name, false)

	wanMac, err := common.GetMacAddr(cfg.WanInterface.Name)
	if err != nil {
		log.Fatal().Err(err).Msgf("Failed to find device '%s'", cfg.WanInterface.Name)
	}

	wanMTU, err := common.GetMacMTU(cfg.WanInterface.Name)
	if err != nil {
		log.Fatal().Err(err).Msgf("Failed to find device '%s'", cfg.WanInterface.Name)
	}

	hwWan, _ := net.ParseMAC(wanMac)

	wanIP, wanCidr, err := net.ParseCIDR(cfg.WanInterface.Addr)
	if err != nil || wanIP == nil {
		log.Fatal().Msgf("Failed to parse override address - should be a subnet %s", cfg.WanInterface.Addr)
	}

	var lansets []nat.Interface
	var lanSources []nat.Source
	listeningStr := ""
	for _, lanInterface := range cfg.LanInterfaces {
		_, tmp, _ := net.ParseCIDR(lanInterface.Addr)
		if err != nil {
			log.Fatal().Err(err).Msgf("Bad addr for interface %v", lanInterface)
		}

		if common.Intersect(tmp, wanCidr) {
			log.Fatal().Err(err).Msgf("Lan interfaces and WAN interfaces cant intersect at all - %v and %v", lanInterface, wanCidr)
		}
		s1, if1s := getInterfaces(lanInterface)
		lansets = append(lansets, if1s)
		lanSources = append(lanSources, s1)
		listeningStr += if1s.IPv4Addr.String() + " "
	}

	wanInterfaceSet := nat.Interface{
		IfName:      cfg.WanInterface.Name,
		IfHWAddr:    hwWan,
		IPv4Addr:    wanIP,
		IPv4Netmask: wanCidr.Mask,
		IPv4Network: *wanCidr,
		MTU:         wanMTU,
		IPv4Gateway: common.Int2ip(common.Ip2int(wanIP.Mask(wanCidr.Mask)) + 1), // Assume the gateway is the first address in the subnet,
		NatEnabled:  false,
		DHCPEnabled: false,
		Callback:    nat.CreateSpitter(cfg.WanInterface.Name, false),
	}

	for _, pfrule := range cfg.PFRules {
		if pfrule.Protocol != "tcp" && pfrule.Protocol != "udp" {
			log.Fatal().Msgf("Invalid protocol %s", pfrule.Protocol)
		}
		endTmp := pfrule.InternalPortStart + (pfrule.ExternalPortEnd - pfrule.ExternalPortStart)
		if pfrule.InternalPortStart > endTmp {
			log.Fatal().Msgf("Invalid port range for %+v", pfrule)
		}

	}
	nat := nat.CreateNat(wanInterfaceSet, lansets, cfg.PFRules)

	log.Info().Msgf("Starting NAT on (lan) - %v and (wan) - %s\nListening on %s, using %s\nPort Forwarding rules: %+v", cfg.LanInterfaces, cfg.WanInterface.Name, listeningStr, wanInterfaceSet.IPv4Addr, cfg.PFRules)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go wanSniffer.Start(nat, fmt.Sprintf("ether src not %s", wanInterfaceSet.IfHWAddr)) // BPF filter to remove packets sent _from_ gonat
	for i, lanSource := range lanSources {
		wg.Add(1)
		go lanSource.Start(nat, fmt.Sprintf("ether src not %s", lansets[i].IfHWAddr)) // BPF filter to remove packets sent _from_ gonat
	}
	wg.Wait()
}

func getInterfaces(lan LanInterface) (source nat.Source, set nat.Interface) {
	lanIP, lanAddr, err := net.ParseCIDR(lan.Addr)
	if err != nil {
		log.Fatal().Err(err).Msgf("Bad addr for interface %v", lan)
	}

	source = nat.CreateSniffer(lan.Name, false)
	spitter1 := nat.CreateSpitter(lan.Name, false)
	if1Mac, err := common.GetMacAddr(lan.Name)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to find devices")
	}
	hw1, _ := net.ParseMAC(if1Mac)

	set = nat.Interface{IfName: lan.Name,
		IfHWAddr:    hw1,
		IPv4Addr:    lanIP,
		IPv4Netmask: lanAddr.Mask,
		IPv4Network: *lanAddr,
		NatEnabled:  true,
		DHCPEnabled: lan.DHCPOptions.Enabled,
		Callback:    spitter1,
		DHCPHandler: dhcp.NewDHCPHandler(lanIP, net.ParseIP(lan.DHCPOptions.Start), net.ParseIP(lan.DHCPOptions.DNS), *lanAddr, lan.DHCPOptions.Count),
	}

	for _, dhcpentry := range lan.StaticDHCPEntries {
		ip := net.ParseIP(dhcpentry.IP)
		hw, err := net.ParseMAC(dhcpentry.MAC)
		if err != nil || ip == nil {
			log.Fatal().Err(err).Msgf("Bad static dhcp entry %s:%s", dhcpentry.IP, dhcpentry.MAC)
		}
		err = set.DHCPHandler.AddEntry(hw, ip)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to add static dhcp entry")
		}
	}

	return

}
