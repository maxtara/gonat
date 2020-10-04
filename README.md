# GoNAT

## Notes
```
# Create a virtual interface
ip link add veth0 type veth peer name veth1
# This will create 2 interfaces, veth0 and veth1. Think of them as 2 ends of a pipe. Any traffic sent into veth0 will come out veth1 and vice versa.

# Configure interface
ifconfig veth0 10.0.0.2 netmask 255.0.0.0 up
ifconfig veth1 up

# Set up routing through the interface. Starting with just *some* traffic
ip route add 8.8.8.8/32 via 10.0.0.1

# Turn off all the gso/tso/gro
ethtool -K eth0 tso off
ethtool -K eth0 gso off
ethtool -K eth0 gro off

ethtool -K eth1 tso off
ethtool -K eth1 gso off
ethtool -K eth1 gro off

ethtool -K veth1 tso off
ethtool -K veth1 gso off
ethtool -K veth1 gro off

ethtool -K veth0 tso off
ethtool -K veth0 gso off
ethtool -K veth0 gro off

```

## Iptables rules
```
iptables -F
iptables -I OUTPUT -d 0.0.0.0/0 -j ACCEPT

iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -s 0.0.0.0/0 -d 0.0.0.0/0 -j ACCEPT
iptables -A INPUT  -i veth0  -j ACCEPT
iptables -A INPUT  -i veth1  -j ACCEPT


iptables -A INPUT -j LOG --log-prefix "INPUT:DROP:" --log-level 6

iptables -A INPUT -j DROP
```

### Plans
  * First version
    * One interface to NAT from (no hairpinning). Has an IP address on the interface. Replies to pings and arp requests.
    * One interface to NAT to, using the already configured interface..

### Speed test
```
# Add a route for speedtest.net get from ping speedtest.net. /16 - as it seems to change a bit
ip route add 151.101.0.0/16 via 10.0.0.1
# Add a route for the server - ping speedtest.yless4u.com.au
ip route add 103.22.144.0/24 via 10.0.0.1
speedtest-cli --server 37133 # using YLess4U
speedtest-cli --server 2166 # using Internode CBR

```

### Latency test
```
ip route add 8.0.0.0/8 via 10.0.0.1
ping 1.1.1.1 -n  -f  -c 100; ping 8.8.8.8 -n  -f  -c 100 

```

#### TODO next
```
Change TCP ports
DNS?
ipv6? ipv6 only?
no serialisation?
Lazy? I dont really want to parse the other layers - or is that only on print
```