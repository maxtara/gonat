# GoNAT
  
## Description
  
Simple pure go implemenation of a NAT, using gopacket for packet parsing and network IO.
This could potentially work as a simple home NAT, if you have a seperate modem.
  
## Features / notes
  
  * UDP/TCP/IP NAT'ing
  * Port forwarding, via a simple YAML configuration file
  * Multiple LAN interfaces (same network, or different)
  * Routing between LAN interfaces
  * Single WAN interface
  * Optional DHCP server on each LAN interface, additionally can setup static IP entries
  * Mostly RFC compliant (details below)
  * Supports IPv4 only.
  * FTP not supported.
  * Fragmentation not supported.
    
## Development enviroment setup
  
My dev enviroment uses two LAN networks, one virtual 'veth' for simple testing, and a seperate network, which can *only* access the internet using the NAT. I run multiple VMs on that network.
    * eth1 is the WAN interface
    * eth2 is the LAN interface (connected to the VMs)
    * veth0/veth1 is the virtual network. The NAT side is veth1, the client side is veth0 - which gets an ip address.
  
```
# Create a virtual interface
ip link add veth0 type veth peer name veth1
# This will create 2 interfaces, veth0 and veth1. Think of them as 2 ends of a pipe. Any traffic sent into veth0 will come out veth1 and vice versa.

# Flush ips
ip addr flush dev eth2
ip addr flush dev eth1
ip addr flush dev veth1
ip addr flush dev veth0

# Turn off ipv6
sysctl -w net.ipv6.conf.default.disable_ipv6=1
sysctl -w net.ipv6.conf.all.disable_ipv6=1

# Turn off routing
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv4.conf.all.forwarding=0

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

ethtool -K eth2 tso off
ethtool -K eth2 gso off
ethtool -K eth2 gro off

ethtool -K veth1 tso off
ethtool -K veth1 gso off
ethtool -K veth1 gro off

ethtool -K veth0 tso off
ethtool -K veth0 gso off
ethtool -K veth0 gro off
```
  
### Speed test
  
```
# Add a route for speedtest.net get from ping speedtest.net. /16 - as it seems to change a bit
ip route add 151.101.0.0/16 via 10.0.0.1
# Add a route for the server - ping speedtest.yless4u.com.au
ip route add 103.22.144.0/24 via 10.0.0.1
# using YLess4U
speedtest-cli --server 37133 
# using Internode, for comparison
speedtest-cli --server 2166 
```
  
### Latency test
  
```
ip route add 8.8.8.8/8 via 10.0.0.1
ping 1.1.1.1 -n  -f  -c 100; ping 8.8.8.8 -n  -f  -c 100 
```
  
#### Possible Next features
  
  * DNS
  * Upnp
  * port knocking
  * Timeout ARP entries
  
# RFC compliance
  
## rfc4787
  * REQ-1 : Done
  * REQ-2 : Done
  * REQ-3 : Done 
  * REQ-3b: Done 
  * REQ-4 : Done
  * REQ-5 : Done
  * REQ-6 : Done
  * REQ-7 : Done
  * REQ-8 : Done
  * REQ-9 : Done
  * REQ-10: Done 
  * REQ-11: Done
  * REQ-12: Done
  * REQ-13: Done
  * REQ-14: TODO - IP Fragementation. 
  
## rfc5382. Some of these are not included, as they are identical to those in rfc4787.
  * REQ-2 : Done
  * REQ-3 : Done
  * REQ-4 : Done 
  * REQ-5 : Done
  * REQ-6 : Done, except for FTP.
  * REQ-9 : TODO: SHOULD translate Unreachable (Type 3) messages.
  * REQ-10: Done
  
## rfc5508. Some of these are not included, as they are identical to those in rfc4787/rfc5382
  * REQ-1    : Done
  * REQ-2    : Done
  * REQ-3    : N/a. I think this is left to gopacket.
  * REQ-4    : TODO, Mostly done via gopacket, will be done once below REQ5 is done i think.
  * REQ-5    : TODO, un-nat layer 4 ICMP Error packet
  * REQ-6    : Done. 
  * REQ-7    : TODO - Hairpin ICMP, and ICMP error packet contents
  * REQ-8    : N/a
  * REQ-9    : Done.
  * REQ-10a1 : Fragmentation, todo (maybe)
  * REQ-10a2 : Done
  * REQ-10b/d: TODO, lots of ICMP messages
  * REQ-11   : Done