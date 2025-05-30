#!/bin/bash
# example firewall policy for Youpot https://github.com/sq5bpf/youpot
# (c) 2025 Jacek Lipkowski <sq5bpf@lipkowski.org>
# Licensed GPLv3: https://www.gnu.org/licenses/gpl-3.0.txt
#
# set to your external interface name
EXTERNAL_INTERFACE=ens192

LIMIT=""
# uncomment the next line if you get too much rejects in logs
#LIMIT="-m limit --limit 100/hour"

echo 0 > /proc/sys/net/ipv4/ip_forward
echo 0 > /proc/sys/net/ipv6/conf/all/forwarding
export PATH=$PATH:/sbin:/usr/sbin

/sbin/modprobe ip_nat_ftp
/sbin/modprobe ip_conntrack_ftp
iptables -F  INPUT
iptables -F  FORWARD
iptables -F -t nat
iptables -F -t mangle


iptables -A INPUT -j ACCEPT -m state --state ESTABLISHED,RELATED
iptables -A FORWARD -j ACCEPT -m state --state ESTABLISHED,RELATED

iptables -A INPUT -i lo -j ACCEPT
iptables -A FORWARD -i lo -j ACCEPT

# this is for openvpn, modify for whatever you're using
iptables -A INPUT -p udp --dport 1194 -j ACCEPT
iptables -A INPUT -i tun0 -j ACCEPT

# ports we dont handle for now
for i in 3389 1433 3650 5900
do
iptables -A INPUT -i $EXTERNAL_INTERFACE -p tcp --dport $i -j REJECT
iptables -t nat -A PREROUTING -i $EXTERNAL_INTERFACE -p tcp --dport $i -j ACCEPT
done

# iptables -A INPUT -i $EXTERNAL_INTERFACE -p tcp -s 1.2.3.4 -j ACCEPT
iptables -A INPUT -i $EXTERNAL_INTERFACE -p tcp -j ACCEPT

# youpot is listening on 65534/tcp, redirect all connections there
iptables -t nat -A PREROUTING -i $EXTERNAL_INTERFACE -p tcp -j REDIRECT --to-port 65534

iptables -A INPUT -m pkttype \! --pkt-type unicast -j DROP

iptables -A INPUT -j LOG --log-prefix "INPUT: " $LIMIT
iptables -A INPUT -j DROP
iptables -A FORWARD -j LOG --log-prefix "FORWARD: " $LIMIT
iptables -A FORWARD -j REJECT


# 2^32 addresses out to be enough for everybody --sq5bpf
ip6tables -F  INPUT
ip6tables -F  FORWARD
ip6tables -A INPUT -j ACCEPT -m state --state ESTABLISHED,RELATED
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A INPUT -j LOG --log-prefix "INPUT6: " $LIMIT
ip6tables -A INPUT -j DROP
ip6tables -A FORWARD -j LOG --log-prefix "FORWARD6: " $LIMIT
ip6tables -A FORWARD -j DROP
# we don't need this: #echo 1 > /proc/sys/net/ipv6/conf/all/forwarding


echo 1 > /proc/sys/net/ipv4/ip_forward


