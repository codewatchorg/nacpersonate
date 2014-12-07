#!/bin/sh
# Sample Apple MAC: f8:1e:df:4a:6c:e3

/sbin/ifconfig $1 down
/sbin/ifconfig $1 hw ether $2
/sbin/ifconfig $1 up
/sbin/iptables -A OUTPUT -p tcp --destination-port 80 --tcp-flags RST RST -j DROP
/sbin/iptables -A OUTPUT -p tcp --destination-port 443 --tcp-flags RST RST -j DROP
