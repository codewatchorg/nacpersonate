#!/usr/bin/python
# Impersonate an OS based on TCP options
# josh.berry@codewatch.org
# 11/2014

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import re
import sys

if len(sys.argv) != 6 or sys.argv[1] is None or sys.argv[2] is None or sys.argv[3] is None or sys.argv[4] is None or sys.argv[5] is None:
  print '[x] Invalid Options'
  print '[x] Usage: python impersonate.py src_port dst_ip dst_port impersonate.os captive.portal\n'
  exit()

src_port = int(sys.argv[1])
dst_ip = sys.argv[2]
dst_port = int(sys.argv[3])

try:
  config=open(sys.argv[4])
except:
  print '[x] Couldn\'t open config file: '+sys.argv[4]+'\n'
  exit()

try:
  captive=open(sys.argv[5])
except:
  print '[x] Couldn\'t open captive portal data file: '+sys.argv[5]+'\n'
  exit()

tcp_flags = ''
tcp_urg = ''
tcp_ttl = ''
tcp_mss = ''
tcp_nop1 = ''
tcp_wscale = ''
tcp_nop2 = ''
tcp_nop3 = ''
tcp_ts1 = ''
tcp_ts2 = ''
tcp_sackok = ''
tcp_eol = ''
portal_data = ''
user_agent = ''
tcpopt = []

for line in config:
  if re.search('^IP_FLAGS=', line):
    ip_flags = line.split('=')[1].replace('\n', '').replace('\r', '')

    if re.search('[A-Z]', ip_flags) is None:
      ip_flags = ''

  if re.search('^TCP_URG_PTR=', line):
    tcp_urg = line.split('=')[1].replace('\n', '').replace('\r', '')

    if re.search('[0-1]', tcp_urg) is None:
      tcp_urg = 0
    else:
      tcp_urg = int(tcp_urg)

  elif re.search('^IP_TTL=', line):
    ip_ttl = line.split('=')[1].replace('\n', '').replace('\r', '')
    
    if re.search('[0-9]', ip_ttl) is None:
      ip_ttl = 64
    else:
      ip_ttl = int(ip_ttl)

  elif re.search('^TCP_MSS=', line):
    tcp_mss = line.split('=')[1].replace('\n', '').replace('\r', '')
    
    if re.search('[0-9]', tcp_mss) is None:
      tcpopt.append(("MSS", 1460))
    else:
      tcpopt.append(("MSS", int(tcp_mss)))

  elif re.search('^TCP_NOP1=', line):
    tcp_nop1 = line.split('=')[1].replace('\n', '').replace('\r', '')
    
    if re.search('^1$', tcp_nop1) is not None:
      tcpopt.append(("NOP", None))

  elif re.search('^TCP_WSCALE=', line):
    tcp_wscale = line.split('=')[1].replace('\n', '').replace('\r', '')
    
    if re.search('[0-9]', tcp_wscale) is not None:
      tcpopt.append(("WScale", int(tcp_wscale)))

  elif re.search('^TCP_NOP2=', line):
    tcp_nop2 = line.split('=')[1].replace('\n', '').replace('\r', '')
    
    if re.search('^1$', tcp_nop2) is not None:
      tcpopt.append(("NOP", None))

  elif re.search('^TCP_NOP3=', line):
    tcp_nop3 = line.split('=')[1].replace('\n', '').replace('\r', '')
    
    if re.search('^1$', tcp_nop3) is not None:
      tcpopt.append(("NOP", None))

  elif re.search('^TCP_TIMESTAMP1=', line):
    tcp_ts1 = line.split('=')[1].replace('\n', '').replace('\r', '')
    
    if re.search('[0-9]', tcp_ts1) is None:
      tcp_ts1 = None
    else:
      tcp_ts1 = int(tcp_ts1)

  elif re.search('^TCP_TIMESTAMP2=', line):
    tcp_ts2 = line.split('=')[1].replace('\n', '').replace('\r', '')
    
    if re.search('[0-9]', tcp_ts2) is not None and tcp_ts1 is not None:
      tcpopt.append(("Timestamp", (tcp_ts1, int(tcp_ts2))))

  elif re.search('^TCP_SACKOK=', line):
    tcp_sackok = line.split('=')[1].replace('\n', '').replace('\r', '')
    
    if re.search('^1$', tcp_sackok) is not None:
      tcpopt.append(("SAckOK", ""))

  elif re.search('^TCP_EOL=', line):
    tcp_eol = line.split('=')[1].replace('\n', '').replace('\r', '')

    if re.search('^1$', tcp_eol) is not None:
      tcpopt.append(("EOL", None))

  elif re.search('^USER_AGENT=', line):
    #user_agent = str(line.split('=')[1:])[2:-4].replace('\\\\', '\\')
    user_agent = line.split('=')[1:]

    if re.search('[a-zA-Z0-9]', line) is None:
      user_agent = ''

for line in captive:
  portal_data = portal_data + line

portal_data = portal_data.replace('DESTINATION_IP', dst_ip)
portal_data = portal_data.replace('USER_AGENT', user_agent[0][:-2])
portal_data = portal_data.replace('\\r', '\r').replace('\\n', '\n')
print portal_data

ip=IP(dst=dst_ip, flags=ip_flags, ttl=ip_ttl)
SYN=TCP(sport=src_port, dport=dst_port, flags="S", seq=10, window=0xffff, urgptr=tcp_urg, options=tcpopt)
SYNACK=sr1(ip/SYN)

ackback = SYNACK.seq + 1
ACK=TCP(sport=src_port, dport=dst_port, flags="A", seq=11, ack=ackback, window=0xffff)
send(ip/ACK)

PUSH=TCP(sport=src_port, dport=dst_port, flags="A", seq=11, ack=ackback, window=0xffff)
FINACK=sr1(ip/PUSH/portal_data)
