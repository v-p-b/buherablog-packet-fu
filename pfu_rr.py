#!/usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import time
from scapy.all import *
import sys
conf.verb = 0
import getopt
from pfu_common import *

def usage():
    print "Usage: %s [-i] <IP> <tcpport>" % sys.argv[0]
    print "\t -i\tdo ICMP RR"

opt,args = getopt.getopt(sys.argv[1:], 'i')
try:
    dst = args[0]
    dport = args[1]
except:
    usage()
    exit(1)

do_icmp = 0
for o,v in opt:
    if o == '-i':
	do_icmp = 1

if do_icmp == 1:
    intr_icmp = sr1(IP(dst=dst, proto=1, options=IPOption('\x01\x07\x27\x04' + '\x00'*36)) / ICMP())
    if (intr_icmp is not ''):
        msg("icmp route: %s" % intr_icmp.options[0].routers)


intr_tcp = sr1(IP(dst=dst, proto=6, options=IPOption('\x01\x07\x27\x04' + '\x00'*36)) / TCP(sport=12342, dport=int(dport), flags="S", window=8192, options=[('MSS', 1460), ('NOP', None), ('WScale', 2), ('NOP', None), ('NOP', None), ('SAckOK', '')]))
#intr_tcp = sr1(IP(dst=dst, proto=6, options=IPOption('\x01\x07\x27\x04' + '\x00'*36)) / TCP(sport=12342, dport=int(dport), flags="S", options=[('MSS',1460),('WScale',2)]))
#intr_tcp = sr1(IP(dst=dst, proto=6, options=IPOption('\x01\x07\x27\x04' + '\x00'*36)) / TCP(sport=12342, dport=int(dport), window=5840, flags="S"))
if (intr_tcp is not ''):
    msg(" tcp route: %s" % intr_tcp.options[0].routers)


