#!/usr/bin/python

import logging, time, sys, getopt
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy import all as scapy
scapy.conf.verb = 0
from pfu_common import msg,err

def usage():
    print "Usage: %s [-i] <IP> <tcpport>" % sys.argv[0]
    print "\t -i\tdo ICMP RR"

def main(dst, port, do_icmp):
    if do_icmp == 1:
	icmprr = rr_icmp(dst)
	msg("icmp route: %s" % icmprr)
    tcprr = rr_tcp(dst, port)
    msg("tcp route: %s" % tcprr)


def rr_icmp(dst):
    pkt = scapy.IP(dst=dst, proto=1, options=scapy.IPOption('\x01\x07\x27\x04' + '\x00'*36))
    pkt/= scapy.ICMP()
    intr_icmp = scapy.sr1( pkt, timeout=2 )
    if (intr_icmp is not ''):
        return intr_icmp.options[0].routers
    return None

def rr_tcp(dst, port):
    pkt = scapy.IP(dst=dst, proto=6, options=scapy.IPOption('\x01\x07\x27\x04' + '\x00'*36))
    pkt/= scapy.TCP(sport=scapy.RandNum(1024,65535), dport=int(dport), flags="S", window=8192, options=[('MSS', 1460), ('NOP', None), ('WScale', 2), ('NOP', None), ('NOP', None), ('SAckOK', '')])
    intr_tcp = scapy.sr1( pkt, timeout=2 )
    if (intr_tcp is not None):
	return intr_tcp.options[0].routers
    return None

if __name__ == "__main__":
    try:
	opt, args = getopt.getopt(sys.argv[1:], 'i')
	do_icmp = 0
	for o,v in opt:
	    if o == '-i':
		do_icmp = 1
	dst = args[0]
	dport = args[1]
    except IndexError:
        usage()
        exit(1)
    main(dst, dport, do_icmp)

