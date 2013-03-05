# TODO
# crap below... :/
# az egesz megoldas trocsok igy, kene bele olyan hogy
# * a target ip helyett tobb IPt/netet is meg lehessen adni -> ezt kirakom makroba
# * ne csak ICMP hanem tcp portot is lehessen adni, mondjuk ha a parameter ip:port
#   formaban van megadva akkor tcp portot csekkoljon, ha csak IP akkor ICMP
# * kurvajo lenne ha target_neten levo hostokon timestamp-fu-val li lehetne leakelni h milyen
#   neteket ismer, es azokra menne a target_ip/net scan... --> makro

import logging, sys
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb = 0
from pfu_arping import getmacs
from pfu_common import *


def main(target_net, target_ip):
    ret = gwscan_broadcast(target_net, target_ip)
    print ret

def usage():
    print "%s 192.168.1.0/24 8.8.8.8" % __name__

def gwscan_broadcast(t_net, t_ip):
    msg('gwscan for net %s, searching gw for %s' %(t_net, t_ip))
    lt = getmacs(t_net)
    #ans,unans = srp( Ether(dst='ff:ff:ff:ff:ff:ff') / IP(dst=target) / TCP(sport=11111, dport=80, flags="S"), timeout=1 )
    # broadcast mac, target ip, aki gw az tovabbdobja
    msg('pinging hosts: %s (broadcast mac)' % t_ip)
    ans,unans = srp( Ether(dst='ff:ff:ff:ff:ff:ff') / IP(dst=t_ip) / ICMP(), timeout=2 )
#    ans.show()
    ret = []
    for a in ans:
#	a[1].show()
	if a[1][ICMP].type == 0 and a[1][ICMP].code == 0:
	    mac = a[1][Ether].src
	    r_ip = a[1][IP].src
    	    ip = lt['mac_ip'][mac]
	    ret.append({
		'ttype':	'ping',
		'gw_mac':	mac,
		'gw_ip':	ip,
		'r_ip':		r_ip
#		't_ip':		t_ip
	    })
    msg('gwscan finished')
    return ret


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])