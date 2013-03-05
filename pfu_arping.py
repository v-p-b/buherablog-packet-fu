import logging, sys
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb = 0
from pfu_common import *


def main(target):
    tab = getmacs(target)
    print '___IP : MAC'
    print tab['ip_mac']
    print '___MAC : IP'
    print tab['mac_ip']

def getmacs(target):
    ret = {'ip_mac':{}, 'mac_ip':{}}
    msg('arping in progress')
    ans,unans = arping(target)
    msg('yea, its finishd')
    for a in ans:
#	a[1].show()
	mac = a[1][ARP].hwsrc
	ip = a[1][ARP].psrc
	if mac in ret['mac_ip']:
	    ret['mac_ip'][mac].append(ip)
	else:
	    ret['mac_ip'][mac] = [ip]
	ret['ip_mac'][ip] = mac
    return ret

if __name__ == "__main__":
    main(sys.argv[1])

