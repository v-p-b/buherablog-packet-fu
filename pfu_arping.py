import logging, sys
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb = 0
from pfu_common import *


def main(target):
	tab = getmacs(target)
	print '___IP : MAC'
	for ip in tab['ip_mac']:
		print ip, tab['ip_mac'][ip]
	print '___MAC : IP'
	for mac in tab['mac_ip']:
		print mac, " ".join(tab['mac_ip'][mac])

def getmacs(target):
	ret = {'ip_mac':{}, 'mac_ip':{}}
	msg('arping in progress')
	ans,unans = arping(target)
	msg('finished')
	for a in ans:
#		a[1].show()
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

