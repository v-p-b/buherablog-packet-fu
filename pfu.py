#!/usr/bin/python

import logging, time, sys, inspect
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)	# prevent scapy warnings for ipv6
from scapy import all as scapy

scapy.conf.verb = 0

# Our helper logger class
class logger:
	def __init__(self):
		self.color = {  "mod": '\033[90m', "msg": '\033[94m',
				"err": '\033[91m', "end": '\033[0m' }

	def __pfu_out(self, msg, msgcolor):
		mod = []
		for fr in reversed(inspect.stack()[1:-1]):
			mod.append(fr[3])
		print self.color["mod"] + '.'.join(mod) +' > '+ msgcolor + str(msg) + self.color["end"]

	def msg(self, msg): self.__pfu_out(msg, self.color["msg"])
	def err(self, msg): self.__pfu_out(msg, self.color["err"])

# global logger instance
log = logger()

# getmacs mixin
class GetMacsMixin:
	def getmacs(self, target):
		ret = {'ip_mac': {}, 'mac_ip': {}}
		log.msg('arping in progress')
		ans,unans = scapy.arping(target)
		log.msg('finished')
		for a in ans:
#			a[1].show()
			mac = a[1][scapy.ARP].hwsrc
			ip = a[1][scapy.ARP].psrc
			if mac in ret['mac_ip']:
				ret['mac_ip'][mac].append(ip)
			else:
				ret['mac_ip'][mac] = [ip]
			ret['ip_mac'][ip] = mac
		return ret

# rr module
class rr:
	def __init__(self, params):
		self.do_icmp = False

		textparams = filter(lambda x: x != "-i", params)
		if len(textparams) < 2:
			self.usage()
			exit(1)

		if "-i" in params:
			self.do_icmp=True

		self.dst = textparams[0]
		self.dport = textparams[1]

	def usage(self):
		print "Usage: %s rr [-i] <IP> <tcpport>" % sys.argv[0]
		print "\t -i\tdo ICMP RR"

	def start(self):
		if self.do_icmp == 1:
			icmprr = self.rr_icmp(self.dst)
			log.msg("icmp route: %s" % icmprr)
		tcprr = self.rr_tcp(self.dst, self.dport)
		log.msg("tcp route: %s" % tcprr)

	def rr_icmp(self, dst):
		pkt = scapy.IP(dst=dst, proto=1, options=scapy.IPOption('\x01\x07\x27\x04' + '\x00'*36))
		pkt /= scapy.ICMP()
		intr_icmp = scapy.sr1(pkt, timeout=2)
		if intr_icmp is not '':
			return intr_icmp.options[0].routers

	def rr_tcp(self, dst, dport):
		pkt = scapy.IP(dst=dst, proto=6, options=scapy.IPOption('\x01\x07\x27\x04' + '\x00'*36))
		pkt/= scapy.TCP(sport=scapy.RandNum(1024,65535), dport=int(dport), flags="S",window=8192,
				options=[('MSS', 1460), ('NOP', None), ('WScale', 2), ('NOP', None),
					 ('NOP', None), ('SAckOK', '')])
		intr_tcp = scapy.sr1(pkt, timeout=2)
		if intr_tcp is not None:
			return intr_tcp.options[0].routers

# gwscan module
class gwscan(GetMacsMixin):
	def __init__(self, params):
		if len(params) != 2:
			self.usage()
			exit(1)

		self.net = params[0]
		self.ip = params[1]

	def usage(self):
		print "Usage:"
		print "\t%s gwscan <target_net> <target_ip>" % sys.argv[0]
		print "example:"
		print "\t%s gwscan 192.168.1.0/24 8.8.8.8" % sys.argv[0]

	def start(self):
		ret = self.gwscan_broadcast(self.net, self.ip)
		for x in ret:
			print "%18s %16s" % (x['gw_mac'], x['gw_ip'])

	def gwscan_broadcast(self, net, ip):
		log.msg('gwscan for net %s, searching gw for %s' %(net, ip))
		lt = self.getmacs(net)
#		ans,unans = scapy.srp(scapy.Ether(dst='ff:ff:ff:ff:ff:ff') / scapy.IP(dst=ip) / scapy.TCP(sport=11111, dport=80, flags="S"), timeout=1)
#		ans,unans = scapy.srp(scapy.Ether(dst='ff:ff:ff:ff:ff:ff') / scapy.IP(dst=ip) / scapy.ICMP(), timeout=2)
		ans,unans = scapy.srp(scapy.Ether(dst=lt['mac_ip'].keys()) / scapy.IP(dst=ip) / scapy.ICMP(), timeout=2)
#		ans.show()
		ret = []
		for a in ans:
#			a[1].show()
			if a[1][scapy.ICMP].type == 0 and a[1][scapy.ICMP].code == 0:
				mac = a[1][scapy.Ether].src
				r_ip = a[1][scapy.IP].src
				ip = lt['mac_ip'][mac]
				ret.append({
					'ttype':	'ping',
					'gw_mac':	mac,
					'gw_ip':	ip,
#					'r_ip':		r_ip
#					't_ip':		t_ip
				})
		log.msg('gwscan finished')
		return ret

# arping module
class arping(GetMacsMixin):
	def __init__(self, params):
		if len(params) != 1:
			self.usage()
			exit(1)
		self.target = params[0]

	def usage(self):
		print "Usage:"
		print "\t%s arping <target>" % sys.argv[0]

	def start(self):
		tab = self.getmacs(self.target)
		print 'IP: MAC'
		for ip in tab['ip_mac']:
			print " ", ip, tab['ip_mac'][ip]
		print 'MAC: IP'
		for mac in tab['mac_ip']:
			print " ", mac, " ".join(tab['mac_ip'][mac])


if __name__ == "__main__":
	modulenames = ["rr", "gwscan", "arping"]
	if len(sys.argv) < 2 or sys.argv[1] not in modulenames:
		print sys.argv[0],"modulename"
		print "modulenames:", ", ".join(modulenames)
		exit(1)

	if   sys.argv[1] == "rr":
		module = rr(sys.argv[2:])
	elif sys.argv[1] == "gwscan":
		module = gwscan(sys.argv[2:])
	elif sys.argv[1] == "arping":
		module = arping(sys.argv[2:])
	module.start()
