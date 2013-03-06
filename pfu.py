#!/usr/bin/python

import logging, time, os, sys, inspect, socket, nfqueue
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
		print "\t%s gwscan <local_subnet> <target_ip/net>" % sys.argv[0]
		print "examples:"
		print "\t%s gwscan 192.168.1.0/24 8.8.8.8" % sys.argv[0]
		print "\t%s gwscan 192.168.1.0/24 10.0.0.0/24" % sys.argv[0]

	def start(self):
		ret = self.gwscan_icmp(self.net, self.ip)
		for x in ret:
			print "%18s %16s %16s" % (x['gw_mac'], x['gw_ip'], x['r_ip'])

	def gwscan_icmp(self, net, ip):
		log.msg('gwscan for net %s, searching gw for %s' %(net, ip))
		lt = self.getmacs(net)
		#ans,unans = scapy.srp(scapy.Ether(dst='ff:ff:ff:ff:ff:ff') / scapy.IP(dst=ip) / scapy.ICMP(), timeout=5)
		pkt = scapy.Ether(dst=lt['mac_ip'].keys())
		pkt/= scapy.IP(dst=ip)
		pkt/= scapy.ICMP()
		ans,unans = scapy.srp( pkt, timeout=5)
		ret = []
		for b in ans:
			for a in b[1]:
				if a[scapy.ICMP].type == 0 and a[scapy.ICMP].code == 0:
					mac = a[scapy.Ether].src
					r_ip = a[scapy.IP].src
					ip = lt['mac_ip'][mac]
					ret.append({
						'ttype':	'ping',
						'gw_mac':	mac,
						'gw_ip':	ip,
						'r_ip':		r_ip
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

# flagfuzzer
class flagfuzzer:
	def __init__(self, params):
		if len(params) != 2:
			self.usage()
			exit(1)
		self.dst = params[0]
		self.port = int(params[1])

	def usage(self):
		print "Usage:"
		print "\t%s flagfuzzer <target_ip> <port>" % sys.argv[0]

	def start(self):
		self.flagfuzzer(self.dst, self.port)
	
	def flagfuzzer(self, dst, port):
		r = {
			'R':[],		# RST
			'RA':[],	# RST-ACK
			'SA':[],	# SYN-ACK
			'--':[],	# no response
			'??':[]		# ICMP error msgs (?)
		}
		scanflags = ['','F','S','FS','R','RF','RS','RSF','A','AF','AS','ASF','AR','ARF','ARS','ARSF']
		for flagval in scanflags:
			pkt = scapy.IP(dst=dst)
			pkt/= scapy.TCP(dport=port, sport=scapy.RandNum(1024,65535), flags=flagval)
			x = scapy.sr1( pkt, timeout=.5)
			sys.stderr.write(" %s \r" % flagval)
			sent = pkt.sprintf("%TCP.flags%")
			if sent == '':
				sent = '-'
			if x is not None:
				recvd = x.sprintf("%TCP.flags%")
				#self.r[recvd].append(sent+"."+str(x[scapy.IP].ttl))
				r[recvd].append(sent)
			else:
				r['--'].append(sent)
		log.msg("finished")
		del r['--']
		for k in r.keys():
			log.msg("%4s: %s" % (k, " ".join(r[k])))


class synfinfu:
	def __init__(self, params):
		if len(params) != 2:
			self.usage()
			exit(1)
		self.ip = params[0]
		self.port = int(params[1])

	def usage(self):
		print "Usage:"
		print "\t%s synfinfu <ip> <port>" % sys.argv[0]

	def start(self):
		self.synfinfu(self.ip, self.port)
	
	def synfinfu(self, ip, port):
		# modprobe nfnetlink_queue
		# apt-get install nfqueue-bindings-python python-netfilter
		#
		# current pid will be the queue_id 
		qid = os.getpid()
		log.msg("NFQueue ID: %d" % qid)

		# we gonna set up the queue
		nfq = nfqueue.queue()
		nfq.open()
		try:
			nfq.bind(socket.AF_INET)
		except RuntimeError as rte:
			log.err("umm... %s ... maybe nfqueue.unbind() wasn't successful last time... :/" % rte)
			log.err("try this: rmmod nfnetlink_queue; modprobe nfnetlink_queue")
			exit(1)
		nfq.set_callback(self.__synfin)
		nfq.create_queue(qid)
		log.msg("NFQueue up")
		# we need the rules
		# I tried to use python-netfilter but its undocumented
		# finally I figured out how to use but just cant use together with nfqueue
		os.system("iptables -A OUTPUT -p tcp --tcp-flags ALL SYN -d %s --dport %d -j NFQUEUE --queue-num %d" % (ip, port, qid))
		os.system("iptables -A OUTPUT -p tcp --tcp-flags ALL SYN -d %s --dport %d -j DROP" % (ip, port))
		log.msg("iptables rules up")
		log.msg("now you can try to connect to %s:%d with your favourite client" % (ip, port))
		# os.system("iptables -L OUTPUT")
		try:
			nfq.try_run()
		except KeyboardInterrupt:
			log.msg("kbd interrupt... ")
			os.system("iptables -D OUTPUT -p tcp --tcp-flags ALL SYN -d %s --dport %d -j NFQUEUE --queue-num %d" % (ip, port, qid))
			os.system("iptables -D OUTPUT -p tcp --tcp-flags ALL SYN -d %s --dport %d -j DROP" % (ip, port))
			log.msg("iptables rules down")
			nfq.unbind(socket.AF_INET)
			nfq.close()
			log.msg("NFQueue down")
			exit(1)

	def __synfin(self, i, payload):
		data = payload.get_data()
		p = scapy.IP(data)
		p[scapy.TCP].flags = "SF"
		del p[scapy.IP].chksum
		del p[scapy.TCP].chksum
		p = p.__class__(str(p))
		scapy.send(p);






if __name__ == "__main__":
	modulenames = ["rr", "gwscan", "arping", "flagfuzzer", "synfinfu"]
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
	elif sys.argv[1] == "flagfuzzer":
		module = flagfuzzer(sys.argv[2:])
	elif sys.argv[1] == "synfinfu":
		module = synfinfu(sys.argv[2:])
	module.start()



