#!/usr/bin/python3

from scapy.all import *

class MACSniffer:

	def __init__(self):
		self.macs = []

	def handleProbes(self, pkt):
		if pkt.haslayer(Dot11):
			if pkt.type == 0 and pkt.subtype == 4:
				self.macs.append(pkt.addr2)

	#Count is the total number of packets to sniff before stopping. Not the number of probe requests to sniff before stopping
	def sniffProbes(self, iface, count = 60):
		sniff(iface=iface, prn=self.handleProbes, count=count)
		
	def getMACs(self):
		return self.macs
		
	def getUniqueMACs(self):
		uniqueMACS = []
		for x in self.macs:
			if x not in uniqueMACS:
				uniqueMACS.append(x)
		return uniqueMACS
