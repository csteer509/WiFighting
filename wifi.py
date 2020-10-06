#!/usr/bin/python3

from scapy.all import *

class Wifi:

	def connect(SSID, srcMAC, dstMAC, iface):
		essid = Dot11Elt(ID='SSID', info=SSID)/Dot11Elt(ID='Rates', info='\x82\x84\x8b\x96\x0c\x12\x18')/Dot11Elt(ID='ESRates', info='\x30\x48\x60\x6c')
		
		probe = Dot11(type=0, subtype=4, addr1=dstMAC, addr2=srcMAC, addr3=dstMAC)/Dot11ProbeReq()

		probeRequest = RadioTap()/probe/essid

		probeResponse = srp1(probeRequest, iface=iface)
		probeResponse.show()

		authentication = Dot11(type=0, subtype=11, addr1=dstMAC, addr2=srcMAC, addr3=dstMAC)/Dot11Auth(algo=0, seqnum=1, status=0)

		authenticationRequest = RadioTap()/authentication

		authenticationResponse = srp1(authenticationRequest, iface=iface)
		authenticationResponse.show()

		association = Dot11(type=0, subtype=0, addr1=dstMAC, addr2=srcMAC, addr3=dstMAC)/Dot11AssoReq(cap=0x1100, listen_interval=0x00a)

		associationRequest = RadioTap()/association/essid

		associationResponse = srp1(associationRequest, iface=iface)
		associationResponse.show()
