#!/usr/bin/python3

from macsniffer import *
from wifi import *
from datetime import *
from time import *
# from xlwt import * Seems like a good module for porting to excel

# Variables below should be changed as necessary
source_interface = ''
wifi_name = ''
wifi_mac = ''

''' Code below sniffs surrounding area for MAC addresses '''
print('Just one moment, collecting MAC addresses...')
sniffer = MACSniffer()
sniffer.sniffProbes(iface=source_interface, count=1000)
umacs = sniffer.getUniqueMACs()
print('Unique MAC addresses found: ')
print(umacs)

''' Code below iterates over unique MAC list, associates each with given Wifi, and then checks status field of connection to ensure that connection was successful '''
wifi = Wifi()
connected_macs = []
for mac in umacs:
	print('Associating MAC address ' + mac + '...')
	answer = wifi.connect(wifi_name, mac, wifi_mac, source_interface)
	if (answer is None):
		print('Connection unsuccessful with MAC ' + mac)
		continue
	layer = (answer.getlayer(scapy.layers.dot11.Dot11AssoResp, nb=1, _track=None, _subclass=None))
	if (layer.fields['status'] == 0):
		print('Success - Status code: 0')
		connected_macs.append(mac)
	else:
		print('Error - Status code: ' + layer.fields['status'])

print('----------------')
print('Output for WifiTrace: ')
for mac in connected_macs:
	print('MAC of spoofed device: ' + mac)
	print('AP Name: ' + wifi_name)
	print('Year: ' + strftime('%Y', gmtime()))
	print('Month: ' + strftime('%b', gmtime()))
	print('Date: ' + strftime('%m-%d', gmtime()))
	print('Start Time: ' + strftime('%H:%M', gmtime()))
	print('End Time: ' + strftime('%H:%M', gmtime())) #This will have to be changed
	print('Unix Start: ' + str(int(time())))
	print('Unix End: ' + str(int(time()))) #This will also have to change
	print('----------------------------')

		
'''
Random shit that I used throughout this process, some of which even works!
~~~ Mostly bad stuff
answer.show2(dump=False, indent=3, lvl='', label_lvl='')
print(answer.layers())
print(answer.getlayer(scapy.layers.dot11.Dot11AssoResp, nb=1, _track=None, _subclass=None).getFieldVal('status'))
layer = answer.getlayer(scapy.layers.dot11.Dot11AssoResp, nb=1, _track=None, _subclass=None)
fields = layer.field()
print(fields)
print(answer.getfield(answer, 'status'))
~~~ Good stuff below
layer = (answer.getlayer(scapy.layers.dot11.Dot11AssoResp, nb=1, _track=None, _subclass=None))
print(layer.fields["status"])
'''
