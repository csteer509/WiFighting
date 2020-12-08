#!/usr/bin/python3

import csv

fields = ['MAC', 'Session_AP_Name', 'Year', 'Month', 'Date', 'Start_Time', 'End_Time', 'Unix_Start_Time', 'Unix_End_Time']

rows = []
mac = '00:00::11'
name = 'test'
time = 1

filename = "test.csv"
for x in range (0, 4):
	rows.append([mac, name, time, time+1, time+2, time+3, time+4, time+5, time+6])


with open(filename, 'w') as csvfile:
	csvwriter = csv.writer(csvfile)
	csvwriter.writerow(fields)
	csvwriter.writerows(rows)
