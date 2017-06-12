#!/usr/bin/python

#demo -- For CDR Tom
#modular -- Allows for custom taps to be set, depending on the input from the database

#Client program for the tap hosts

  # Connect to Database Server
  # Start/stop scapy.sniff on command
# Set up connection with database and transfer .cap file.

import socket
from scapy.all import *
import threading
from ftplib import FTP

tap_ip = 'localhost'
tap_name = 'default'
tap_interface_count = 0
tap_interfaces = {}

collect_packets = True
name = '-1'
dump_thread = None
interfaces_to_tap = []

def get_file_name (interface):
	return "./Collected_Data/"+name+"-"+interface+".pcap"

def thread_dump ():
	print("Dumping into: ")
	for iface in interfaces_to_tap:
		print("\t"+get_file_name(iface))
	while (collect_packets):
		#Each sniff() function call blocks until it reads in a packet.
		#That means that while one interface waits for a new packet,
			# another interface might skip a packet before a new
			# sniff call can take it down.
		#Solutions:
			# Timeout in sniff()
			# Multiple threads, though it is probably unnecessary
		for iface in interfaces_to_tap:
			file_name = get_file_name(iface)
			#Tranlsate ECDIS or RADAR into 'eth0' or 'eth2'
			network_interface = tap_interfaces[iface]
			pkts = sniff(iface=network_interface, count=1)
			wrpcap (file_name, pkts, append=True)

def start():
	dump_thread = threading.Thread(target=thread_dump)
	dump_thread.start()
	print ("Started dump thread")
	return dump_thread

def stop(dump_thread):
	global collect_packets
	collect_packets = False
	dump_thread.join()
	print("Stopped dump thread")

def send(ftp_client, database_ip):
	print("Received send cmd")

	#Change to 'test_name' directory
	ftp.cwd(name)

	for iface in tap_interfaces:
		
		#Open pcap file
		iface_file = open(get_file_name(iface), 'rb')
	
		#Pass the opened pcap file to the ftp server
		print(ftp.storbinary('STOR '+tap_name+'-'+iface+'.pcap', iface_file))
		iface_file.close()
	
	#Return to parent directory
	ftp.cwd('..')

#-------Read in config file-------#
config_file = open('./taphost.config','r')

tap_ip = config_file.readline().rstrip()
tap_name = config_file.readline().rstrip()
tap_interface_count = int(config_file.readline())
for i in range(tap_interface_count):
	interface = config_file.readline().rstrip().split(':')
	tap_interfaces[interface[1]] = interface[0]

print tap_ip
print tap_name
print tap_interface_count
print tap_interfaces

#---Main Program----#

listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
print("Created new socket")

listen_socket.bind((tap_ip,2000))
print("Bound to port 2000")
listen_socket.listen(5)

#Listen for database connections
while 1:
	print("Waiting for client database")
	database_client, database_address = listen_socket.accept()
	print("Connected: ",database_address)
	database_ip = database_address[0]

	collect_packets = True
	
	ftp = FTP(database_ip)
	print("Connected to ftp server")
	#Login with arbitrary credentials
	print(ftp.login('ccw06','ccw06ccw06'))
	ftp.cwd('Experiments')
	ftp.cwd('..')
	ftp.cwd('Experiments')

	quit = False
	while not quit:
		ex_or_query = database_client.recv(512)
		print "Received command from database: "+ex_or_query

		#Transfer Taphost config file to database
		if (ex_or_query == 'query'):
			# Send tap data
			tap_data = tap_name
			tap_data += ':'+tap_ip
			for name, iface in tap_interfaces.iteritems():
				tap_data += ':'+name
			database_client.send(tap_data)
			print "Sent tap data to database: "+tap_data

		#Run an experiment
		elif (ex_or_query == 'ex'):
			print ("Running test")

			name = database_client.recv(512)
			print("Test name: "+name)
			
			#Clear interfaces_to_tap
			del interfaces_to_tap[:]
			interfaces_to_tap = ['ETH0','ETH2']

#			cmd = database_client.recv(512)
#			while cmd != 'done':
#				print("Tapping interface: "+cmd)
#				interfaces_to_tap.append(cmd)
#				cmd = database_client.recv(512)

			cmd = 'no start'
			while cmd != 'start':
				print ("Received: "+cmd+" instead of start command")
				cmd = database_client.recv(512)
			thrd = start()

			cmd = 'no stop'
			while cmd != 'stop':
				print ("Received: "+cmd+" instead of send command")
				cmd = database_client.recv(512)
			stop(thrd)

			cmd = 'no send'
			while cmd != 'send':
				print ("Received: "+cmd+" instead of start command")				
				cmd = database_client.recv(512)
			send(ftp, database_address[0])
		
		elif (ex_or_query == 'quit' or ex_or_query == ''):
			print "Closing database connection"
			quit = True
		else:
			print "invalid command: "+ex_or_query
	ftp.close()
	database_client.close()
