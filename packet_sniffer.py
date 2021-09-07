#!/usr/bin/python3
print("Use Sudo")
#Packet sniffer script using scapy
from datetime import datetime 
import sys
import subprocess #Create another processs
from scapy.all import *

net_iface = input("Enter interface name: ")

subprocess.call(["ifconfig",net_iface,"promisc"]) #creating another process to run command

num_of_pkt = int(input("Enter the packet count you want to capture"))

time_sec =int(input("Enter the time how long(in sec) run to capture"))

proto = input("Enter the protocol(arp | icmp |all)")

#sniff function call it and pass every packet in byte format
def logs(packet):
	print("__________________________________________________________________")
	#print(packet.show())
	print(f"SRC_MAC: {str(packet[0].src)} DEST_MAC: {str(packet[0].dst)} TYPE: {str(packet[0].type)}")
	print(f"psrc: {str(packet[1].psrc)} hwsrc: {str(packet[1].hwsrc)} pdst: {str(packet[1].pdst)}")
	
if proto == "all":
	sniff(iface = net_iface ,count = num_of_pkt, timeout = time_sec, prn=logs ) #sniffing packet
elif proto == "arp" or proto == "icmp":
	sniff(iface = net_iface, count = num_of_pkt,timeout = time_sec , prn = logs , filter = proto) #sniffing packet
else:
	print("Wrong protocol")


