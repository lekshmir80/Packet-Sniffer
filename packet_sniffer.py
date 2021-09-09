#!/usr/bin/python3
print("Use Sudo")
#Packet sniffer script using scapy
from datetime import datetime 
import sys
import subprocess #Create another processs
from scapy.all import *
from rich.console import Console

console = Console()


net_iface = str(sys.argv[1])

subprocess.call(["ifconfig",net_iface,"promisc"]) #creating another process to run command

num_of_pkt = int(sys.argv[2])

time_sec =int(sys.argv[3])

proto = str(sys.argv[4])

#sniff function call it and pass every packet in byte format
def logs(packet):
	print("__________________________________________________________________")
	#print(packet.show())
	console.print(f"SRC_MAC: {str(packet[0].src)} DEST_MAC: {str(packet[0].dst)} TYPE: {str(packet[0].type)}",style="bold red")
	console.print(f"psrc: {str(packet[1].psrc)} hwsrc: {str(packet[1].hwsrc)} pdst: {str(packet[1].pdst)}",style="bold blue")
	
if proto == "all":
	sniff(iface = net_iface ,count = num_of_pkt, timeout = time_sec, prn=logs ) #sniffing packet
elif proto == "arp" or proto == "icmp":
	sniff(iface = net_iface, count = num_of_pkt,timeout = time_sec , prn = logs , filter = proto) #sniffing packet
else:
	print("Wrong protocol")


