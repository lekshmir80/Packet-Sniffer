#Packet sniffer script using scapy
from datetime import datetime 
import sys
from time import sleep
import os
import subprocess #Create another processs
from scapy.all import *
from rich.console import Console
from rich.text import Text

def gprint(string): 
	console.print(Text(string,style="bold green"))
def yprint(string): 
	console.print(Text(string,style="bold yellow"))	
def rprint(string): 
	console.print(Text(string,style="bold red"))	
	
console = Console()

net_iface = str(sys.argv[1])

subprocess.call(["ifconfig",net_iface,"promisc"]) #creating another process to run command

num_of_pkt = int(sys.argv[2])

time_sec =int(sys.argv[3])

proto = str(sys.argv[4])
gprint("Use Sudo")
gprint("Wait...................................")
#sleep(1)
def logs(packet):
	console.print("__________________________________________________________________",style = "green")
	yprint(f"SRC_MAC: {str(packet[0].src)} DEST_MAC: {str(packet[0].dst)} TYPE: {str(packet[0].type)}")

	
if proto == "all":
	sniff(iface = net_iface ,count = num_of_pkt, timeout = time_sec, prn=logs ) #sniffing packet
elif proto == "arp" or proto == "icmp" or proto == "tcp" or proto =="udp" or proto == "http" or proto == "igmp" or proto == "ip" or proto == "dns":
	sniff(iface = net_iface, count = num_of_pkt,timeout = time_sec , prn = logs , filter = proto) #sniffing packet
else:
	rprint("Wrong protocol")

