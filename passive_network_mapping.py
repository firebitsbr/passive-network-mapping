# -*- coding: utf-8 -*-
'''Warning remover'''
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *


adressList=[] 

def readPacket(pkt):
	if pkt.haslayer(IP): # If our packet has an IP layer
		IPadress = pkt[IP].src # get IP adress (located in IP layer)
		MACadress = pkt[Ether].src # get MAC adress (located in Ether Layer)
		if IPadress not in adressList: 	# Then If IP never found before
			adressList.append(IPadress) # Add to our list
			print ('[+] Host Found\nMAC: ' + MACadress + ' | IP: '+ IPadress + '\n') # Print caracteristics


print('[+] Listening... \n')
sniff(prn=readPacket)
