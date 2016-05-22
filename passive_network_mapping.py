# -*- coding: utf-8 -*-

'''Warning remover'''
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *



adressList=[] 

def list(adressList): 
	def readPacket(pkt):
		IPadress = pkt[IP].src # for every packet, get IP adress
		MACadress = pkt.src # for every packet, get MAC adress
		if IPadress not in adressList: 	# If IP never found before
			adressList.append(IPadress) # Add to our list
			print ('Found ' + MACadress + ' : '+ IPadress) # Print caracteristics
	return readPacket


print('[+] Listening... \n')
sniff(filter='arp', prn=list(adressList))
