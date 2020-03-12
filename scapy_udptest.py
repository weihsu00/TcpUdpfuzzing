from scapy.all import *
from argparse import ArgumentParser
import socket
import time
import random
import sys
import os

class UdpSend():

	def __init__(self, dstip, srcip, dstport, srcport):
		self.src = srcip
		self.dst = dstip
		self.sport = srcport
		self.dport = dstport
		self.ipheader = IP(dst=self.dst, src=self.src)
		self.packet = UDP(sport = self.sport, dport = self.dport)
		self.payload = ""

	def payload_handler(self):
		rand_payload = os.urandom(65000)
		return rand_payload

	def forge_packet(self):
		if args.Tcase:
			if args.Tcase == 1:
				self.packet.len = random.randint(0,7)
			if args.Tcase == 2:
				self.packet.len = 65535
			if args.Tcase == 3:
				self.packet.len = random.randint(41,32766)
			if args.Tcase == 4:
				self.packet.len = random.randint(9,39)
			if args.Tcase == 5:
				self.packet.len = random.randint(32767, 65534)
			if args.Tcase == 6:
				self.packet.chksum = random.randint(0,65535)
			if args.Tcase == 7:
				pass
			if args.Tcase == 8:
				pass
		else:		
			# self.packet.len = 7
			# self.packet.chksum = None
			# self.payload = self.payload_handler()
			# self.payload = "KKKK"
			pass


	def start_sending(self):
		self.forge_packet()
		# print(self.packet.show())
		print("[*] Send DNS query(UDP)")
		if self.payload:
			response, unans = sr(self.ipheader/self.packet/DNS(rd=1, qd=DNSQR(qname='www.iii.org.tw'))/self.payload, timeout=1, verbose=0)	
		else:
			response, unans = sr(self.ipheader/self.packet/DNS(rd=1, qd=DNSQR(qname='www.iii.org.tw')), timeout=1, verbose=0)	


		if response:
			print(response[0][0][UDP].show())
			print(response[DNS].summary())
			# print(hexdump(response[0][0]))
		else:
			print("No response from DUT")
			

if __name__ == '__main__':
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(("8.8.8.8", 80))
	local_ip = s.getsockname()[0]
	print("[*] Local ip found:", local_ip)
	s.close()

	parser = ArgumentParser()
	parser.add_argument("-v", "--verbose", help="Show verbosity.", action="store_true")
	parser.add_argument("-T", "--Tcase", help="EDSA test cases.", type=int, choices=range(1,9))
	parser.add_argument("-c", "--count", help="How many packets to send(not for flooding cases).", type=int, default=1)
	parser.add_argument("destIP", help="Destination device IP.", type=str)
	parser.add_argument("destPort", help="Destination device port.", type=int)
	args = parser.parse_args()

	DUT_ip = args.destIP
	DUT_port = args.destPort
	start_port = random.randrange(49152, 2**16-args.count)
	for packet_num, port_num in enumerate(range(start_port, start_port+args.count)):
			print("---------Packet %s -----------" % packet_num)
			print("[*] Local port number:", port_num)
			udp_snd = UdpSend(DUT_ip, local_ip, DUT_port, port_num)
			udp_snd.start_sending()
	