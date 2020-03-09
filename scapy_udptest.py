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
		# rand_payload = ''.join(random.choice(ascii_letters) for i in range(random.randint(1, 65536)))
		# rand_payload = ''.join(random.choice(ascii_letters) for i in range(0, 65501))
		rand_payload = os.urandom(65507)
		return rand_payload

	def forge_packet(self):
		# self.packet.len = 0xffff
		# self.packet.chksum = None
		# self.payload = self.payload_handler()
		pass


	def start_sending(self):
		self.forge_packet()
		# print(self.packet.show())
		if self.payload:
			print("[*] Send Raw")
			send(self.ipheader/self.packet/self.payload)
		else:
			print("[*] Send DNS")
			response, unans = sr(self.ipheader/self.packet/DNS(rd=1, qd=DNSQR(qname='www.iii.org.tw')), timeout=2, verbose=0)	
			print(response[0][0][UDP].show())
			print(response[DNS].summary())
			print(hexdump(response[0][0]))

if __name__ == '__main__':
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(("8.8.8.8", 80))
	local_ip = s.getsockname()[0]
	print("[*] Local ip found:", local_ip)
	s.close()

	parser = ArgumentParser()
	parser.add_argument("-r", "--rand",help="Make packet random if set.", action="store_true")
	parser.add_argument("-v", "--verbose", help="Show verbosity.", action="store_true")
	parser.add_argument("destIP", help="Destination device IP.", type=str)
	parser.add_argument("destPort", help="Destination device port.", type=int)
	args = parser.parse_args()

	DUT_ip = args.destIP
	DUT_port = args.destPort
	port_num = random.randrange(49152, 2**16)
	print("[*] Local port number:", port_num)
	udp_snd = UdpSend(DUT_ip, local_ip, DUT_port, port_num)
	udp_snd.start_sending()
	