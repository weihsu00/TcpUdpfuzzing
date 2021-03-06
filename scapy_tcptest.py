from scapy.all import *
from argparse import ArgumentParser
import socket
import time
import random
import sys
import os

class TcpHandshake():

	def __init__(self, dstip, srcip, dstport, srcport):
		self.seq = 0
		self.seq_next = 0
		self.src = srcip
		self.dst = dstip
		self.sport = srcport
		self.dport = dstport
		self.ipheader = IP(dst=self.dst, src=self.src)
		self.packet = TCP(sport=self.sport, dport=self.dport, flags=0, seq=random.randrange(0,2**32))
		self.payload = ""
		if args.Tcase not in flooding_cases:
			print("[*] Initializing TcpHandshake on ", self.dst, ":", self.dport)

	def recv_handler(self, res_packet):
		if res_packet and res_packet.haslayer(IP) and res_packet.haslayer(TCP):
			if res_packet[TCP].flags=="SA":
				print("[*] Received:\t SYN+ACK")
				return self.send_synack_ack(res_packet)
			elif res_packet[TCP].flags=="PFA":
				print("[*] Received:\t PSH+FIN+ACK")
				return self.send_rst(res_packet)
			elif res_packet[TCP].flags=="A" or res_packet[TCP].flags=="FA":
				print("[*] Received:\t ACK")
				return self.send_ack_finack(res_packet)
			elif res_packet[TCP].flags=="RA":
				print("[*] Received:\t RST+ACK")
				print("[*] Port %d is closed." % res_packet[TCP].sport)
				return True
			elif res_packet[TCP].flags=="R":
				print("[*] Received:\t RST")
				print("[*] Port %d is closed." % res_packet[TCP].sport)
				return True
		else:
			pass

	def send_syn(self):
		print("[*] Send:\t SYN")
		self.packet.flags = "S"
		if args.Tcase in [7,8,12,13,15,16]:
			self.forge_syn_packet()
		# 2 MSS 		len4
		# 3 WScale  	len3
		# 4 SAckOK 		len2
		# 5 SAck 		lenN 
		# 8 Timestamp 	len10
		# 9 POCP 		len2
		# 14 AltChkSum 	len3
		# 15 AltChkSumOpt 	lenN
		# self.packet.options = self.options_handler()
		response, unans = sr(self.ipheader/self.packet, timeout=2, verbose=0)
		self.packet.seq += 1
		if response:
		# print(response[0][1])
		# print(response)
			return self.recv_handler(response[0][1])
		else:
			print("[*] No response from DUT before timeout")
			# This is the packet that cause no response
			print(self.packet.show())
			print(hexdump(self.ipheader/self.packet))
			return False

	def send_synack_ack(self, res_packet):
		print("[*] Send:\t ACK")
		self.packet.ack = res_packet[TCP].seq+1
		self.packet.flags = "A"
		if args.Tcase == 13:
			self.packet.options = self.options_handler("ack")

		send(self.ipheader/self.packet, verbose=0)
		return True
	
	def stop_sniff(self, x):
		if "F" in x[TCP].flags:
			return True
		else:
			return False

	def send_payload(self):
		print("[*] Send:\t PSH+ACK")
		# ------Forge packet here---------
		self.forge_packet()
		# ------End forge packet here------		
		if self.payload:
			response, unans = sr(self.ipheader/self.packet/self.payload, multi=0, timeout=1, verbose=0)
		else:
			response, unans = sr(self.ipheader/self.packet, multi=1, timeout=1, verbose=0)
		if response:		
			self.packet.seq += len(self.payload)
			# response[0][0] is the packet sent, response[0][1] is the response from the DUT
			# response = sniff(filter = "ip src %s and tcp and tcp port %d" % (self.dst,self.dport), count=1, timeout = 2)
			
			# print(response.summary())
			print(response[0][0][TCP].show())
			print(hexdump(response[0][0]))
			# print(type(response[0][0][TCP]))			
			# print(response[0][1])
			# print(response[0][1][TCP].flags)
			return self.recv_handler(response[0][1])
		else:
			print("[*] No response from DUT before timeout")
			# This is the packet that cause no response
			print((self.packet/self.payload).show())
			print(hexdump(self.ipheader/self.packet/self.payload))
			return False

	def send_ack_finack(self, res_packet):
		print("[*] Send:\t FIN -> ACK")
		self.packet.flags = "FA"
		# self.packet.ack = res_packet[TCP].seq+1
		self.packet.ack = res_packet[TCP].seq
		response,unans = sr(self.ipheader/self.packet, verbose=0, timeout=1)
		print(response.summary())
		self.packet.ack += 1
		self.packet.seq += 1 
		
		if response and response[0][1][TCP].flags == "FPA":
			self.send_rst()
			return True
		elif response and response[0][1][TCP].flags == "A":
			self.packet.flags = "A"
			response1, unans1 = sr(self.ipheader/self.packet,timeout=0.1, verbose=0)
			if response1 and response1[0][1][TCP].flags == "A":
				print(response1.summary())
				return False
			else:
				return True
		elif response and response[0][1][TCP].flags == "R":
			return True
		else:
			print("[*] No response from DUT.")
			return False
			
		# except Exception:
		# 	print("[*] No response from DUT.")
		# 	return False

	# def send_finack_ack(self, res_packet):
	# 	print("[*] Send:\t FIN -> ACK")
	# 	self.packet.flags = "A"
	# 	print(res_packet[Raw])
	# 	print(len(res_packet[Raw]))
	# 	self.packet.ack = res_packet[TCP].seq+len(res_packet[Raw])
	# 	# self.packet[TCP].ack += 6
	# 	send(self.ipheader/self.packet, verbose=0)
	# 	# self.packet[TCP].ack -= 1
	# 	# send(self.ipheader/self.packet)
	# 	self.packet.flags = "RA"
	# 	send(self.ipheader/self.packet, verbose=0)
	# 	# self.packet[TCP].flags = "F"
	# 	# send(self.packet)

	def send_rst(self):
		print("[*] Send:\t RST")
		# self.packet.flags = "R"
		rst_packet = TCP(sport=self.sport, dport=self.dport, flags="RA", seq=self.packet.seq, ack=self.packet.ack)
		send(self.ipheader/rst_packet, verbose=0)

	def forge_syn_packet(self):
		if args.Tcase:
			if args.Tcase == 7:
				self.packet.options = self.options_handler("syn")
			if args.Tcase == 8:
				self.packet.sport = self.dport
				self.ipheader.src = self.dst
			if args.Tcase == 12:	
				self.packet.options = self.options_handler("syn")
			if args.Tcase == 13:
				self.packet.options = self.options_handler("syn")
			if args.Tcase == 15:
				self.packet.dport = random.choice([0x0000, 0xffff])
			if args.Tcase == 16:
				pass
		
	def forge_packet(self):
		if args.Tcase:
			self.packet.flags = "PA"
			if args.Tcase == 2:
				self.packet.dataofs = random.randint(0,4)
			elif args.Tcase == 3:				
				self.packet.dataofs = random.randint(6,15)
			elif args.Tcase == 4:
				self.packet.flags = "UPA"
				randx = random.randint(1, 65495)
				self.payload = os.urandom(randx)
				self.packet.urgptr = random.randint(randx, 65535)
			elif args.Tcase == 5:
				self.packet.chksum = random.randint(0,65535)
			elif args.Tcase == 6:				
				randx = random.randint(6,15)
				self.packet.dataofs = randx
				self.payload = os.urandom((randx-5)*4)
			elif args.Tcase == 9:
				self.packet.flags = random.randint(0,511)
				self.packet.reserved = random.randint(0,7)
			elif args.Tcase == 10:
				self.packet.window = random.randint(0, 65535)
				self.payload = os.urandom(random.randint(0, 65495))
				# need reset??
			elif args.Tcase == 11:				
				self.packet.seq = random.getrandbits(32)
				self.payload = os.urandom(random.randint(0, 65495))
			elif args.Tcase == 12:				
				self.packet.options = self.options_handler("packet")
				self.payload = os.urandom(random.randint(0, 65495))
			elif args.Tcase == 13:				
				self.packet.options = self.options_handler("packet")
				self.payload = os.urandom(random.randint(0, 65495))
				# self.payload = "KKKK"
			elif args.Tcase == 14:
				self.packet.flags = "UPA"
				randx = random.randint(0, 65495)
				self.payload = os.urandom(randx)
				self.packet.urgptr = random.choice([0, random.randint(1, randx-1), randx])
			elif args.Tcase == 16:				
				self.payload = os.urandom(random.randint(0, 65495))
			elif args.Tcase == 17:
				self.packet.flags = "UPA"
				self.payload = os.urandom(65495)
				self.packet.urgptr = 65495
			elif args.Tcase == 20:
				self.packet.seq += 100
				self.payload = "KKKK"
			elif args.Tcase == 21:
				self.packet.window = 0 
				self.payload = "KKKK"
			elif args.Tcase == 23:
				self.packet.flags = "F"
			else:
				self.packet.flags = "PA"
				self.payload = "KKKK"

		elif args.rand:
			self.packet.reserved = random.randint(0,7)
			self.packet.flags = random.randint(0,32)
			self.packet.window = random.randint(0, 65535)
			self.packet.urgptr = random.randint(0, 65535)
			self.packet.options = self.options_handler()
		elif args.noraml:
			self.packet.flags = "A"
			self.payload = "KKKK"
		else:
			# self.packet.dataofs = 15
			# self.packet.reserved = 0
			# self.packet.seq += 100 
			self.packet.flags = "PA"
			# self.packet.window = 0
			# self.packet.chksum = 0xffff
			# self.packet.urgptr = 100
			# self.packet.options = self.options_handler()
			self.payload = "KKKK"
			# self.payload = os.urandom(65400)
			# self.payload = self.payload_handler()

	def options_handler(self, sign):
		# Choose random options from:
		# 2 MSS 		len4
		# 3 WScale  	len3
		# 4 SAckOK 		len2
		# 5 SAck 		lenN 
		# 8 Timestamp 	len10
		# 9 POCP 		len2
		# 14 AltChkSum 	len3
		# 15 AltChkSumOpt 	lenN
		optlist = []
		ws_shift = ['\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', '\x08', '\x09', '\x0a', '\x0b','\x0c', '\x0d', '\x0e' ]
		altchk_type = ['\x01', '\x02']
		# Forging SYN
		if sign == "syn":
			if args.Tcase == 7:
				crt_options = [2,3,4,9,14]
				# crt_options = [2, 3, 4, 5, 8, 9, 14]
				choices = random.sample(crt_options, random.randint(1, len(crt_options)))
				for op in choices:
					if op == 2:
						optlist.append((op, os.urandom(2)))
					elif op == 3:
						optlist.append((op, random.choice(ws_shift)))
					elif op == 4:
						optlist.append((op, b''))
					elif op == 5:
						optlist.append((op, os.urandom(16)))
					elif op == 8:
						optlist.append((op, os.urandom(8)))
					elif op == 9:
						optlist.append((op, b''))
					elif op == 14:
						optlist.append((op, random.choice(altchk_type)))
					# else:
					# 	optlist.append((op, os.urandom(6)))
				# print(optlist)
			elif args.Tcase == 12:
				optlist.append((4, b''))
			elif args.Tcase == 13:
				optlist.append((8, os.urandom(8)))
		#  Forging packet
		elif sign == "packet":
			if args.Tcase == 12:
				optlist.append((5, os.urandom(16)))
			elif args.Tcase == 13:
				optlist.append((8, os.urandom(8)))
		elif sign == "ack":
			if args.Tcase == 13:
				optlist.append((8, os.urandom(8)))
		return optlist

	def payload_handler(self):
		# rand_payload = ''.join(random.choice(ascii_letters) for i in range(random.randint(1, 65535)))
		rand_payload = os.urandom(random.randint(1,65495))
		return rand_payload

	def start_handshake(self):
		if self.send_syn():
			if self.send_payload():
				pass
			else:
				# Send another SYN to check
				# self.send_rst()
				print ("Need to send another SYN")
				sys.exit(0)
		else:
			# Send another SYN to check
			# self.send_rst()
			print ("Need to send another SYN")
			sys.exit(0)
		# Send: 	SYN
		# Receive:	SYN+ACK
		# Send:		SYN+ACK -> ACK
		# self.send_payload()
		# Send :	PSH+ACK
		# self.send_finack_ack()
	def flooding_packet(self):
		if args.Tcase == 17:
			self.send_syn()
			self.send_payload()
		elif args.Tcase == 18:
			self.packet.flags = "S"
			send(self.ipheader/self.packet, verbose=0, inter=0.0001)
		elif args.Tcase == 19:
			self.send_syn()
		elif args.Tcase == 20 or args.Tcase == 21:
			self.send_syn()
			self.send_payload()
		elif args.Tcase == 22:
			self.send_syn()
			self.send_rst()
		elif args.Tcase == 23:
			self.send_syn()
			self.packet.flags = "F"
			send(self.ipheader/self.packet, verbose=0)
		else:
			pass

if __name__=='__main__':
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(("8.8.8.8", 80))
	local_ip = s.getsockname()[0]
	print("[*] Local ip found:", local_ip)
	s.close()

	# file = sys.stdout
	# sys.stdout = open("tcpresults/test.txt", "w")

	parser = ArgumentParser()
	parser.add_argument("-v", "--verbose", help="Show verbosity if set.", action="store_true")
	parser.add_argument("-r", "--rand",help="Make packet random if set.", action="store_true")
	parser.add_argument("-n", "--noraml", help="Normal SYN.", action="store_true")
	parser.add_argument("-T", "--Tcase", help="EDSA test cases.", type=int, choices=range(2,24))
	# not over a amount of packets?
	parser.add_argument("-c", "--count", help="How many packets to send(not for flooding cases).", type=int, default=1)
	parser.add_argument("destIP", help="Destination device IP.", type=str)
	parser.add_argument("destPort", help="Destination device port.", type=int)
	args = parser.parse_args()
	try:
		os.system("iptables -A OUTPUT -p tcp --tcp-flags RST RST -s "+local_ip+" -j DROP")
	except:
		pass
	DUT_ip = args.destIP
	DUT_port = args.destPort
	start_port = random.randrange(49152, 2**16-args.count)
	flooding_cases = [17,18,19,20,21,22,23]
	
	print("[*] Configuration Status: ")
	print("verbose is:\t", args.verbose)
	print("rand is:\t", args.rand)
	print("case number:\t", args.Tcase)
	print("packets send:\t", args.count)
	
	print("[*] Starting packet send...")
	time.sleep(1)

	if args.Tcase in flooding_cases:
		print("[*] Flooding in progress...... Ctrl+C to terminate.")
		start_port = 49152
		start_ip = local_ip
		for packet_num, port_num in enumerate(range(start_port, 2**16)):
			tcp_hs = TcpHandshake(DUT_ip, start_ip, DUT_port, port_num)
			tcp_hs.flooding_packet()

	else:
		for packet_num, port_num in enumerate(range(start_port, start_port+args.count)):
			print("---------Packet %s -----------" % packet_num)
			print("[*] Local port number:", port_num)
			tcp_hs = TcpHandshake(DUT_ip, local_ip, DUT_port, port_num)
			tcp_hs.start_handshake()

	print("[*] Session ended.")

	# sys.stdout.close()
	# sys.stdout = file
	# print("Terminal messege")