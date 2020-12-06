import fcntl
import sys
import termios
import threading
import time
from datetime import datetime
from subprocess import call
import psutil
import socket
from struct import *

next_call = time.time()
PROTOCOL_NAME_NUMBER = {name[8:]: num for name, num in vars(socket).items() if
                        name.startswith("IPPROTO")}
sent, received = {}, {}
device = "Unknown"
start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S %p')
MIN_WIDTH = 80
interval = 1


def mac_adr_to_str(adr):
	return ':'.join("{:02X}".format(p) for p in adr)


def get_local_ip():
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(('8.8.8.8', 1))
	return s.getsockname()[0]


def terminal_width():
	_, tw, _, _ = unpack('HHHH', fcntl.ioctl(0, termios.TIOCGWINSZ,
	                                         pack('HHHH', 0, 0, 0, 0)))
	return tw


def print_core(tw):
	template = "%-6s %-40s" + ' ' * (tw - MIN_WIDTH + 1) + "%-7s %-10s %-13s"
	print(f"Started at: {start_time}")
	print(
		f"Current time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S %p')}")
	print("\u001b[47m"  # background color
	      + "\u001b[30m"  # text color
	      + template % ("PID",
	                    "Process Name",
	                    "Device",
	                    "Sent (KB)",
	                    "Received (KB)")
	      + "\033[m")  # closing the coloring
	for pid in sent.keys():
		print(template % (pid,
		                  psutil.Process(pid).cmdline()[0],
		                  device,
		                  sent[pid] / 1000,
		                  received[pid] / 1000))


def parse_eth_header(header):
	# ! for network packets (= big-endian)
	# 6s for string of 6 bytes
	# H for unsigned short
	mac_header = unpack("!6s6sH", header)
	return mac_adr_to_str(mac_header[0]), mac_adr_to_str(mac_header[1]), \
	       socket.ntohs(mac_header[2])


def parse_ip_header(ip_header):
	unpacked = unpack("!BBHHHBBH4s4s", ip_header)
	version, ihl = unpacked[0] >> 4, unpacked[0] & 0xF
	dscp, ecn = unpacked[1] >> 6, unpacked[1] & 0x3
	total_length = unpacked[2]
	identification = unpacked[3]
	flags, frag_off = unpacked[4] >> 3, unpacked[4] & 0x1FFF
	ttl, protocol = unpacked[5], unpacked[6]
	header_chksum = unpacked[7]
	src_ip_adr = socket.inet_ntoa(unpacked[8])
	dest_ip_adr = socket.inet_ntoa(unpacked[9])
	
	return {"proto": protocol,
	        "ihl": ihl,
	        "src_ip": src_ip_adr,
	        "dest_ip": dest_ip_adr}


def parse_tcp_header(tcp_header):
	unpacked = unpack('!HHLLBBHHH', tcp_header)
	src_port = unpacked[0]
	dest_port = unpacked[1]
	seq_num = unpacked[2]
	ack_num = unpacked[3]
	data_off, rev, ns = unpacked[4] >> 4, unpacked[4] & 0x0E, unpacked[4] & 0x1
	cwr, ece, urg, ack, psh, rst, syn, fin = unpacked[5] & 0x1, unpacked[
		5] & 0x2, unpacked[5] & 0x4, unpacked[5] & 0x8, unpacked[5] & 0x10, \
	                                         unpacked[5] & 0x20, unpacked[
		                                         5] & 0x40, unpacked[5] & 0x80
	window_size = unpacked[6]
	checksum = unpacked[7]
	urg_pointer = unpacked[8]
	
	return src_port, dest_port


def print_result():
	global next_call
	call('clear')
	print(
		"Welcome to process-level network traffic monitoring tool (under TCP)!\n")
	tw = terminal_width()
	if tw < MIN_WIDTH:
		print(
			f"Your window width is {tw}. Please make it at least {MIN_WIDTH}!")
	else:
		print_core(tw)
	next_call = next_call + interval
	threading.Timer(next_call - time.time(), print_result).start()


def update_connections(local_ip):
	temp = {}
	temp_snt = sent.copy()
	temp_rec = received.copy()
	for c in psutil.net_connections("tcp"):
		tsip, tsp = c.laddr.ip, c.laddr.port
		tdip, tdp = "", ""
		if c.raddr:
			tdip, tdp = c.raddr.ip, c.raddr.port
		if tsip == local_ip and c.pid is not None:
			temp[(tsip, tsp, tdip, tdp)] = c.pid
			if c.pid not in sent.keys() and c.pid not in received.keys():
				temp_snt[c.pid] = 0
				temp_rec[c.pid] = 0
	return temp, temp_snt, temp_rec


def get_device(local_ip):
	devices = psutil.net_if_addrs()
	for dev in devices:
		for adr in devices[dev]:
			if adr.address == local_ip:
				return dev
	return "Unknown"


def main():
	# TODO fix globals if it could be fixed
	global sent, received, device
	local_ip = get_local_ip()
	device = get_device(local_ip)
	sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
	                     socket.ntohs(0x0003))
	
	ssdd_proc, sent, received = update_connections(local_ip)
	print_result()
	
	while True:
		pkt, address = sock.recvfrom(65535)
		dest_mac, src_mac, eth_type = parse_eth_header(pkt[:14])
		local_ip = get_local_ip()
		device = get_device(local_ip)
		if eth_type == 8:  # IPV4
			ip = parse_ip_header(pkt[14:14 + 20])
			sip, dip = ip["src_ip"], ip["dest_ip"]
			if ip["proto"] == PROTOCOL_NAME_NUMBER["TCP"] and ip["ihl"] <= 5:
				sp, dp = parse_tcp_header(pkt[14 + 20:14 + 20 + 20])
				if sip == local_ip:
					ssdd = (sip, sp, dip, dp)
					ssdd_proc, sent, received = update_connections(local_ip)
					if ssdd in ssdd_proc.keys():
						sent[ssdd_proc[ssdd]] += len(pkt)
				elif dip == local_ip:
					ssdd = (dip, dp, sip, sp)
					ssdd_proc, sent, received = update_connections(local_ip)
					if ssdd in ssdd_proc.keys():
						received[ssdd_proc[ssdd]] += len(pkt)
			elif ip["proto"] == PROTOCOL_NAME_NUMBER["UDP"]:  # TODO UDP
				pass
			elif ip["proto"] == PROTOCOL_NAME_NUMBER["ICMP"]:  # TODO ICMP
				pass
		
		elif eth_type == 56710:  # TODO IPV6
			pass


def handle_args():
	global interval
	if len(sys.argv) > 1:
		interval_pos = sys.argv.index("-i")
		# the interval number comes right after -i
		interval = int(sys.argv[interval_pos + 1])


if __name__ == '__main__':
	handle_args()
	main()
