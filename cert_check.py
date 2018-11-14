from scapy.all import *
import sys

magic = "= '\\x16\\x03\\x01"	#magic string at start of certificate raw blocks

def main():
	pax = []
	if len(sys.argv) == 1:
		f = raw_input("Enter PCAP file to analyze: ")
	else:
		f = sys.argv[1]
	cap = rdpcap(f)
	p = 1
	print
	print("Checking " + f + "...")
	print("--------------------------------------------")
	for packet in cap:
		a = str(packet.show(dump=True))
		if "Raw" in a:
			rawblock = a.split("Raw ]###")[1]
			rawblock = rawblock.split("load    ")[1]
			if magic in rawblock:
				if len(rawblock) > 1900:
					print "Analyzing certificate..."
					spc = rawblock.count(" ")
					if spc <= 10:
						print("Invalid certificate possible in packet: " + str(p))
						pax.append(str(p))
					else:
						print("Certificate is valid")
					
		p += 1
	finstr = "Packets with invalid certs: "
	c = 0
	for pac in pax:
		if c == len(pax)-1:
			finstr = finstr + pac
		else:
			finstr = finstr + pac + ", "
		c += 1
	if len(pax) == 0:
		finstr = "No invalid certificates detected"	
	print("--------------------------------------------")
	print finstr
	print
main()

