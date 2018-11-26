"""
This script will analyze pcap files to detect meterpreter reverse https shells.

It does this by analyzing the certificate at the start of the https handshake.
Meterpreter rev_https shells don't have valid certificates, and instead generate
a random alphanumeric string as their certificate issuer and domain.  As a result
of this, it's easy to differentiate meterpreter's certificates from something 
like Digicert's certificates.  By picking out these garbage certificates we 
can see when a meterpreter session is being initialized, and notify the user.


USAGE
-----
The only input file is the PCAP, taken as a command-line arg or user input:

cert_check.py mycap.pcap
        or
cert_check.py
Enter PCAP file to analyze: mycap.pcap


"""

from scapy.all import *
import sys

magic = "= '\\x16\\x03\\x01"    #magic string at start of certificate raw blocks

def main(inp):
    pax = []
    if inp == None:     #either take user input or use cmd arg for pcap
        f = raw_input("Enter PCAP file to analyze: ")
    else:
        f = inp
    cap = rdpcap(f)
    p = 1
    print
    print("Checking " + f + "...")
    print("--------------------------------------------")
    for packet in cap:
        a = str(packet.show(dump=True))     # dump each packet as a string  
        if "Raw" in a:
            rawblock = a.split("Raw ]###")[1]   #pull the raw block out
            rawblock = rawblock.split("load    ")[1]    #minor parsing to remove scapy headers
            if magic in rawblock:
                if len(rawblock) > 1900:                #approx. min length for cert block
                    print "Analyzing certificate..."    #only look at cert blocks, ignore others
                    spc = rawblock.count(" ")           #count spaces in cert block
                    if spc <= 10:                       #meterpreters certs never have spaces
                        print("Invalid certificate possible in packet: " + str(p))
                        pax.append(str(p))              #add it to list of bad packets
                    else:
                        print("Certificate is valid")   
                    
        p += 1
    finstr = "Packets with invalid certs: "
    c = 0
    for pac in pax:                                     #formatting
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


