#!/usr/bin/env python

import argparse
from dstop_cli import main as c


parser = argparse.ArgumentParser(description='Analyze HTTPS certificates in pcap files.')
parser.add_argument('--cli', dest='cli', action='store_true', help='use command line interface instead of GUI')
parser.add_argument('--inp', dest='inp', action='store', help='Input PCAP location')
args = parser.parse_args()


cli = args.cli
inp = args.inp

if cli:
    c(inp)
else:
    from dstop_gui import *
 


