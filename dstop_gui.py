#!/usr/bin/env python

from Tkinter import *
from time import sleep
from scapy.all import *
import Tkinter as tk 
import tkFileDialog

f = 'PCAP FileName'
magic = "= '\\x16\\x03\\x01"

def getFile():
    global f
    a = tkFileDialog.askopenfile(parent=root, mode='r', title='Select a PCAP')
    f = a.name
    b = "File: " + f
    fl_lbl = tk.Label(root, text=b).pack()
    
    
def analyze():
    global f
    pax = []
    out_st = "\n"
    cap = rdpcap(f)
    p = 1
    out_st += "Reading file...\n"
    out = tk.Label(root, text=out_st)
    out.pack()
    out_st += "Analyzing certificates...\n"
    out.config(text=out_st)
    for packet in cap:
        a = str(packet.show(dump=True))     # dump each packet as a string  
        if "Raw" in a:
            rawblock = a.split("Raw ]###")[1]   #pull the raw block out
            rawblock = rawblock.split("load    ")[1]    #minor parsing to remove scapy headers
            if magic in rawblock:
                if len(rawblock) > 1900:                #approx. min length for cert block
                    spc = rawblock.count(" ")           #count spaces in cert block
                    if spc <= 10:                       #meterpreters certs never have spaces
                        pax.append(str(p))              #add it to list of bad packets
    
        p += 1
    out_st += "Analysis complete.\n"
    out.config(text=out_st)
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
    out_st += finstr + "\n"
    out.config(text=out_st)


root = tk.Tk()
root.title("DoorStop")
root.geometry('500x500')

fl_btn = tk.Button(root, text='Browse PCAP', command=getFile).place(anchor='nw')

an_btn = tk.Button(root, text='Analyze', command=analyze).place(anchor="nw", x=125)

log_lbl = tk.Label(root, text="ANALYSIS LOG:").place(anchor = 'nw', y=35)

fill = tk.Label(root, text=" \n\n").pack()


root.mainloop() 




