from scapy.all import *

cap = rdpcap('caps/pizza.pcap')
for packet in cap:
	a = packet.show()
	layers = []
	counter = 0
	while True:
		layer = packet.getlayer(counter)
		if (layer != None):
			layers.append(layer.name)
		else:
			break
		counter += 1

	print "Layers: " +  str(layers)
			

