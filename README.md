# DoorStop
        ___                 __ _              
       /   \___   ___  _ __/ _\ |_ ___  _ __  
      / /\ / _ \ / _ \| '__\ \| __/ _ \| '_ \ 
     / /_// (_) | (_) | |  _\ \ || (_) | |_) |
    /___,' \___/ \___/|_|  \__/\__\___/| .__/ 
                                       |_|    


### PCAP certificate analysis for finding reverse https backdoors

This script will parse an input PCAP file, pull out certificates, and analyze them.  
Reverse https shells can be hard to detect because unlike TCP and HTTP, the content is encrypted.  To get around this and attempt some level of detection, we can analyze the handshake at the start of the connection.  
Meterpreter reverse https shells have randomly generated certificates, so if the issuer/domain are random charcters then we know the server is not legitimate and could be a reverse https back door.

#### Usage
To run DoorStop as a GUI, simply call it with no arguments:  
`python doorstop.py`  

To run DoorStop as a CLI, run it with the --cli argument:  
`python doorstop.py --cli`  
`Enter PCAP file to analyze: mycap.pcap`  
or specify input file using the --inp argument
`python doorstop.py --cli --inp mycap.pcap`

#### Output
The output of the CLI is fairly simple.  As the PCAP is analyzed it will display weather it was valid or not.  If a certificate is flagged as invalid, the packet number will be displayed.  A list of all flagged packets will also be displayed at the end.  With this information, an investigator can use a tool such as [wireshark](https://www.wireshark.org/) to take a more in-depth look at the suspicious packets.  
  
Example: 

    user@box$ python cert_check.py caps/pizza.pcap

    Checking caps/pizza.pcap...
    --------------------------------------------
    Analyzing certificate...
    Certificate is valid
    Analyzing certificate...
    Invalid certificate possible in packet: 13
    Analyzing certificate...
    Certificate is valid
    Analyzing certificate...
    Certificate is valid
    Analyzing certificate...
    Certificate is valid
    Analyzing certificate...
    Certificate is valid
    Certificate is valid
    Analyzing certificate...
    Certificate is valid
    Analyzing certificate...
    Invalid certificate possible in packet: 746
    Analyzing certificate...
    Certificate is valid
    Analyzing certificate...
    Certificate is valid
    --------------------------------------------
    Packets with invalid certs: 13, 746


