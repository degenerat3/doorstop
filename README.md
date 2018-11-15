# doorstop
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
To run the python script, simply call it with the pcap as an argument:
`cert_check.py mycapture.pcap`

or run the script with no arguments and specify the capture with user input:
`cert_check.py`
`Enter PCAP file to analyze: mycap.pcap`

#### Output
The output is fairly simple.  As the PCAP is analyzed it will display weather it was valid or not.  If a certificate is flagged as invalid, the packet number will be displayed.  A list of all flagged packets will also be displayed at the end.  With this information, an investigator can use a tool such as [wireshark](https://www.wireshark.org/) to take a more in-depth look at the suspicious packets.


