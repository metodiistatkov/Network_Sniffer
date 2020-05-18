# Network_Sniffer

A packet sniffer for Linux systems, which inspects packets on Ethernet, Network, Transport, and Presentation layers. Besides packet monitoring, the program has some Intrusion Detection characteristics. It can detect TOR traffic and potential ARP spoofing attacks (if the default gateway information on the host is not spoofed already).

I get the list of TOR nodes from [here](https://www.dan.me.uk/tornodes).  
Note: The list gets updated every 30 mins, so if you want to have accurate TOR detection, make sure to have the latest version. 
