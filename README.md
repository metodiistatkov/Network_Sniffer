# Network_Sniffer

A packet sniffer for Linux systems, which inspects packets on Ethernet, Network, Transport, and Presentation layers. Besides packet monitoring, the program has some Intrusion Detection characteristics. It can detect TOR traffic and potential ARP spoofing attacks (if the default gateway information on the host is not spoofed already).

I get the list of TOR nodes from [here](https://www.dan.me.uk/tornodes).  
Note: The list gets updated every 30 mins, so if you want to have accurate TOR detection, make sure to have the latest version. 

## Starting the sniffer
sudo python3 Sniffer.py

The sudo command is needed because a raw socket is opened to the operating system's network interface. Ussually it is not recommended to start such programs as super user, which could be avoided by setting a CAP_NET_RAW capability on the file to be executed. Unfortunately, this does not work with interpreted languages (like Python) because the script is executed by the interpreter. 
