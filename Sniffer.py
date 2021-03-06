import socket
from PrintPackets import print_ethernet_frame_header_info, \
    print_ipv4_packet_header, \
    print_ipv6_packet_header, \
    print_icmp_packet, \
    print_tcp_packet, \
    print_udp_packet, \
    print_http_data, \
    print_arp_packet
from typing import Any, Tuple
from Ethernet import EthernetPacket, extract_info_from_socket
from IPv4 import IPv4Packet, unpack_ipv4_packet
from IPv6 import IPv6Packet, unpack_ipv6_packet
from ICMP import ICMPPacket, unpack_icmp_packet
from TCP import TCPFlags, TCPPacket, unpack_tcp_packet
from UDP import UDPPacket, unpack_udp_packet
from ARP import ARPPacket, unpack_arp_packet
from dnslib import DNSRecord
import sys
from ColorPrinting import Colors


def get_icmp_info(ipv4_packet: IPv4Packet) -> None:
    icmp_packet: ICMPPacket = unpack_icmp_packet(ipv4_packet.data)
    print_icmp_packet(icmp_packet)


def get_tcp_info(ipv4_packet: IPv4Packet) -> None:
    tcp_packet: TCPPacket = unpack_tcp_packet(ipv4_packet.data)
    print_tcp_packet(tcp_packet)
    # if there is html data display it
    if len(tcp_packet.data) > 0:
        print_http_data(tcp_packet.data)


def get_dns_info(udp_packet: UDPPacket) -> None:
    print('\nDNS FRAME\n')
    dns_record = DNSRecord.parse(udp_packet.data)
    print(dns_record)


def get_udp_info(ipv4_packet: IPv4Packet) -> None:
    udp_packet: UDPPacket = unpack_udp_packet(ipv4_packet.data)
    print_udp_packet(udp_packet)
    if udp_packet.src_port == 53 or udp_packet.dest_port == 53:
        get_dns_info(udp_packet)


def sniff_IPv4(ethernet_packet: EthernetPacket) -> None:
    ipv4_packet: IPv4Packet = unpack_ipv4_packet(ethernet_packet.data)
    print_ethernet_frame_header_info(ethernet_packet, 'IPv4')
    print_ipv4_packet_header(ipv4_packet.version, ipv4_packet.header_length, ipv4_packet.ttl,
                             ipv4_packet.protocol,
                             ipv4_packet.src, ipv4_packet.dest)

    if ipv4_packet.protocol == 1:
        get_icmp_info(ipv4_packet)

    elif ipv4_packet.protocol == 6:
        get_tcp_info(ipv4_packet)

    elif ipv4_packet.protocol == 17:
        get_udp_info(ipv4_packet)


def sniff_ARP(ethernet_packet: EthernetPacket) -> None:
    print_ethernet_frame_header_info(ethernet_packet, 'ARP')
    arp_packet = unpack_arp_packet(ethernet_packet.data)
    print_arp_packet(arp_packet)


def sniff_IPv6(ethernet_packet: EthernetPacket) -> None:
    print_ethernet_frame_header_info(ethernet_packet, 'IPv6')
    ipv6_packet: IPv6Packet = unpack_ipv6_packet(ethernet_packet.data)
    print_ipv6_packet_header(ipv6_packet)


def main():
    try:
        # capture all network packets
        connection: socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

        while True:
            ethernet_packet: EthernetPacket = extract_info_from_socket(connection)
            print(
                f"{Colors.YELLOW}--------------------------------------------------------------------------------------------------------------{Colors.ENDC}")
            # IPv4 traffic
            if ethernet_packet.protocol_type == 2048:
                sniff_IPv4(ethernet_packet)

            # ARP traffic
            elif ethernet_packet.protocol_type == 2054:
                sniff_ARP(ethernet_packet)

            # IPv6 Traffic
            elif ethernet_packet.protocol_type == 34525:
                sniff_IPv6(ethernet_packet)

            else:
                print('Traffic different than IPv4, IPv6 and ARP')
                print('Ethernet Protocol Number:{}'.format(ethernet_packet.protocol_type))

            print(
                f"{Colors.YELLOW}--------------------------------------------------------------------------------------------------------------{Colors.ENDC}")
    except KeyboardInterrupt:
        print('Program Closed, Goodbye!')
        sys.exit(0)


if __name__ == '__main__':
    main()
