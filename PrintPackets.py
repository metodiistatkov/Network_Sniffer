from Ethernet import EthernetPacket
from IPv4 import IPv4Packet
from IPv6 import IPv6Packet
from ICMP import ICMPPacket
from TCP import TCPFlags, TCPPacket
from UDP import UDPPacket
from ARP import ARPPacket
from ColorPrinting import Colors


def print_ethernet_frame_header_info(ethernet_packet: EthernetPacket, protocol_name: str) -> None:
    print(f"{Colors.HEADER}Ethernet Frame\n{Colors.ENDC}")
    print('MAC Source: {} | MAC Destination: {} | Protocol: {} ({})'.format(ethernet_packet.mac_src,
                                                                            ethernet_packet.mac_dest,
                                                                            ethernet_packet.protocol_type,
                                                                            protocol_name))


def print_ipv4_packet_header(version: object, header_length: object, ttl: object, protocol: object, src: object,
                             dest: object) -> None:
    print(f"\n{Colors.BOLD}IPv4 Frame{Colors.ENDC}\n")
    print('IP Version:', version, '| Header Length:', header_length, 'Bytes |', 'TTL:', ttl, '| Protocol:', protocol,
          '| Source:', src, "| Destination:", dest)


def print_ipv6_packet_header(ipv6_packet: IPv6Packet) -> None:
    print(f"\n{Colors.BOLD}IPv6 Frame{Colors.ENDC}\n")
    print('IP Version:{} | Traffic Class:{} | Flow Label:{} | Payload Length:{} | Next Header:{} | Hop Limit:{} | '
          'Source: {} | Destination: {}'.format(ipv6_packet.version, ipv6_packet.traffic_class, ipv6_packet.flow_label,
                                                ipv6_packet.payload_length, ipv6_packet.next_header,
                                                ipv6_packet.hop_limit,
                                                ipv6_packet.src, ipv6_packet.dest, ipv6_packet.data))


def print_icmp_packet(icmp_packet: ICMPPacket) -> None:
    print(f"\n{Colors.BOLD}ICMP Frame{Colors.ENDC}\n")
    print('Type: {} | Code: {} | Checksum: {}'.format(icmp_packet.icmp_type, icmp_packet.code, icmp_packet.checksum))


def __print_tcp_flags(tcp_flags: TCPFlags) -> None:
    print('\nTCP Flags')
    print('URG:{}'.format(tcp_flags.urg))
    print('ACK:{}'.format(tcp_flags.ack))
    print('PSH:{}'.format(tcp_flags.psh))
    print('RST:{}'.format(tcp_flags.rst))
    print('SYN:{}'.format(tcp_flags.syn))
    print('FIN:{}'.format(tcp_flags.fin))


def print_tcp_packet(tcp_packet: TCPPacket) -> None:
    print(f"\n{Colors.BOLD}TCP Frame{Colors.ENDC}\n")
    print(
        'Source Port:{} | Destination Port:{} | Sequence Number:{} | Acknowledgment Number:{} | Data Offset: {}'.format(
            tcp_packet.src_port, tcp_packet.dest_port, tcp_packet.sequence_num, tcp_packet.acknowledgement_num,
            tcp_packet.data_offset))
    __print_tcp_flags(tcp_packet.reserved_flags)


def print_udp_packet(udp_packet: UDPPacket) -> None:
    print(f"\n{Colors.BOLD}UDP Frame{Colors.ENDC}\n")
    print('Source Port:{} | Destination Port:{} | Length:{} | Checksum:{}'.format(udp_packet.src_port,
                                                                                  udp_packet.dest_port,
                                                                                  udp_packet.length,
                                                                                  udp_packet.checksum))


def print_http_data(tcp_data: bytes) -> None:
    try:
        decoded_data = tcp_data.decode('UTF-8')
        print('\n HTTP DATA:\n{}'.format(decoded_data))
    except:
        print('\n HTTP DATA:\n{}'.format(tcp_data))


def print_arp_packet(arp_packet: ARPPacket) -> None:
    print(f"\n{Colors.BOLD}ARP Frame{Colors.ENDC}\n")
    print('Source Hardware Address:{} | Source Protocol Address:{} | Destination Hardware Address:{} | Destination '
          'Protocol Address:{}'.format(arp_packet.src_hardware,
                                       arp_packet.src_protocol,
                                       arp_packet.dest_hardware,
                                       arp_packet.dest_protocol))
