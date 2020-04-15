import struct


class IPv6Packet:
    def __init__(self, version: int, traffic_class: int, flow_label: int, payload_length: int, next_header: int,
                 hop_limit: int, src: str, dest: str, data: bytes):
        self.version: int = version
        self.traffic_class: int = traffic_class
        self.flow_label: int = flow_label
        self.payload_length: int = payload_length
        self.next_header: int = next_header
        self.hop_limit: int = hop_limit
        self.src: str = src
        self.dest: str = dest
        self.data: bytes = data


def __bit_mask(num_bits: int) -> int:
    return (1 << num_bits) - 1


def __get_ipv6_address(ipv6_addr: tuple) -> str:
    readable_ipv6: str = ''
    for i in range(len(ipv6_addr)):
        readable_ipv6 += str(hex(ipv6_addr[i])[2:])
        if i != len(ipv6_addr) - 1:
            readable_ipv6 += '::'

    return readable_ipv6


def unpack_ipv6_packet(packet: bytes) -> IPv6Packet:
    header: tuple = struct.unpack('! I H B B 16H', packet[:40])
    data: bytes = packet[:40]

    version: int = header[0] >> 28
    traffic_class: int = (header[0] >> 20) & __bit_mask(8)
    flow_label: int = header[0] & __bit_mask(20)
    payload_length: int = header[1]
    next_header: int = header[2]
    hop_limit: int = header[3]
    src: str = __get_ipv6_address(header[4:12])
    dest: str = __get_ipv6_address(header[12:20])

    ipv6_packet: IPv6Packet = IPv6Packet(version, traffic_class, flow_label, payload_length, next_header, hop_limit, src, dest, data)
    return ipv6_packet
