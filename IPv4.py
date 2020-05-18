import struct
import sys
from ColorPrinting import Colors


class IPv4Packet:
    def __init__(self, version: int, header_length: int, ttl: int, protocol: int, src: str, dest: str,
                 data: bytes):
        self.version: int = version
        self.header_length: int = header_length
        self.ttl: int = ttl
        self.protocol: int = protocol
        self.src: str = src
        self.dest: str = dest
        self.data: bytes = data


def __format_IPv4_address(raw_bytes: bytes) -> str:
    readable_ipv4: str = "%d.%d.%d.%d" % struct.unpack("BBBB", raw_bytes)
    return readable_ipv4


def set_TOR_IPs(file_name: str) -> set:
    file = open(file_name)
    tor_ips = set()

    for line in file:
        ip = line.split('|')[0]  # extract ip only
        tor_ips.add(ip)

    return tor_ips


# check if the IP belongs to TOR exit node
def check_IP(ip: str, tor_ips: set) -> None:
    if ip in tor_ips:
        # TODO: add gui POP up
        print(f"{Colors.WARNING}*****TOR Traffic Detected!*****{Colors.ENDC}")

# Create a set with TOR exit nodes IP addresses
tor_ips: set = set_TOR_IPs('TOR_IPs.txt')


def unpack_ipv4_packet(data: object) -> IPv4Packet:
    version_and_header_length: int = data[0]
    version: int = version_and_header_length >> 4  # take the first 4 bits(high nibble) --> Arithmetic right shift
    # the result is the number of 32 bit words for header_length => result * 32 / 8 == result * 4 Bytes
    header_length: int = (version_and_header_length & 15) * 4  # take the last 4 bits(low nibble) --> Num & 00001111
    ttl: int
    protocol: int
    src: str
    dest: str
    ttl, protocol, src, dest = struct.unpack('! 8x B B 2x 4s 4s', data[:20])  # header of IP is 20 Bytes long
    ipv4_packet: IPv4Packet = IPv4Packet(version, header_length, ttl, protocol, __format_IPv4_address(src),
                                         __format_IPv4_address(dest), data[header_length:])
    check_IP(__format_IPv4_address(src), tor_ips)
    check_IP(__format_IPv4_address(dest), tor_ips)

    return ipv4_packet
