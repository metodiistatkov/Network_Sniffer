import struct


class ICMPPacket:
    def __init__(self, icmp_type: int, code: int, checksum: int, data: bytes):
        self.icmp_type: int = icmp_type
        self.code: int = code
        self.checksum: int = checksum
        self.data: bytes = data


def unpack_icmp_packet(data: bytes) -> ICMPPacket:
    icmp_type: int
    code: int
    checksum: int
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    icmp_packet: ICMPPacket = ICMPPacket(icmp_type, code, checksum, data[4:])
    return icmp_packet
