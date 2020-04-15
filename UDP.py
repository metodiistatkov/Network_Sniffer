import struct


class UDPPacket:
    def __init__(self, src_port: int, dest_port: int, length: int, checksum: int, data: bytes):
        self.src_port: int = src_port
        self.dest_port: int = dest_port
        self.length: int = length
        self.checksum: int = checksum
        self.data: bytes = data


def unpack_udp_packet(data: bytes) -> UDPPacket:
    src_port, dest_port, length, checksum = struct.unpack('! H H H H', data[:8])
    udp_data = data[8:]
    udp_packet: UDPPacket = UDPPacket(src_port, dest_port, length, checksum, udp_data)
    return udp_packet
