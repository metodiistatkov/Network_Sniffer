import socket
import struct


class EthernetPacket:
    def __init__(self, mac_dest: str, mac_src: str, protocol_type: int, data: bytes) :
        self.mac_dest: str = mac_dest
        self.mac_src: str = mac_src
        self.protocol_type: int = protocol_type
        self.data: bytes = data


def __format_MAC_address(raw_bytes: bytes) -> str:
    readable_mac: str = "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", raw_bytes)
    return readable_mac.upper()


def __unpack_ethernet_frame(data: object) -> EthernetPacket:
    mac_dest: bytes = struct.unpack('! 6s', data[:6])[0]
    mac_src: bytes = struct.unpack('! 6s', data[6:12])[0]
    protocol_type: int = struct.unpack('! H', data[12:14])[0]
    remaining_data: bytes = data[14:]
    ethernet_packet: EthernetPacket = EthernetPacket(__format_MAC_address(mac_dest), __format_MAC_address(mac_src),
                                                     protocol_type, remaining_data)
    return ethernet_packet


def extract_info_from_socket(connection: socket) -> EthernetPacket:
    socket_info: Tuple[bytes, Any] = connection.recvfrom(65535)
    raw_data: bytes = socket_info[0]
    address: object = socket_info[1]
    return __unpack_ethernet_frame(raw_data)
