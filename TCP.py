import struct


class TCPFlags:
    def __init__(self, urg: int, ack: int, psh: int, rst: int, syn: int, fin: int):
        self.urg: int = urg
        self.ack: int = ack
        self.psh: int = psh
        self.rst: int = rst
        self.syn: int = syn
        self.fin: int = fin


class TCPPacket:
    def __init__(self, src_port: int, dest_port: int, sequence_num: int, acknowledgement_num: int, data_offset: int,
                 reserved_flags: TCPFlags, data: bytes):
        self.src_port: int = src_port
        self.dest_port: int = dest_port
        self.sequence_num: int = sequence_num
        self.acknowledgement_num: int = acknowledgement_num
        self.data_offset: int = data_offset
        self.reserved_flags: TCPFlags = reserved_flags
        self.data: bytes = data


def __unpack_tcp_flags(reserved_flags: int) -> TCPFlags:
    flag_urg: int = (reserved_flags & 32) >> 5
    flag_ack: int = (reserved_flags & 16) >> 4
    flag_psh: int = (reserved_flags & 8) >> 3
    flag_rst: int = (reserved_flags & 4) >> 2
    flag_syn: int = (reserved_flags & 2) >> 1
    flag_fin: int = reserved_flags & 1
    tcp_flags: TCPFlags = TCPFlags(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin)
    return tcp_flags


def unpack_tcp_packet(data: bytes) -> TCPPacket:
    src_port: int
    dest_port: int
    sequence_num: int
    acknowledgement_num: int
    data_offset_reserved_flags: int
    src_port, dest_port, sequence_num, acknowledgement_num, data_offset_reserved_flags = struct.unpack('! H H L L H',
                                                                                                       data[:14])
    data_offset: int = (data_offset_reserved_flags >> 12) * 4
    # extracting all different flags for handshake
    tcp_flags: TCPFlags = __unpack_tcp_flags(data_offset_reserved_flags)
    # remaining data in tcp packet
    tcp_data: bytes = data[data_offset:]
    tcp_packet: TCPPacket = TCPPacket(src_port, dest_port, sequence_num, acknowledgement_num, data_offset, tcp_flags,
                                      tcp_data)
    return tcp_packet
