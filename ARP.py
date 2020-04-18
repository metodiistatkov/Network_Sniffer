import struct
from Ethernet import __format_MAC_address
from IPv4 import __format_IPv4_address
from ColorPrinting import Colors
import warnings
from tkinter import messagebox
from tkinter import Tk
import netifaces
import subprocess

class ARPPacket:
    def __init__(self, src_hardware: int, src_protocol: int, dest_hardware: int, dest_protocol: int):
        self.src_hardware: int = src_hardware
        self.src_protocol: int = src_protocol
        self.dest_hardware: int = dest_hardware
        self.dest_protocol: int = dest_protocol


def def_gw_IP() -> str:
    gws: str = netifaces.gateways()
    return gws['default'][netifaces.AF_INET][0]


def def_gw_MAC() -> str:
    addrs: str = subprocess.check_output(['arp', '-a']).decode('utf-8')
    list_arp: list = addrs.splitlines()
    gw_mac: str

    for line in list_arp:
        if '_gateway' in line:
          gw_mac = line.split()[3]

    return gw_mac.upper()


# provide your default gateway details here
DEFAULT_GATEWAY: dict = {def_gw_IP(): def_gw_MAC()}
# gui message related
root = Tk()


def arp_spoofing_check(arp_packet: ARPPacket) -> None:
    dg_IP: str = list(DEFAULT_GATEWAY.keys())[0]
    dg_MAC: str = list(DEFAULT_GATEWAY.values())[0]
    if arp_packet.src_protocol == dg_IP:
        if arp_packet.src_hardware != dg_MAC:
            print(f"{Colors.WARNING}*****Two different MAC address entries for Default Gateway! Possible ARP spoofing "
                  f"attack!*****{Colors.ENDC}")
            # display pop up message
            messagebox.showwarning('ARP Spoofing',
                                   'Two different MAC address entries for Default Gateway! Possible ARP spoofing '
                                   'attack!\nMAC address of the possible attacker: %s' % arp_packet.src_hardware)
            # root.destroy()
    elif arp_packet.dest_protocol == dg_IP:
        if arp_packet.dest_hardware != dg_MAC:
            print(f"{Colors.WARNING}*****Two different MAC address entries for Default Gateway! Possible ARP spoofing "
                  f"attack!*****{Colors.ENDC}")
            messagebox.showwarning('ARP Spoofing',
                                   'Two different MAC address entries for Default Gateway! Possible ARP spoofing '
                                   'attack!\nMAC address of the possible attacker: %s' % arp_packet.src_hardware)


def unpack_arp_packet(ethernet_data: bytes) -> ARPPacket:
    src_hardware: int
    src_protocol: int
    dest_hardware: int
    dest_protocol: int
    src_hardware, src_protocol, dest_hardware, dest_protocol = struct.unpack('! 8x 6s 4s 6s 4s', ethernet_data[:28])
    arp_packet: ARPPacket = ARPPacket(__format_MAC_address(src_hardware), __format_IPv4_address(src_protocol),
                                      __format_MAC_address(dest_hardware), __format_IPv4_address(dest_protocol))
    arp_spoofing_check(arp_packet)
    return arp_packet
