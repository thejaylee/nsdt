import socket

import netifaces

from argparse import ArgumentParser
from random import randbytes
from threading import Thread

from datatypes import ByteData
from protocol import NsdpDatagram


SOCK_BUF_SZ = 0xffff


def list_interfaces():
    return {iface: netifaces.ifaddresses(iface) for iface in netifaces.interfaces()}


class BroadcastSocket():
    def __init__(self, ip: str, src_port: int, dst_port: int):
        self.ip = ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.sock : socket.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind((ip, src_port))
        self.sock.settimeout(None)
        self.listening = True
        self.recv_thread = Thread(target=self._receiver, daemon=True)
        self.recv_thread.start()

    def _receiver(self):
        while self.listening:
            (data, addr) = self.sock.recvfrom(SOCK_BUF_SZ)
            nsdp = NsdpDatagram.from_bytes(data)
            print(f"----- {addr[0]}:{addr[1]} -----")
            print(str(nsdp))

    def send(self, data: ByteData):
        self.sock.sendto(data, ('255.255.255.255', self.dst_port))
