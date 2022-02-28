import signal
import socket
import struct
import sys

import netifaces

from argparse import ArgumentParser
from dataclasses import dataclass
from enum import IntEnum
from random import randbytes
from threading import Thread
from time import sleep
from typing import List, Union

import pdb


NSDP_SRC_PORT = 63321
NSDP_DST_PORT = 63322
SOCK_BUF_SZ = 0xffff


ByteData = Union[bytes, bytearray]

def sigint_handler(signal, frame):
    sys.exit()

def list_interfaces():
    return {iface: netifaces.ifaddresses(iface) for iface in netifaces.interfaces()}
    #interfaces: List = socket.getaddrinfo(host=socket.gethostname(), port=None, family=socket.AF_INET)


class Args():
    def __init__(self, argv: List):
        self.parser = parser = ArgumentParser(description='NetGear Switch Discovery Tool')
        parser.add_argument('-l', action='store_true', help='list interfaces', dest='list_interfaces')
        parser.add_argument('-i', help='interface to use', type=int, metavar='<num>', dest='interface_num')
        parser.add_argument('-t', help='message types to interrogate', type=__class__.hex, metavar=('<hex>', 'hex'), nargs='+', dest='message_types')
        parser.add_argument('--list-message-types', action='store_true', help='list message types', dest='list_message_types')
        self._parsed = parser.parse_args(argv)

    @property
    def parsed(self):
        return self._parsed

    def help(self):
        self.parser.print_help()

    @staticmethod
    def hex(value: str) -> int:
        try:
            return int(str(value), 16)
        except ValueError:
            return 0


@dataclass(frozen=True)
class OffsetLength:
    offset: int
    length: int

    def read_slice(self):
        return slice(self.offset, self.offset + self.length)

    def write_slice(self):
        return slice(self.offset, self.offset + self.length - 1)


class Datagram(bytearray):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def update(self, offlen: OffsetLength, data: ByteData) -> None:
        if offlen.offset == -1:
            self += data
        else:
            self[offlen.write_slice()] = data[:offlen.length]
        return self

    def read_offset(self, offlen: OffsetLength) -> ByteData:
        return self[offlen.read_slice()]


class NsdpMessageRecord:
    class Type(IntEnum):
        DEV_MODEL= 0x0001
        DEV_NAME = 0x0003
        DEV_MAC = 0x0004
        DEV_SYSTEM_LOCATION = 0x0005
        DEV_CURRENT_IP = 0x0006
        DEV_NETMASK = 0x0007
        ROUTER_IP = 0x0008
        ADMIN_PASS = 0x000A
        FIRMWARE_SLOT_1 = 0x000D
        FIRMWARE_SLOT_2 = 0x000E
        NEXT_FIRMWARE_SLOT = 0x000F
        PORTS_STATUS = 0x0C00
        PORT_TRAFFIC_STAT = 0x1000
        GET_VLAN_INFO = 0x2800
        DELETE_VLAN = 0x2C00
        PORT_MIRRORING = 0x5C00
        DEV_SERIAL_NUM = 0x7800

    def __init__(self, msg_type: int, msg_data: ByteData):
        self.type = msg_type
        self.data = msg_data

    def __bytes__(self):
        return struct.pack('!H', self.type) + struct.pack('!H', len(self.data)) + self.data

    def __repr__(self):
        return f"{self.__class__}(type=0x{self.type:02x} len=0x{len(self.data):02x} data={self.data.hex(':')})"

    def __str__(self):
        out = f"type=0x{self.type:02x} "
        try:
            # I don't actually know if the strings are UTF-8
            if self.type == self.Type.DEV_MODEL:
                out += f"device_model=\"{self.data.decode('utf-8')}\""
            elif self.type == self.Type.DEV_NAME:
                out += f"device_name=\"{self.data.decode('utf-8')}\""
            elif self.type == self.Type.DEV_CURRENT_IP:
                out += f"device_ip={socket.inet_ntoa(self.data)}"
            elif self.type == self.Type.DEV_NETMASK:
                out += f"device_netmask={socket.inet_ntoa(self.data)}"
            elif self.type == self.Type.ROUTER_IP:
                out += f"router_ip={socket.inet_ntoa(self.data)}"
            elif self.type == self.Type.FIRMWARE_SLOT_1:
                out += f"firmware_slot_1=\"{self.data.decode('utf-8')}\""
            elif self.type == self.Type.FIRMWARE_SLOT_2:
                out += f"firmware_slot_2=\"{self.data.decode('utf-8')}\""
            elif self.type == self.Type.PORT_TRAFFIC_STAT:
                out += f"port={hex(self.data[0])} " \
                    f"bytes_in={struct.unpack('!Q', self.data[1:9])[0]} " \
                    f"bytes_out={struct.unpack('!Q', self.data[9:17])[0]} " \
                    f"???={struct.unpack('!Q', self.data[17:25])[0]} " \
                    f"???={struct.unpack('!Q', self.data[25:33])[0]} " \
                    f"???={struct.unpack('!Q', self.data[33:41])[0]} " \
                    f"crc_error={struct.unpack('!Q', self.data[41:49])[0]} "
            elif self.type == self.Type.DEV_SERIAL_NUM:
                out += f"serial_num=\"{self.data.decode('utf-8')}\""
            elif self.type == self.Type.PORT_MIRRORING:
                portmask = struct.unpack('!H', self.data[1:])[0]
                out += f"dest_port={self.data[0]} src_ports="
                out += ''.join(['Y' if portmask & p else 'N' for p in [0x80, 0x40, 0x20, 0x10, 0x08]])
            else:
                out += f"len=0x{len(self.data):02x} data={self.data.hex(':')} ({self.data})"
        except:
            out += f"len=0x{len(self.data):02x} data={self.data.hex(':')}"
        return out


# https://en.wikipedia.org/wiki/Netgear_Switch_Discovery_Protocol
class NsdpDatagram:
    OFFSET_PROTO_VER  = OffsetLength(0x00, 0x01)
    OFFSET_OPCODE     = OffsetLength(0x01, 0x01)
    OFFSET_RESULT     = OffsetLength(0x02, 0x02)
    OFFSET_UNKNOWN_1  = OffsetLength(0x04, 0x04)
    OFFSET_HOST_MAC   = OffsetLength(0x08, 0x06)
    OFFSET_DEV_MAC    = OffsetLength(0x0E, 0x06)
    OFFSET_UNKNOWN_2  = OffsetLength(0x14, 0x02)
    OFFSET_SEQUENCE   = OffsetLength(0x16, 0x02)
    OFFSET_PROTO_SIG  = OffsetLength(0x18, 0x04)
    OFFSET_UNKNOWN_3  = OffsetLength(0x1C, 0x04)
    OFFSET_MESSAGE    = OffsetLength(0x20, -0x04)
    OFFSET_END_MARKER = OffsetLength(-0x01, 0x04)

    PROTO_VERSION = b'\x01'
    PROTO_SIG = b'NSDP'
    END_MARKER = b'\xFF\xFF\x00\x00'

    class OpCode(IntEnum):
        READ_REQ   = 0x01
        READ_RESP  = 0x02
        WRITE_REQ  = 0x03
        WRITE_RESP = 0x04

    def __init__(self, *args, **kwargs):
        # first byte is proto version, always 0x01
        self._opcode = b'\x00'
        self._result = b'\x00\x00'
        self._host_mac = b'\x00\x00\x00\x00\x00\x00'
        self._dev_mac = b'\x00\x00\x00\x00\x00\x00'
        self._sequence = b'\x00\x00'
        self._messages = []

    def __bytes__(self) -> bytes:
        dgram = Datagram()
        dgram.update(__class__.OFFSET_PROTO_VER, __class__.PROTO_VERSION)
        dgram.update(__class__.OFFSET_OPCODE, self._opcode)
        dgram.update(__class__.OFFSET_RESULT, self._result)
        dgram.update(__class__.OFFSET_UNKNOWN_1, b'\x00\x00\x00\x00')
        dgram.update(__class__.OFFSET_HOST_MAC, self._host_mac)
        dgram.update(__class__.OFFSET_DEV_MAC, self._dev_mac)
        dgram.update(__class__.OFFSET_UNKNOWN_2, b'\x00\x00')
        dgram.update(__class__.OFFSET_SEQUENCE, self._sequence)
        dgram.update(__class__.OFFSET_PROTO_SIG, __class__.PROTO_SIG)
        dgram.update(__class__.OFFSET_UNKNOWN_3, b'\x00\x00\x00\x00')
        for msg in self._messages:
            dgram += bytes(msg)
        dgram.update(__class__.OFFSET_END_MARKER, __class__.END_MARKER)
        return bytes(dgram)

    def __str__(self) -> str:
        output = f"Neatgear Switch Discovery(\n"
        output += f"\topcode(0x{self._opcode.hex()})\n"
        output += f"\tresult(0x{self._result.hex()})\n"
        output += f"\thost_mac({self._host_mac.hex(':')})\n"
        output += f"\tdev_mac({self._dev_mac.hex(':')})\n"
        output += f"\tsequence(0x{self._sequence.hex()})\n"
        output += f"\tmessages(\n"
        for msg in self._messages:
            output += f"\t\t{str(msg)}\n"
        output += "\t)\n)"
        return output

    def add_message(self, message: NsdpMessageRecord):
        self._messages.append(message)

    @classmethod
    def from_bytes(cls, data: ByteData):
        dgram = Datagram(data)
        nsdp = cls()
        nsdp._opcode = dgram.read_offset(__class__.OFFSET_OPCODE)
        nsdp._result = dgram.read_offset(__class__.OFFSET_RESULT)
        nsdp._host_mac = dgram.read_offset(__class__.OFFSET_HOST_MAC)
        nsdp._dev_mac = dgram.read_offset(__class__.OFFSET_DEV_MAC)
        nsdp._sequence = dgram.read_offset(__class__.OFFSET_SEQUENCE)
        nsdp._messages = NsdpDatagram.decode_messages(dgram[__class__.OFFSET_MESSAGE.offset:-4])
        return nsdp

    @classmethod
    def decode_messages(self, data: ByteData):
        offset = 0
        messages = []
        while offset < len(data):
            msg_type = struct.unpack_from('!H', data, offset=offset)[0]
            msg_len = struct.unpack_from('!H', data, offset=offset+2)[0]
            messages.append(NsdpMessageRecord(msg_type, data[offset+4:offset+4 + msg_len]))
            offset += 4 + msg_len
        return messages


    @property
    def opcode(self) -> int:
        return struct.unpack('!B', self._opcode)
    @opcode.setter
    def opcode(self, value: Union[int, ByteData]):
        self._opcode = struct.pack('!B', value % 0x100) if isinstance(value, int) else value[:1]

    @property
    def result(self) -> int:
        return struct.unpack('!H', self._result)
    @result.setter
    def result(self, value: Union[int, ByteData]):
        self._result = struct.pack('!H', value % 0x10000) if isinstance(value, int) else value[:2]

    @property
    def sequence(self) -> int:
        return struct.unpack('!H', self._sequence)
    @sequence.setter
    def sequence(self, value: Union[int, ByteData]):
        self._sequence = struct.pack('!H', value % 0x10000) if isinstance(value, int) else value[:2]

    @property
    def host_mac(self) -> bytes:
        return self._host_mac
    @host_mac.setter
    def host_mac(self, value: ByteData):
        self._host_mac = value[:6]

    @property
    def dev_mac(self) -> bytes:
        return self._dev_mac
    @dev_mac.setter
    def dev_mac(self, value: ByteData):
        self._dev_mac = value[:6]

    @property
    def proto_ver(self):
        return __class__.PROTO_VERSION

    @property
    def proto_sig(self):
        return __class__.PROTO_SIG


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


if __name__ == '__main__':
    signal.signal(signal.SIGINT, sigint_handler)
    args = Args(sys.argv[1:])

    interfaces = list_interfaces()
    if args.parsed.list_interfaces:
        for idx, (iface, details) in enumerate(interfaces.items()):
            print(f"{idx + 1}. {details[netifaces.AF_INET][0]['addr']} / {details[netifaces.AF_INET][0]['netmask']}")
        sys.exit()

    if args.parsed.list_message_types:
        print("Known message types:")
        print("\t0x0001\tDevice model")
        print("\t0x0003\tDevice given name")
        print("\t0x0004\tDevice MAC-address")
        print("\t0x0005\tDevice system location")
        print("\t0x0006\tDevice current IP-address (may be unsupported by certain devices)")
        print("\t0x0007\tDevice IP-network mask (may be unsupported by certain devices)")
        print("\t0x0008\tRouter IP-address (may be unsupported by certain devices)")
        print("\t0x000A\tadministration password")
        print("\t0x000D\tDevice Firmware version slot 1 (may be unsupported by certain devices)")
        print("\t0x000E\tDevice Firmware version slot 2 (may be unsupported by certain devices)")
        print("\t0x000F\tNext active firmware slot after reboot (01 = 1, 02 = 2, may be unsupported by certain devices)")
        print("\t0x001A\tEncrypted pass for writes?")
        print("\t0x0C00\tSpeed/link status of ports")
        print("\t0x1000\tPort Traffic Statistic")
        print("\t0x2800\tGet VLAN info")
        print("\t0x3400\tQoS Global Config")
        print("\t0x2C00\tDelete VLAN (write only)")
        print("\t0x4C00\tRate Limit")
        print("\t0x5400\tBroadcast Filtering")
        print("\t0x5C00\tPort Mirroring")
        print("\t0x7800\tDevice Serial Number")
        print("\t0x9000\tLoop Detection")
        print("\t0xa800\tPower Saving Mode")
        sys.exit()

    if (
        not args.parsed.interface_num or args.parsed.interface_num > len(interfaces) or
        not args.parsed.message_types or len(args.parsed.message_types) < 1
    ):
        args.help()
        sys.exit()

    interface_name = list(interfaces)[args.parsed.interface_num - 1]
    interface = interfaces[interface_name]
    nsdp = NsdpDatagram()
    nsdp.opcode = NsdpDatagram.OpCode.READ_REQ
    nsdp.host_mac = bytes.fromhex(interface[netifaces.AF_LINK][0]['addr'].replace(':', ''))
    nsdp.dev_mac = bytes(6)
    nsdp.sequence = randbytes(2)
    for msg_type in args.parsed.message_types:
        nsdp.add_message(NsdpMessageRecord(msg_type, bytes()))

    broadcast = BroadcastSocket(ip=interface[netifaces.AF_INET][0]['addr'], src_port=NSDP_SRC_PORT, dst_port=NSDP_DST_PORT)
    broadcast.send(bytes(nsdp))

    while True:
        sleep(1)
