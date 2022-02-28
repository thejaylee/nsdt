import signal
import sys

import netifaces

from argparse import ArgumentParser
from random import randbytes
from time import sleep
from typing import List

from net import BroadcastSocket, list_interfaces
from protocol import NSDP_SRC_PORT, NSDP_DST_PORT, NsdpDatagram, NsdpMessageRecord


def sigint_handler(signal, frame):
    sys.exit()


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
