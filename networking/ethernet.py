import socket
import struct


class Ethernet:

    def __init__(self, raw_data):

        dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])

        self.proto = socket.htons(prototype)
        self.data = raw_data[14:]



