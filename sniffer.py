import socket
import json
from networking.ethernet import Ethernet
from networking.ipv4 import IPv4
from networking.tcp import TCP
from networking.http import HTTP

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    i = 0

    while True:
        raw_data, addr = conn.recvfrom(65535)
        
        # Unpack Ethernet
        eth = Ethernet(raw_data)

        # Unpack IPv4
        if eth.proto == 8:
            ipv4 = IPv4(eth.data)

            # Unpack TCP
            if ipv4.proto == 6:
                tcp = TCP(ipv4.data)

                # Unpack HTTP
                if len(tcp.data) > 0:
                    if tcp.src_port == 80 or tcp.dest_port == 80:
                        http = HTTP(tcp.data)
                        if len(http.data) < 10:
                            continue
                        i += 1
                        print('PACKET [' + str(i) + ']\n')
                        print('\t\t   ' + 'Source: {}:{}, Target: {}:{}'.format(ipv4.src, tcp.src_port, ipv4.target, tcp.dest_port))
                        print('\t\t   ' + 'HTTP Data:')
                        http_info = str(http.data).split('\n')
                        for line in http_info:
                            print('\t\t\t   ' + str(line))
                        pack = {
                            "packet_number": i,
                            "source": str(ipv4.src) + ':' + str(tcp.src_port),
                            "destination": str(ipv4.target) + ':' + str(tcp.dest_port),
                            "data:": http_info
                        }
                        dump = json.dumps(pack)
                        print(dump)

main()
