import argparse
import socket
import struct
from uuid import getnode as get_mac
from random import randint

MAX_BYTES = 65535
server_port = 10067
client_port = 68
class ServerPKT:
    def buildPacket(self, type):
        #macb = getMacInBytes()
        packet = b''
        packet += b'\x02'   #Message type: Boot Request (1)
        packet += b'\x01'   #Hardware type: Ethernet
        packet += b'\x06'   #Hardware address length: 6
        packet += b'\x00'   #Hops: 0
        packet += b'\x39\x03\xF3\x26'       #Transaction ID
        packet += b'\x00\x00'    #Seconds elapsed: 0
        packet += b'\x80\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
        #packet += b'\x00\x00\x00\x00'   #Your (client) IP address: 0.0.0.0
        packet += b'\xC0\xA8\x01\x64'   #Your (client) IP address: 0.0.0.0
        #packet += b'\x00\x00\x00\x00'   #Next server IP address: 0.0.0.0
        packet += b'\xC0\xA8\x01\x01'   #Next server IP address: 0.0.0.0		
        packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
        packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
        #packet += macb
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 67  #Server host name not given
        packet += b'\x00' * 125 #Boot file name not given
        packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
        packet += b'\x35\x01' + type   #Option: (t=53,l=1) DHCP Message Type = DHCP Discover
        #packet += b'\x3d\x06\x00\x26\x9e\x04\x1e\x9b'   #Option: (t=61,l=6) Client identifier
        packet += b'\x3d\x06\x00\x26\x9e\x04\x1e\x9b'
        packet += b'\x37\x03\x03\x01\x06'   #Option: (t=55,l=3) Parameter Request List
        packet += b'\xff'   #End Option
        return packet

class ClientPKT:
    def buildPacket(self, type):
        #macb = getMacInBytes()
        packet = b''
        packet += b'\x01'   #Message type: Boot Request (1)
        packet += b'\x01'   #Hardware type: Ethernet
        packet += b'\x06'   #Hardware address length: 6
        packet += b'\x00'   #Hops: 0
        packet += b'\x39\x03\xF3\x26'       #Transaction ID
        packet += b'\x00\x00'    #Seconds elapsed: 0
        packet += b'\x80\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #Your (client) IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
        packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
        #packet += macb
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 67  #Server host name not given
        packet += b'\x00' * 125 #Boot file name not given
        packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
        packet += b'\x35\x01' + type  #Option: (t=53,l=1) DHCP Message Type = DHCP Discover
        #packet += b'\x3d\x06\x00\x26\x9e\x04\x1e\x9b'   #Option: (t=61,l=6) Client identifier
        packet += b'\x3d\x06\x00\x26\x9e\x04\x1e\x9b'
        packet += b'\x37\x03\x03\x01\x06'   #Option: (t=55,l=3) Parameter Request List
        packet += b'\xff'   #End Option
        return packet


def server(port):
    dhcps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dhcps.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) #broadcast
    dhcps.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    dhcps.bind(('0.0.0.0', port))
    serverPacket = ServerPKT()    
    while True:
        print('Listening at {}'.format(dhcps.getsockname()))
        while True:
            data, address = dhcps.recvfrom(MAX_BYTES)			
            text = 'I want a ip'
            print('The client at {} says: {!r}'.format(address, text))
            dhcps.sendto(serverPacket.buildPacket(b'\x02'), ('255.255.255.255',client_port))
            break
        while True:
            data, address = dhcps.recvfrom(MAX_BYTES)
            text = 'REQUEST'
            print('The client at {} says: {!r}'.format(address, text))          
            dhcps.sendto(serverPacket.buildPacket(b'\x05'), ('255.255.255.255',client_port))
            break

def client(port):
    dhcps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dhcps.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) #broadcast
    dhcps.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        dhcps.bind(('', port))    #we want to send from port 68
    except Exception as e:
        print('port %d in use...' % port)
        dhcps.close
        input('press any key to quit...')
        exit()

    #buiding and sending the DHCPDiscover packet
    clientPacket = ClientPKT()
    dhcps.sendto(clientPacket.buildPacket(b'\x01'), ('255.255.255.255', server_port))
    print('DHCP Discover sent waiting for reply...')
	
    try:
        while True:
            data, address = dhcps.recvfrom(MAX_BYTES)
            text = 'server OFFER ' #str(data[16:20], encoding = "utf-8")  
            print('The server at {} says: {!r}'.format(address, text))
            dhcps.sendto(clientPacket.buildPacket(b'\x03'), ('255.255.255.255', server_port))
            break
    except socket.timeout as e:
        print(e)
    
    try:
        while True:
            data, address = dhcps.recvfrom(MAX_BYTES)
            text = 'ACKNOWLEDGE'
            print('The server at {} says: {!r}'.format(address, text))
            break
    except socket.timeout as e:
        print(e)

if __name__ == '__main__':
    choices = {'client': client, 'server': server}
    parser = argparse.ArgumentParser(description='Send and receive UDP locally')
    parser.add_argument('role', choices=choices, help='which role to play')
    args = parser.parse_args()
    function = choices[args.role]
    if args.role == 'server':
    	function(server_port)
    else:
    	function(client_port)