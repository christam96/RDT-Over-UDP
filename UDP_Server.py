import binascii
import socket
import struct
import sys
import hashlib

#UDP_IP = "192.168.88.134" # Testing local to VM
UDP_IP = "127.0.0.1" # Testing local to local
UDP_PORT = 5005
unpacker = struct.Struct('I I 8s 32s')

# Create the socket and listen
sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
sock.bind((UDP_IP, UDP_PORT))

while True:
    # Receive Data
    data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
    UDP_Packet = unpacker.unpack(data)
    print('\nReceived Packet From: ', addr)
    print('Message Received: ', UDP_Packet)
    # Create the Checksum for comparison
    values = (UDP_Packet[0],UDP_Packet[1],UDP_Packet[2])
    packer = struct.Struct('I I 8s')
    packed_data = packer.pack(*values)
    chksum =  bytes(hashlib.md5(packed_data).hexdigest(), encoding="UTF-8")
    content = data[3:]
    seqNum = UDP_Packet[1]
    # Compare Checksums to test for corrupt data
    if UDP_Packet[3] == chksum:
        print('\nCheckSums Match, Packet OK')
        print('PACKET VALUES:')
        print('Ack number: ', UDP_Packet[0])
        print('Sequence number: ', UDP_Packet[1])
        print('Packet data: ', UDP_Packet[2])
        print('Checksum value: ', UDP_Packet[3])
        # Build UDP packet and send ACK to client
        values = (1, seqNum, b'ACK',chksum)
        UDP_Packet_Data = struct.Struct('I I 8s 32s')
        UDP_Packet = UDP_Packet_Data.pack(*values)
        sock.sendto(UDP_Packet, addr)
        print('Acknowledgement sent to client for packet. Packet details: ')
        print(UDP_Packet)
    else:
        print('Checksums Do Not Match, Packet Corrupt')
