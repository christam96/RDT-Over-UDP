import binascii
import socket
import struct
import sys
import hashlib
import time

#UDP_IP = "192.168.88.134" # Testing local to VM
UDP_IP = "127.0.0.1" # Testing local to local
UDP_PORT = 5005
unpacker = struct.Struct('I I 8s 32s')

print("UDP target IP:", UDP_IP)
print("UDP target port:", UDP_PORT)


################################
# First packet block (NCC-1701)
################################

# Create the Checksum for first UDP packet
values = (0,0,b'NCC-1701')
UDP_Data = struct.Struct('I I 8s')
packed_data = UDP_Data.pack(*values)
chksum =  bytes(hashlib.md5(packed_data).hexdigest(), encoding="UTF-8")

# Build the first UDP Packet (NCC-1701)
values = (0,0,b'NCC-1701',chksum)
UDP_Packet_Data = struct.Struct('I I 8s 32s')
UDP_Packet = UDP_Packet_Data.pack(*values)

# Create a new socket to send/receive
sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP

# Set timeout in preparation for receiving packet
timeout = sock.settimeout(0.09)

ack_received = False
while not ack_received:
    # Send the UDP Packet
    print('\nSending first packet...')
    sock.sendto(UDP_Packet, (UDP_IP, UDP_PORT))
    # Output the details of the first packet sent
    print('First packet sent to server. Packet details: ')
    print(UDP_Packet)

    try:
        # Receive message from server
        data, addr = sock.recvfrom(1024)
        print('\nPacket received from server!')
        UDP_Packet = unpacker.unpack(data)
        # Create the Checksum for comparison
        values = (UDP_Packet[0],UDP_Packet[1],UDP_Packet[2])
        packer = struct.Struct('I I 8s')
        packed_data = packer.pack(*values)
        # Compare Checksums to test for corrupt data
        if UDP_Packet[3] == chksum:
            ack_received = True
            # Output the details of the acknowledged packet
            print('ACK PACKET 1- Packet is not corrupt.')
            print('PACKET VALUES:')
            print('Ack number: ', UDP_Packet[0])
            print('Sequence number: ', UDP_Packet[1])
            print('Packet data: ', UDP_Packet[2])
            print('Checksum value: ', UDP_Packet[3])
        else:
            # Output the details of the unacknowledged packet
            print('NOT ACK - Packet may be corrupt.')
            print('PACKET VALUES:')
            print('Ack number: ', UDP_Packet[0])
            print('Sequence number: ', UDP_Packet[1])
            print('Packet Data: ', UDP_Packet[2])
            print('Checksum value: ', UDP_Packet[3])
    except:
        print("Timeout")
        continue;


################################
# Second packet block (NCC-1664)
################################

# Create the Checksum for second UDP packet
values = (0,1,b'NCC-1664')
UDP_Data = struct.Struct('I I 8s')
packed_data = UDP_Data.pack(*values)
chksum =  bytes(hashlib.md5(packed_data).hexdigest(), encoding="UTF-8")

# Build the second UDP Packet (NCC-1701)
values = (0,1,b'NCC-1664',chksum)
UDP_Packet_Data = struct.Struct('I I 8s 32s')
UDP_Packet = UDP_Packet_Data.pack(*values)

# Create a new socket to send/receive
sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP

# Set timeout in preparation for receiving packet
timeout = sock.settimeout(0.09)

ack_received = False
while not ack_received:
    # Send the UDP Packet
    print('\nSending second packet...')
    sock.sendto(UDP_Packet, (UDP_IP, UDP_PORT))
    # Output the details of the second packet sent
    print('Second packet sent to server. Packet details: ')
    print(UDP_Packet)

    try:
        # Receive message from server
        data, addr = sock.recvfrom(1024)
        print('\nPacket received from server!')
        UDP_Packet = unpacker.unpack(data)
        # Create the Checksum for comparison
        values = (UDP_Packet[0],UDP_Packet[1],UDP_Packet[2])
        packer = struct.Struct('I I 8s')
        packed_data = packer.pack(*values)
        # Compare Checksums to test for corrupt data
        if UDP_Packet[3] == chksum:
            ack_received = True
            # Output the details of the acknowledged packet
            print('ACK PACKET 2- Packet is not corrupt.')
            print('PACKET VALUES:')
            print('Ack number: ', UDP_Packet[0])
            print('Sequence number: ', UDP_Packet[1])
            print('Packet data: ', UDP_Packet[2])
            print('Checksum value: ', UDP_Packet[3])
        else:
            # Output the details of the unacknowledged packet
            print('NOT ACK - Packet may be corrupt.')
            print('PACKET VALUES:')
            print('Ack number: ', UDP_Packet[0])
            print('Sequence number: ', UDP_Packet[1])
            print('Packet Data: ', UDP_Packet[2])
            print('Checksum value: ', UDP_Packet[3])
    except:
        print("Timeout")
        continue;


################################
# Third packet block (NCC-1664)
################################

# Create the Checksum for third UDP packet
values = (0,0,b'NCC-1017')
UDP_Data = struct.Struct('I I 8s')
packed_data = UDP_Data.pack(*values)
chksum =  bytes(hashlib.md5(packed_data).hexdigest(), encoding="UTF-8")

# Build the third UDP Packet (NCC-1701)
values = (0,0,b'NCC-1017',chksum)
UDP_Packet_Data = struct.Struct('I I 8s 32s')
UDP_Packet = UDP_Packet_Data.pack(*values)

# Create a new socket to send/receive
sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP

# Set timeout in preparation for receiving packet
timeout = sock.settimeout(0.09)

ack_received = False
while not ack_received:
    # Send the UDP Packet
    print('\nSending third packet...')
    sock.sendto(UDP_Packet, (UDP_IP, UDP_PORT))
    # Output the details of the third packet sent
    print('Third packet sent to server. Packet details: ')
    print(UDP_Packet)

    try:
        # Receive message from server
        data, addr = sock.recvfrom(1024)
        print('\nPacket received from server!')
        UDP_Packet = unpacker.unpack(data)
        # Create the Checksum for comparison
        values = (UDP_Packet[0],UDP_Packet[1],UDP_Packet[2])
        packer = struct.Struct('I I 8s')
        packed_data = packer.pack(*values)
        # Compare Checksums to test for corrupt data
        if UDP_Packet[3] == chksum:
            ack_received = True
            # Output the details of the acknowledged packet
            print('ACK PACKET 3- Packet is not corrupt.')
            print('PACKET VALUES:')
            print('Ack number: ', UDP_Packet[0])
            print('Sequence number: ', UDP_Packet[1])
            print('Packet data: ', UDP_Packet[2])
            print('Checksum value: ', UDP_Packet[3])
        else:
            # Output the details of the unacknowledged packet
            print('NOT ACK - Packet may be corrupt.')
            print('PACKET VALUES:')
            print('Ack number: ', UDP_Packet[0])
            print('Sequence number: ', UDP_Packet[1])
            print('Packet Data: ', UDP_Packet[2])
            print('Checksum value: ', UDP_Packet[3])
    except:
        print("Timeout")
        continue;
