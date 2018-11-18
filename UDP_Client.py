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

# Array holding packets to send to server
packetArr = [b'NCC-1701', b'NCC-1664', b'NCC-1017']

# Initialize variables for ackNum and b (which will be used to determine each packets seqNum)
# seqNum is switched between 0 and 1 by incrementing b after modulusing b by 2 on each iteration of the packet loop
ackNum = 0
b = 0

for packet in packetArr:

    # Here we use the variable b to determine the value of seqNum on each iteration of the packet loop
    # By modulusing b by 2 before incrementing b, seqNum will start at 0 and will switch between 0 and 1 on each iteration of the loop
    seqNum = b % 2
    b = b + 1

    # Create the Checksum for UDP packet
    values = (ackNum,seqNum,packet)
    UDP_Data = struct.Struct('I I 8s')
    packed_data = UDP_Data.pack(*values)
    chksum =  bytes(hashlib.md5(packed_data).hexdigest(), encoding="UTF-8")

    # Build the UDP Packet
    values = (ackNum,seqNum,packet,chksum)
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
        print('\nSending packet: ', packet)
        sock.sendto(UDP_Packet, (UDP_IP, UDP_PORT))
        # Output the details of the first packet sent
        print(packet, ' sent to server. Packet details: ')
        print(UDP_Packet)

        try:
            # Receive message from server
            data, addr = sock.recvfrom(1024)
            print('\nAcknowledgement received from server!')
            UDP_Packet = unpacker.unpack(data)
            # Create the Checksum for comparison
            values = (UDP_Packet[0],UDP_Packet[1],UDP_Packet[2])
            packer = struct.Struct('I I 8s')
            packed_data = packer.pack(*values)
            # Compare Checksums to test for corrupt data
            if UDP_Packet[3] == chksum:
                ack_received = True
                # Output the details of the acknowledged packet
                print('ACK RE: ', packet)
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
