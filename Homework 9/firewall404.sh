#!/bin/sh


# Homework Number: 9
# Name: Nikita Ravi
# ECN Login: ravi30	
# Due Date: 04/06/2021

#-------QUESTION ONE---------
# Flush the previous rules
sudo iptables -t filter -F
sudo iptables -t nat -F

# Delete previous chains
sudo iptables -t filter -X
sudo iptables -t nat -X

#-------QUESTION TWO---------
# For all outgoing packets, change their source IP address to your own machine's IP addres
# -t table
# -A is to append a new rule
# POSTROUTING for altering packets immediately after the routing decision
# -o Specifying an output interface 
# -j specifies action needed to be taken
# MASQUERADE can substitute a DHCP IP address
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE 

#-------QUESTION THREE---------
# Block all new packets coming from yahoo.com
# -t table name
# INPUT for processing all incoming packets
# -A is to append a new rule
# -s source address
# -j action to be taken
# DROP drop all packets 
# IP address obtained by pinging the website
sudo iptables -t filter -A INPUT -p tcp -s yahoo.com -j DROP

#-------QUESTION FOUR---------
# Block  your  computer  from  being pinged  by  all  other  hosts
# -t table
# -A is to append a new rule
# INPUT for processing all incominh packets
# -p for specifying the protocol
# icmp is the type of protocol
# --icmp-type to specify type of icmp
# -j action to be taken
# DROP drop all packets 
sudo iptables -t filter -A INPUT -p icmp --icmp-type echo-request -j DROP

#-------QUESTION FIVE---------
# Set up port-forwarding from an unused port of your choice to port 22 on your computer
# Testing with unused port 5678 
# -t table
# -A is to append a new rule
# PREROUTING for altering packets as soon as they come in
# -p for specifying the protocol
# --d-port destination port
# -j action to be taken
# REDIRECT redirect to different destination
# --to-ports specifies which port it needs to get directed to
# PORT1=5678
# PORT2=22

sudo iptables -t nat -A PREROUTING -p tcp --dport 5678 -j REDIRECT --to-ports 22
sudo iptables -t nat -A PREROUTING -p udp --dport 5678 -j REDIRECT --to-ports 22


#-------QUESTION SIX---------
# Allow for SSH access (port 22) to your machine from only the engineering.purdue.edu domain
# -t table
# -A is to append a new rule
# INPUT for processing all incominh packets
# -p for specifying the protocol
# --d-port destination port
# -s source address
# -j action to be taken
# ACCEPT accept packet
# DROP drop packet 
# IP address obtained by pinging the website
sudo iptables -t filter -A INPUT -p tcp --dport 22 -s 128.46.104.20 -j ACCEPT
sudo iptables -t filter -A INPUT -p tcp --dport 22 ! -s 128.46.104.20 -j DROP

#-------QUESTION SEVEN---------
# write a rule for preventing DoS attacks by limiting connection requests to 30 per minute after a total of 60 connections have been made
# -t table
# -A is to append a new rule
# FORWARD for processing all packets being routed through the machine
# -p for specifying the protocol
# --syn this rule is meant for SYN packets
# -m to match
# state to check if a connection is established
# limit to use limit functions
# --limit-burst to limit to 60 packets max
# --limit to limit to x packets per minute
# -j action to be taken
# DROP drop packets
sudo iptables -t filter -A FORWARD -p tcp --syn -m state --state ESTABLISHED -m limit --limit-burst 60 --limit 30/m -j DROP

#-------QUESTION EIGHT---------
# Drop any other packets if they are not caught by the above rules
# -t table
# -A is to append a new rule
# INPUT for processing all incominh packets 
# -j action to be taken
# REJECT reject packets and output an error
sudo iptables -t filter -A INPUT -j REJECT
