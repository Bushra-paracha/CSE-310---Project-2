# README for Programming Assignment 2

#### CSE 310 - Programming Assignment 2 Summary
Student Name: Bushra Paracha
Assignment: Programming Assignment 2
Due Date: March 27, 2025
Fiename: analysis_pcap_tcp.py

### Overview

The goal of this assignment was to analyze a PCAP file and extract flow-level information about TCP traffic using Python and the dpkt library. The assignment required parsing TCP flows, identifying transaction details, calculating throughput, estimating congestion windows, and detecting retransmissions.

The PCAP file used was assignment2.pcap, which contains TCP packet captures between the sender 130.245.145.12 and the receiver 128.208.2.198. The trace was captured at the sender.
Both sender and reciever are hardcoded 

## How to Run:
Ensure Python 3 is installed.

Install the required library using:*
*pip install dpkt

Place assignment2.pcap in the same directory as analysis_pcap_tcp.py.

Run the script:
python analysis_pcap_tcp.py

# Output
For each TCP flow, the following is printed:
Source and destination IP/ports
First two transactions (seq, ack, window size)
Sender_Throughput in bytes/sec
First 3 congestion window sizes
Number of retransmissions due to triple duplicate ACKs and timeouts
