import dpkt
import socket
from collections import defaultdict

sender='130.245.145.12'
reciever= '128.208.2.198'

# analyze TCP flows
def analyze_pcap_tcp(file_path,sender,receiver):
    # load packets from PCAP file
    with open(file_path,'rb') as f:
        reader=dpkt.pcap.Reader(f)

        #initialize variables
        tcp_flows= defaultdict(lambda: {
            'status' : 'IDLE' ,
            'packets' : [] ,
            'start_time' : None,
            'end_time': None,
            'first_seq_ts': None,
            'last_ack_ts': None,
            'bytes_sent' : 0 ,
            'data_seq_set': set(),
            'scale' : 1,
        })
        total_flows=0
       
        #Iterate through each packet in the pcap file
        for ts, buf in reader: 
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                if not isinstance(ip.data, dpkt.tcp.TCP):
                    continue

                tcp = ip.data
                src_ip = socket.inet_ntoa(ip.src)  # convert src_ip bytes to string
                dst_ip = socket.inet_ntoa(ip.dst)
                src_port=tcp.sport
                dst_port=tcp.dport

                
                if (src_ip, dst_ip) != (sender, receiver) and (src_ip, dst_ip) != (receiver, sender):
                    continue

                flow_tuple = (src_ip, src_port, dst_ip, dst_port)
                tcp_flow = tcp_flows[flow_tuple]
                tcp_flow['packets'].append((ts, tcp,src_ip,dst_ip))

                if src_ip == sender and len(tcp.data) > 0:
                    if tcp.seq not in tcp_flow['data_seq_set']:
                        tcp_flow['bytes_sent'] +=  len(tcp.data)
                        tcp_flow['data_seq_set'].add(tcp.seq)
                    
                    if tcp_flow['first_seq_ts'] is None:
                        tcp_flow['first_seq_ts'] = ts 
                    tcp_flow['last_ack_ts']= ts
                    
                if tcp.flags & dpkt.tcp.TH_SYN and not (tcp.flags & dpkt.tcp.TH_ACK):
                    if tcp_flow['status'] == 'IDLE':
                        tcp_flow['status'] = 'OPEN'
                        tcp_flow['scale'] = get_window_scale(tcp)
                        total_flows += 1

            except Exception as e:
                print(f"Error processing packet: {e}")
                continue

        flow_id=1
        for flow_key, flow_data in tcp_flows.items():
            src_ip,src_port,dst_ip,dst_port=flow_key
            if flow_data['status'] == "IDLE":
                continue
            
            print(f"Tcp_Flow {flow_id}: {flow_key}")
            print(f"Source Port: {src_port}, \nSource IP: {src_ip}, \nDestination Port: {dst_port}, \nDestination IP: {dst_ip}")
            
            # Analyze first two transactions
            trans_count = [tcp for ts, tcp, src, dst in flow_data['packets']
                            if len(tcp.data) > 0 and tcp.flags & dpkt.tcp.TH_ACK 
                            and src == sender and dst == receiver]
            for i, tcp_pkt in enumerate(trans_count[:2],start=1):
                print(f"\nTransaction: {i}")
                print(f"Sequence Number: {tcp_pkt.seq}\nAcknowledgement Number: {tcp_pkt.ack}\nWindow Size: {tcp_pkt.win}")

            # Calculate the sender throughput and analyze the TCP flows
            start=flow_data ['first_seq_ts']
            end=flow_data['last_ack_ts']
            if start and end and end > start:
                sender_throughput = flow_data['bytes_sent'] /(end-start)
                print(f"\nSender_throughput: {sender_throughput} bytes/sec")

            #Estimate cwd size
            cwnd_sizes= estimate_cwnd(flow_data['packets'])
            trend = "Increasing Congestion Window Sizes" if len(cwnd_sizes) >= 2 and cwnd_sizes[0] < cwnd_sizes[1] else "Fluctuating/Unclear Growth"
            print(f"Congestion window size: {cwnd_sizes[ :3]}.\n{trend}")


            triple_acks,timeout_ts=find_retransmissions([(ts, tcp) for ts, tcp, _, _ in flow_data['packets']])
            print(f"\nTriple Duplicate ACK retransmission: {triple_acks}")
            print(f"Timeout retransmission: {0 if timeout_ts != -1 else 1}")
            print("-" * 42)
            print('\n')
            flow_id+=1
        print(f"Total TCP flows initiated: {total_flows}")

# parse TCP options to get window scale               
def get_window_scale(tcp):
    opts = dpkt.tcp.parse_opts(tcp.opts)
    for opt_type, opt_data in opts:
        if opt_type == dpkt.tcp.TCP_OPT_WSCALE and len(opt_data) == 1:
            return 2 ** opt_data[0]
    return 1  # default scale is 1

# estimation of congestion window sizes               
def estimate_cwnd(packets):
    cwnd_sizes = []
    flight_counter = 0
    last_ack_ts = None
    current_ack = None

    for ts, pkt, src, dst in packets:
        if src == sender and dst == reciever and len(pkt.data) > 0:
            flight_counter += 1
        elif pkt.flags & dpkt.tcp.TH_ACK and src == reciever and dst == sender:
            if pkt.ack != current_ack:
                if last_ack_ts is None or ts - last_ack_ts > 0.01:
                    if flight_counter > 0:
                        cwnd_sizes.append(flight_counter)
                    flight_counter = 0
                    last_ack_ts = ts
                current_ack = pkt.ack
    if flight_counter > 0:
        cwnd_sizes.append(flight_counter)
    return cwnd_sizes

# estimate retransmissions
def find_retransmissions(packets):
    triple_acks=0
    timeout_ts= -1
    seq={}
    dup_ack=defaultdict(int)

    for ts,pkt in packets:
        if pkt.flags & dpkt.tcp.TH_ACK:
            dup_ack[pkt.ack]+=1
            if dup_ack[pkt.ack]==3:
                triple_acks+=1

        if pkt.seq in seq:
            if ts - seq[pkt.seq] > 1 and timeout_ts == -1:
                timeout_ts = ts
        
        seq[pkt.seq] = ts
    
    return triple_acks,timeout_ts

if __name__ == "__main__":
    file_path="assignment2.pcap"
    # analyze TCP flows
    analyze_pcap_tcp(file_path,sender,reciever)