import numpy as np
import pyshark

# Storage for flow data
flows = {}

def calculate_flow_features(packet):
    # Identify the flow based on source IP, destination IP, source port, and destination port
    flow_id = (packet.ip.src, packet.ip.dst, int(packet.tcp.srcport), int(packet.tcp.dstport))
    
    if flow_id not in flows:
        flows[flow_id] = {
            "start_time": float(packet.sniff_time.timestamp()),
            "end_time": float(packet.sniff_time.timestamp()),
            "total_fwd_packets": 0,
            "total_bwd_packets": 0,
            "total_length_of_fwd_packets": 0,
            "total_length_of_bwd_packets": 0,
            "fwd_packet_lengths": [],
            "bwd_packet_lengths": [],
            "fwd_iat_times": [],
            "bwd_iat_times": [],
            "last_fwd_packet_time": float(packet.sniff_time.timestamp()),
            "last_bwd_packet_time": None,
            "syn_flag_count": 0,
            "fin_flag_count": 0,
            "rst_flag_count": 0,
            "psh_flag_count": 0,
            "ack_flag_count": 0,
            "urg_flag_count": 0,
            "ece_flag_count": 0,
            "fwd_psh_flags": 0,
            "bwd_psh_flags": 0,
            "fwd_urg_flags": 0,
            "bwd_urg_flags": 0,
            "fwd_header_length": int(packet.tcp.hdr_len),
            "bwd_header_length": 0,
            "fwd_packets_sec": 0,
            "bwd_packets_sec": 0,
            "subflow_fwd_bytes": 0,
            "subflow_bwd_bytes": 0,
            "init_win_bytes_forward": int(packet.tcp.window_size),
            "init_win_bytes_backward": None,
            "act_data_pkt_fwd": 0,
            "act_data_pkt_bwd": 0,
            "min_seg_size_forward": None,
            "down_up_ratio": 0,
            "average_packet_size": 0,
            "cwe_flag_count": 0,  # Placeholder for CWE flag count
        }

    # Update flow information
    flow = flows[flow_id]
    flow["end_time"] = float(packet.sniff_time.timestamp())

    # Determine if the packet is a forward or backward packet
    if packet.ip.src == flow_id[0]:
        # Forward packet
        flow["total_fwd_packets"] += 1
        flow["total_length_of_fwd_packets"] += int(packet.length)
        flow["fwd_packet_lengths"].append(int(packet.length))
        
        if flow["last_fwd_packet_time"] is not None:
            iat = float(packet.sniff_time.timestamp()) - flow["last_fwd_packet_time"]
            flow["fwd_iat_times"].append(iat)
        
        flow["last_fwd_packet_time"] = float(packet.sniff_time.timestamp())
        flow["act_data_pkt_fwd"] += 1
        flow["subflow_fwd_bytes"] += int(packet.length)

        # Check and update flag counts
        if 'SYN' in packet.tcp.flags:
            flow["syn_flag_count"] += 1
        if 'FIN' in packet.tcp.flags:
            flow["fin_flag_count"] += 1
        if 'RST' in packet.tcp.flags:
            flow["rst_flag_count"] += 1
        if 'PSH' in packet.tcp.flags:
            flow["psh_flag_count"] += 1
            flow["fwd_psh_flags"] += 1
        if 'ACK' in packet.tcp.flags:
            flow["ack_flag_count"] += 1
        if 'URG' in packet.tcp.flags:
            flow["urg_flag_count"] += 1
            flow["fwd_urg_flags"] += 1
        if 'ECE' in packet.tcp.flags:
            flow["ece_flag_count"] += 1

    else:
        # Backward packet
        flow["total_bwd_packets"] += 1
        flow["total_length_of_bwd_packets"] += int(packet.length)
        flow["bwd_packet_lengths"].append(int(packet.length))
        
        if flow["last_bwd_packet_time"] is not None:
            iat = float(packet.sniff_time.timestamp()) - flow["last_bwd_packet_time"]
            flow["bwd_iat_times"].append(iat)
        
        flow["last_bwd_packet_time"] = float(packet.sniff_time.timestamp())
        flow["act_data_pkt_bwd"] += 1
        flow["subflow_bwd_bytes"] += int(packet.length)
        
        if flow["init_win_bytes_backward"] is None:
            flow["init_win_bytes_backward"] = int(packet.tcp.window_size)

        if 'PSH' in packet.tcp.flags:
            flow["bwd_psh_flags"] += 1
        if 'URG' in packet.tcp.flags:
            flow["bwd_urg_flags"] += 1

    # Calculate Down/Up Ratio and Average Packet Size
    if flow["total_bwd_packets"] > 0:
        flow["down_up_ratio"] = flow["total_fwd_packets"] / flow["total_bwd_packets"]
    if flow["fwd_packet_lengths"] or flow["bwd_packet_lengths"]:
        flow["average_packet_size"] = (sum(flow["fwd_packet_lengths"]) + sum(flow["bwd_packet_lengths"])) / (flow["total_fwd_packets"] + flow["total_bwd_packets"])

    # Return features for prediction
    features = [
        int(packet.tcp.dstport),  # Destination_Port
        flow["end_time"] - flow["start_time"],  # Flow_Duration
        flow["total_fwd_packets"],  # Total_Fwd_Packets
        flow["total_bwd_packets"],  # Total_Backward_Packets
        flow["total_length_of_fwd_packets"],  # Total_Length_of_Fwd_Packets
        flow["total_length_of_bwd_packets"],  # Total_Length_of_Bwd_Packets
        max(flow["fwd_packet_lengths"]) if flow["fwd_packet_lengths"] else 0,  # Fwd_Packet_Length_Max
        min(flow["fwd_packet_lengths"]) if flow["fwd_packet_lengths"] else 0,  # Fwd_Packet_Length_Min
        np.mean(flow["fwd_packet_lengths"]) if flow["fwd_packet_lengths"] else 0,  # Fwd_Packet_Length_Mean
        np.std(flow["fwd_packet_lengths"]) if flow["fwd_packet_lengths"] else 0,  # Fwd_Packet_Length_Std
        max(flow["bwd_packet_lengths"]) if flow["bwd_packet_lengths"] else 0,  # Bwd_Packet_Length_Max
        min(flow["bwd_packet_lengths"]) if flow["bwd_packet_lengths"] else 0,  # Bwd_Packet_Length_Min
        np.mean(flow["bwd_packet_lengths"]) if flow["bwd_packet_lengths"] else 0,  # Bwd_Packet_Length_Mean
        np.std(flow["bwd_packet_lengths"]) if flow["bwd_packet_lengths"] else 0,  # Bwd_Packet_Length_Std
        (flow["total_length_of_fwd_packets"] + flow["total_length_of_bwd_packets"]) / 
        (flow["end_time"] - flow["start_time"]) if flow["end_time"] - flow["start_time"] > 0 else 0,  # Flow_Bytes_Sec
        (flow["total_fwd_packets"] + flow["total_bwd_packets"]) / 
        (flow["end_time"] - flow["start_time"]) if flow["end_time"] - flow["start_time"] > 0 else 0,  # Flow_Packets_Sec
        np.mean(flow["fwd_iat_times"] + flow["bwd_iat_times"]) if (flow["fwd_iat_times"] + flow["bwd_iat_times"]) else 0,  # Flow_IAT_Mean
        np.std(flow["fwd_iat_times"] + flow["bwd_iat_times"]) if (flow["fwd_iat_times"] + flow["bwd_iat_times"]) else 0,  # Flow_IAT_Std
        max(flow["fwd_iat_times"] + flow["bwd_iat_times"]) if (flow["fwd_iat_times"] + flow["bwd_iat_times"]) else 0,  # Flow_IAT_Max
        min(flow["fwd_iat_times"] + flow["bwd_iat_times"]) if (flow["fwd_iat_times"] + flow["bwd_iat_times"]) else 0,  # Flow_IAT_Min
        sum(flow["fwd_iat_times"]) if flow["fwd_iat_times"] else 0,  # Fwd_IAT_Total
        np.mean(flow["fwd_iat_times"]) if flow["fwd_iat_times"] else 0,  # Fwd_IAT_Mean
        np.std(flow["fwd_iat_times"]) if flow["fwd_iat_times"] else 0,  # Fwd_IAT_Std
        max(flow["fwd_iat_times"]) if flow["fwd_iat_times"] else 0,  # Fwd_IAT_Max
        min(flow["fwd_iat_times"]) if flow["fwd_iat_times"] else 0,  # Fwd_IAT_Min
        sum(flow["bwd_iat_times"]) if flow["bwd_iat_times"] else 0,  # Bwd_IAT_Total
        np.mean(flow["bwd_iat_times"]) if flow["bwd_iat_times"] else 0,  # Bwd_IAT_Mean
        np.std(flow["bwd_iat_times"]) if flow["bwd_iat_times"] else 0,  # Bwd_IAT_Std
        max(flow["bwd_iat_times"]) if flow["bwd_iat_times"] else 0,  # Bwd_IAT_Max
        min(flow["bwd_iat_times"]) if flow["bwd_iat_times"] else 0,  # Bwd_IAT_Min
        flow["fwd_psh_flags"],  # Fwd_PSH_Flags
        flow["bwd_psh_flags"],  # Bwd_PSH_Flags
        flow["fwd_urg_flags"],  # Fwd_URG_Flags
        flow["bwd_urg_flags"],  # Bwd_URG_Flags
        flow["fwd_header_length"],  # Fwd_Header_Length
        flow["bwd_header_length"],  # Bwd_Header_Length
        flow["fwd_packets_sec"],  # Fwd_Packets_Sec
        flow["bwd_packets_sec"],  # Bwd_Packets_Sec
        min(flow["fwd_packet_lengths"] + flow["bwd_packet_lengths"]) if (flow["fwd_packet_lengths"] + flow["bwd_packet_lengths"]) else 0,  # Min_Packet_Length
        max(flow["fwd_packet_lengths"] + flow["bwd_packet_lengths"]) if (flow["fwd_packet_lengths"] + flow["bwd_packet_lengths"]) else 0,  # Max_Packet_Length
        np.mean(flow["fwd_packet_lengths"] + flow["bwd_packet_lengths"]) if (flow["fwd_packet_lengths"] + flow["bwd_packet_lengths"]) else 0,  # Packet_Length_Mean
        np.std(flow["fwd_packet_lengths"] + flow["bwd_packet_lengths"]) if (flow["fwd_packet_lengths"] + flow["bwd_packet_lengths"]) else 0,  # Packet_Length_Std
        np.var(flow["fwd_packet_lengths"] + flow["bwd_packet_lengths"]) if (flow["fwd_packet_lengths"] + flow["bwd_packet_lengths"]) else 0,  # Packet_Length_Variance
        flow["fin_flag_count"],  # FIN_Flag_Count
        flow["syn_flag_count"],  # SYN_Flag_Count
        flow["rst_flag_count"],  # RST_Flag_Count
        flow["psh_flag_count"],  # PSH_Flag_Count
        flow["ack_flag_count"],  # ACK_Flag_Count
        flow["urg_flag_count"],  # URG_Flag_Count
        flow["cwe_flag_count"],  # CWE_Flag_Count
        flow["ece_flag_count"],  # ECE_Flag_Count
        flow["down_up_ratio"],  # Down_Up_Ratio
        flow["average_packet_size"],  # Average_Packet_Size
        np.mean(flow["fwd_packet_lengths"]) if flow["fwd_packet_lengths"] else 0,  # Avg_Fwd_Segment_Size
        np.mean(flow["bwd_packet_lengths"]) if flow["bwd_packet_lengths"] else 0,  # Avg_Bwd_Segment_Size
        0,  # Fwd_Avg_Bytes_Bulk (you may need to calculate this separately)
        0,  # Fwd_Avg_Packets_Bulk (you may need to calculate this separately)
        0,  # Fwd_Avg_Bulk_Rate (you may need to calculate this separately)
        0,  # Bwd_Avg_Bytes_Bulk (you may need to calculate this separately)
        0,  # Bwd_Avg_Packets_Bulk (you may need to calculate this separately)
        0,  # Bwd_Avg_Bulk_Rate (you may need to calculate this separately)
        flow["total_fwd_packets"],  # Subflow_Fwd_Packets
        flow["subflow_fwd_bytes"],  # Subflow_Fwd_Bytes
        flow["total_bwd_packets"],  # Subflow_Bwd_Packets
        flow["subflow_bwd_bytes"],  # Subflow_Bwd_Bytes
        flow["init_win_bytes_forward"],  # Init_Win_bytes_forward
        flow["init_win_bytes_backward"] if flow["init_win_bytes_backward"] else 0,  # Init_Win_bytes_backward
        flow["act_data_pkt_fwd"],  # act_data_pkt_fwd
        flow["min_seg_size_forward"] if flow["min_seg_size_forward"] else 0,  # min_seg_size_forward
        0,  # Active_Mean (you may need to calculate this separately)
        0,  # Active_Std (you may need to calculate this separately)
        0,  # Active_Max (you may need to calculate this separately)
        0,  # Active_Min (you may need to calculate this separately)
        0,  # Idle_Mean (you may need to calculate this separately)
        0,  # Idle_Std (you may need to calculate this separately)
        0,  # Idle_Max (you may need to calculate this separately)
        0,  # Idle_Min (you may need to calculate this separately)
    ]
    
    return features
