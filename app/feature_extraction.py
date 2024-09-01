import numpy as np

# Armazenamento dos dados do fluxo
flows = {}

def calculate_flow_features(packet):
    # Identificação do fluxo e cálculo das features conforme descrito anteriormente
    flow_id = (packet[0][1].src, packet[0][1].dst, packet[0][2].sport, packet[0][2].dport)
    
    if flow_id not in flows:
        flows[flow_id] = {
            "start_time": packet.time,
            "end_time": packet.time,
            "total_fwd_packets": 0,
            "total_bwd_packets": 0,
            "total_length_of_fwd_packets": 0,
            "total_length_of_bwd_packets": 0,
            "fwd_packet_lengths": [],
            "bwd_packet_lengths": [],
            "fwd_iat_times": [],
            "last_fwd_packet_time": None,
            "syn_flag_count": 0,
            "subflow_fwd_bytes": 0,
            "init_win_bytes_forward": packet[TCP].window,
            "init_win_bytes_backward": None,
            "act_data_pkt_fwd": 0,
            "min_seg_size_forward": None,
        }

    # Atualiza as informações do fluxo e calcula as features conforme necessário
    flow = flows[flow_id]
    flow["end_time"] = packet.time

    # Exemplo de retorno de features para predição (você precisa ajustar de acordo com as features calculadas)
    if flow["fwd_packet_lengths"]:
        features = [
            flow["end_time"] - flow["start_time"],  # Flow_Duration
            flow["total_length_of_fwd_packets"],  # Total_Length_of_Fwd_Packets
            flow["total_length_of_bwd_packets"],  # Total_Length_of_Bwd_Packets
            max(flow["fwd_packet_lengths"]),  # Fwd_Packet_Length_Max
            np.std(flow["fwd_packet_lengths"]),  # Fwd_Packet_Length_Std
            max(flow["bwd_packet_lengths"]) if flow["bwd_packet_lengths"] else 0,  # Bwd_Packet_Length_Max
            np.mean(flow["bwd_packet_lengths"]) if flow["bwd_packet_lengths"] else 0,  # Bwd_Packet_Length_Mean
            (flow["total_length_of_fwd_packets"] + flow["total_length_of_bwd_packets"]) / 
            (flow["end_time"] - flow["start_time"]) if flow["end_time"] - flow["start_time"] > 0 else 0,  # Flow_Bytes_Sec
            (flow["total_fwd_packets"] + flow["total_bwd_packets"]) / 
            (flow["end_time"] - flow["start_time"]) if flow["end_time"] - flow["start_time"] > 0 else 0,  # Flow_Packets_Sec
            np.std(flow["fwd_iat_times"]) if flow["fwd_iat_times"] else 0,  # Fwd_IAT_Std
            max(flow["fwd_iat_times"]) if flow["fwd_iat_times"] else 0,  # Fwd_IAT_Max
            max(flow["fwd_packet_lengths"] + flow["bwd_packet_lengths"]) if (flow["fwd_packet_lengths"] + flow["bwd_packet_lengths"]) else 0,  # Max_Packet_Length
            np.var(flow["fwd_packet_lengths"] + flow["bwd_packet_lengths"]) if (flow["fwd_packet_lengths"] + flow["bwd_packet_lengths"]) else 0,  # Packet_Length_Variance
            flow["syn_flag_count"],  # SYN_Flag_Count
            np.mean(flow["bwd_packet_lengths"]) if flow["bwd_packet_lengths"] else 0,  # Avg_Bwd_Segment_Size
            flow["subflow_fwd_bytes"],  # Subflow_Fwd_Bytes
            flow["init_win_bytes_forward"],  # Init_Win_bytes_forward
            flow["init_win_bytes_backward"] if flow["init_win_bytes_backward"] else 0,  # Init_Win_bytes_backward
            flow["act_data_pkt_fwd"],  # act_data_pkt_fwd
            flow["min_seg_size_forward"] if flow["min_seg_size_forward"] else 0  # min_seg_size_forward
        ]
        return features

    return None
