"""
Module for extracting network flow features for DDoS detection.
"""
import numpy as np
from typing import Dict, Tuple, List, Optional
from dataclasses import dataclass, field


@dataclass
class FlowFeatures:
    """Stores features of a network flow."""
    flow_id: Tuple[str, str, int, int]  # (src_ip, dst_ip, src_port, dst_port)
    start_time: float = 0.0
    end_time: float = 0.0
    total_fwd_packets: int = 0
    total_bwd_packets: int = 0
    total_length_of_fwd_packets: int = 0
    total_length_of_bwd_packets: int = 0
    fwd_packet_lengths: List[int] = field(default_factory=list)
    bwd_packet_lengths: List[int] = field(default_factory=list)
    fwd_iat_times: List[float] = field(default_factory=list)
    bwd_iat_times: List[float] = field(default_factory=list)
    last_fwd_packet_time: Optional[float] = None
    last_bwd_packet_time: Optional[float] = None
    syn_flag_count: int = 0
    fin_flag_count: int = 0
    rst_flag_count: int = 0
    psh_flag_count: int = 0
    ack_flag_count: int = 0
    urg_flag_count: int = 0
    ece_flag_count: int = 0
    cwe_flag_count: int = 0
    fwd_psh_flags: int = 0
    bwd_psh_flags: int = 0
    fwd_urg_flags: int = 0
    bwd_urg_flags: int = 0
    fwd_header_length: int = 0
    bwd_header_length: int = 0
    fwd_packets_sec: float = 0.0
    bwd_packets_sec: float = 0.0
    subflow_fwd_bytes: int = 0
    subflow_bwd_bytes: int = 0
    init_win_bytes_forward: int = 0
    init_win_bytes_backward: Optional[int] = None
    act_data_pkt_fwd: int = 0
    act_data_pkt_bwd: int = 0
    min_seg_size_forward: Optional[int] = None
    down_up_ratio: float = 0.0
    average_packet_size: float = 0.0


class FlowTracker:
    """Tracks and manages multiple network flows."""
    
    def __init__(self, timeout: float = 300.0):
        """
        Initialize the flow tracker.
        
        Args:
            timeout: Time in seconds to expire inactive flows
        """
        self.flows: Dict[Tuple[str, str, int, int], FlowFeatures] = {}
        self.timeout = timeout
    
    def get_or_create_flow(
        self, 
        flow_id: Tuple[str, str, int, int],
        packet_time: float,
        tcp_hdr_len: int,
        window_size: int
    ) -> FlowFeatures:
        """
        Get an existing flow or create a new one.
        
        Args:
            flow_id: Flow identifier (src_ip, dst_ip, src_port, dst_port)
            packet_time: Packet timestamp
            tcp_hdr_len: TCP header length
            window_size: TCP window size
            
        Returns:
            FlowFeatures: Object with flow features
        """
        if flow_id not in self.flows:
            self.flows[flow_id] = FlowFeatures(
                flow_id=flow_id,
                start_time=packet_time,
                end_time=packet_time,
                last_fwd_packet_time=packet_time,
                fwd_header_length=tcp_hdr_len,
                init_win_bytes_forward=window_size
            )
        return self.flows[flow_id]
    
    def cleanup_expired_flows(self, current_time: float) -> None:
        """
        Remove expired flows.
        
        Args:
            current_time: Current timestamp
        """
        expired_flows = [
            flow_id for flow_id, flow in self.flows.items()
            if current_time - flow.end_time > self.timeout
        ]
        for flow_id in expired_flows:
            del self.flows[flow_id]
    
    def get_flow(self, flow_id: Tuple[str, str, int, int]) -> Optional[FlowFeatures]:
        """Return a specific flow or None if it doesn't exist."""
        return self.flows.get(flow_id)


# Global tracker instance (can be replaced by dependency injection)
_flow_tracker = FlowTracker()


def calculate_flow_features(packet) -> Optional[List[float]]:
    """
    Calculate network flow features from a packet.
    
    Args:
        packet: Packet captured by pyshark
        
    Returns:
        List[float]: List of extracted features or None on error
    """
    try:
        # Basic validation
        if 'IP' not in packet or 'TCP' not in packet:
            return None
        
        # Identify the flow
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        src_port = int(packet.tcp.srcport)
        dst_port = int(packet.tcp.dstport)
        flow_id = (src_ip, dst_ip, src_port, dst_port)
        
        # Get or create flow
        packet_time = float(packet.sniff_time.timestamp())
        tcp_hdr_len = int(packet.tcp.hdr_len)
        window_size = int(packet.tcp.window_size)
        
        flow = _flow_tracker.get_or_create_flow(
            flow_id, packet_time, tcp_hdr_len, window_size
        )
        
        # Update flow information
        flow.end_time = packet_time
        packet_length = int(packet.length)
        
        # Determine if it's forward or backward packet
        is_forward = packet.ip.src == flow_id[0]
        
        if is_forward:
            _update_forward_packet(flow, packet, packet_time, packet_length)
        else:
            _update_backward_packet(flow, packet, packet_time, packet_length)
        
        # Calculate derived metrics
        _calculate_derived_metrics(flow)
        
        # Cleanup expired flows periodically
        _flow_tracker.cleanup_expired_flows(packet_time)
        
        # Return features
        return _extract_feature_vector(flow, dst_port)
        
    except Exception as e:
        # Error logging would be done in the detection module
        return None


def _update_forward_packet(
    flow: FlowFeatures, 
    packet, 
    packet_time: float, 
    packet_length: int
) -> None:
    """Update forward packet information."""
    flow.total_fwd_packets += 1
    flow.total_length_of_fwd_packets += packet_length
    flow.fwd_packet_lengths.append(packet_length)
    
    if flow.last_fwd_packet_time is not None:
        iat = packet_time - flow.last_fwd_packet_time
        flow.fwd_iat_times.append(iat)
    
    flow.last_fwd_packet_time = packet_time
    flow.act_data_pkt_fwd += 1
    flow.subflow_fwd_bytes += packet_length
    
    # Update TCP flags
    flags = packet.tcp.flags
    if 'SYN' in flags:
        flow.syn_flag_count += 1
    if 'FIN' in flags:
        flow.fin_flag_count += 1
    if 'RST' in flags:
        flow.rst_flag_count += 1
    if 'PSH' in flags:
        flow.psh_flag_count += 1
        flow.fwd_psh_flags += 1
    if 'ACK' in flags:
        flow.ack_flag_count += 1
    if 'URG' in flags:
        flow.urg_flag_count += 1
        flow.fwd_urg_flags += 1
    if 'ECE' in flags:
        flow.ece_flag_count += 1


def _update_backward_packet(
    flow: FlowFeatures, 
    packet, 
    packet_time: float, 
    packet_length: int
) -> None:
    """Update backward packet information."""
    flow.total_bwd_packets += 1
    flow.total_length_of_bwd_packets += packet_length
    flow.bwd_packet_lengths.append(packet_length)
    
    if flow.last_bwd_packet_time is not None:
        iat = packet_time - flow.last_bwd_packet_time
        flow.bwd_iat_times.append(iat)
    
    flow.last_bwd_packet_time = packet_time
    flow.act_data_pkt_bwd += 1
    flow.subflow_bwd_bytes += packet_length
    
    if flow.init_win_bytes_backward is None:
        flow.init_win_bytes_backward = int(packet.tcp.window_size)
    
    flags = packet.tcp.flags
    if 'PSH' in flags:
        flow.bwd_psh_flags += 1
    if 'URG' in flags:
        flow.bwd_urg_flags += 1


def _calculate_derived_metrics(flow: FlowFeatures) -> None:
    """Calculate derived flow metrics."""
    if flow.total_bwd_packets > 0:
        flow.down_up_ratio = flow.total_fwd_packets / flow.total_bwd_packets
    
    total_packets = flow.total_fwd_packets + flow.total_bwd_packets
    if total_packets > 0:
        total_length = flow.total_length_of_fwd_packets + flow.total_length_of_bwd_packets
        flow.average_packet_size = total_length / total_packets
    
    duration = flow.end_time - flow.start_time
    if duration > 0:
        flow.fwd_packets_sec = flow.total_fwd_packets / duration
        flow.bwd_packets_sec = flow.total_bwd_packets / duration


def _extract_feature_vector(flow: FlowFeatures, dst_port: int) -> List[float]:
    """
    Extract feature vector from flow.
    
    Args:
        flow: FlowFeatures object
        dst_port: Destination port
        
    Returns:
        List[float]: Feature vector
    """
    all_packet_lengths = flow.fwd_packet_lengths + flow.bwd_packet_lengths
    all_iat_times = flow.fwd_iat_times + flow.bwd_iat_times
    
    duration = flow.end_time - flow.start_time
    
    features = [
        float(dst_port),  # Destination_Port
        duration,  # Flow_Duration
        float(flow.total_fwd_packets),  # Total_Fwd_Packets
        float(flow.total_bwd_packets),  # Total_Backward_Packets
        float(flow.total_length_of_fwd_packets),  # Total_Length_of_Fwd_Packets
        float(flow.total_length_of_bwd_packets),  # Total_Length_of_Bwd_Packets
        float(max(flow.fwd_packet_lengths)) if flow.fwd_packet_lengths else 0.0,  # Fwd_Packet_Length_Max
        float(min(flow.fwd_packet_lengths)) if flow.fwd_packet_lengths else 0.0,  # Fwd_Packet_Length_Min
        float(np.mean(flow.fwd_packet_lengths)) if flow.fwd_packet_lengths else 0.0,  # Fwd_Packet_Length_Mean
        float(np.std(flow.fwd_packet_lengths)) if flow.fwd_packet_lengths else 0.0,  # Fwd_Packet_Length_Std
        float(max(flow.bwd_packet_lengths)) if flow.bwd_packet_lengths else 0.0,  # Bwd_Packet_Length_Max
        float(min(flow.bwd_packet_lengths)) if flow.bwd_packet_lengths else 0.0,  # Bwd_Packet_Length_Min
        float(np.mean(flow.bwd_packet_lengths)) if flow.bwd_packet_lengths else 0.0,  # Bwd_Packet_Length_Mean
        float(np.std(flow.bwd_packet_lengths)) if flow.bwd_packet_lengths else 0.0,  # Bwd_Packet_Length_Std
        (flow.total_length_of_fwd_packets + flow.total_length_of_bwd_packets) / duration if duration > 0 else 0.0,  # Flow_Bytes_Sec
        (flow.total_fwd_packets + flow.total_bwd_packets) / duration if duration > 0 else 0.0,  # Flow_Packets_Sec
        float(np.mean(all_iat_times)) if all_iat_times else 0.0,  # Flow_IAT_Mean
        float(np.std(all_iat_times)) if all_iat_times else 0.0,  # Flow_IAT_Std
        float(max(all_iat_times)) if all_iat_times else 0.0,  # Flow_IAT_Max
        float(min(all_iat_times)) if all_iat_times else 0.0,  # Flow_IAT_Min
        float(sum(flow.fwd_iat_times)) if flow.fwd_iat_times else 0.0,  # Fwd_IAT_Total
        float(np.mean(flow.fwd_iat_times)) if flow.fwd_iat_times else 0.0,  # Fwd_IAT_Mean
        float(np.std(flow.fwd_iat_times)) if flow.fwd_iat_times else 0.0,  # Fwd_IAT_Std
        float(max(flow.fwd_iat_times)) if flow.fwd_iat_times else 0.0,  # Fwd_IAT_Max
        float(min(flow.fwd_iat_times)) if flow.fwd_iat_times else 0.0,  # Fwd_IAT_Min
        float(sum(flow.bwd_iat_times)) if flow.bwd_iat_times else 0.0,  # Bwd_IAT_Total
        float(np.mean(flow.bwd_iat_times)) if flow.bwd_iat_times else 0.0,  # Bwd_IAT_Mean
        float(np.std(flow.bwd_iat_times)) if flow.bwd_iat_times else 0.0,  # Bwd_IAT_Std
        float(max(flow.bwd_iat_times)) if flow.bwd_iat_times else 0.0,  # Bwd_IAT_Max
        float(min(flow.bwd_iat_times)) if flow.bwd_iat_times else 0.0,  # Bwd_IAT_Min
        float(flow.fwd_psh_flags),  # Fwd_PSH_Flags
        float(flow.bwd_psh_flags),  # Bwd_PSH_Flags
        float(flow.fwd_urg_flags),  # Fwd_URG_Flags
        float(flow.bwd_urg_flags),  # Bwd_URG_Flags
        float(flow.fwd_header_length),  # Fwd_Header_Length
        float(flow.bwd_header_length),  # Bwd_Header_Length
        flow.fwd_packets_sec,  # Fwd_Packets_Sec
        flow.bwd_packets_sec,  # Bwd_Packets_Sec
        float(min(all_packet_lengths)) if all_packet_lengths else 0.0,  # Min_Packet_Length
        float(max(all_packet_lengths)) if all_packet_lengths else 0.0,  # Max_Packet_Length
        float(np.mean(all_packet_lengths)) if all_packet_lengths else 0.0,  # Packet_Length_Mean
        float(np.std(all_packet_lengths)) if all_packet_lengths else 0.0,  # Packet_Length_Std
        float(np.var(all_packet_lengths)) if all_packet_lengths else 0.0,  # Packet_Length_Variance
        float(flow.fin_flag_count),  # FIN_Flag_Count
        float(flow.syn_flag_count),  # SYN_Flag_Count
        float(flow.rst_flag_count),  # RST_Flag_Count
        float(flow.psh_flag_count),  # PSH_Flag_Count
        float(flow.ack_flag_count),  # ACK_Flag_Count
        float(flow.urg_flag_count),  # URG_Flag_Count
        float(flow.cwe_flag_count),  # CWE_Flag_Count
        float(flow.ece_flag_count),  # ECE_Flag_Count
        flow.down_up_ratio,  # Down_Up_Ratio
        flow.average_packet_size,  # Average_Packet_Size
        float(np.mean(flow.fwd_packet_lengths)) if flow.fwd_packet_lengths else 0.0,  # Avg_Fwd_Segment_Size
        float(np.mean(flow.bwd_packet_lengths)) if flow.bwd_packet_lengths else 0.0,  # Avg_Bwd_Segment_Size
        0.0,  # Fwd_Avg_Bytes_Bulk
        0.0,  # Fwd_Avg_Packets_Bulk
        0.0,  # Fwd_Avg_Bulk_Rate
        0.0,  # Bwd_Avg_Bytes_Bulk
        0.0,  # Bwd_Avg_Packets_Bulk
        0.0,  # Bwd_Avg_Bulk_Rate
        float(flow.total_fwd_packets),  # Subflow_Fwd_Packets
        float(flow.subflow_fwd_bytes),  # Subflow_Fwd_Bytes
        float(flow.total_bwd_packets),  # Subflow_Bwd_Packets
        float(flow.subflow_bwd_bytes),  # Subflow_Bwd_Bytes
        float(flow.init_win_bytes_forward),  # Init_Win_bytes_forward
        float(flow.init_win_bytes_backward) if flow.init_win_bytes_backward else 0.0,  # Init_Win_bytes_backward
        float(flow.act_data_pkt_fwd),  # act_data_pkt_fwd
        float(flow.min_seg_size_forward) if flow.min_seg_size_forward else 0.0,  # min_seg_size_forward
        0.0,  # Active_Mean
        0.0,  # Active_Std
        0.0,  # Active_Max
        0.0,  # Active_Min
        0.0,  # Idle_Mean
        0.0,  # Idle_Std
        0.0,  # Idle_Max
        0.0,  # Idle_Min
    ]
    
    return features
