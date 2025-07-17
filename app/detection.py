import logging
import pyshark
from app.feature_extraction import calculate_flow_features
from app.model_prediction import predict_attack

# Configure logging
logging.basicConfig(filename='logs/detection.log', level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s: %(message)s')

# Add a basic log to verify the script is running
print("Detection script started")

def packet_callback(packet):
    print("Packet captured, entering callback")
    try:
        # Check if the packet is TCP
        if 'TCP' in packet:
            print(f"TCP Packet captured: {packet}")

            # Extract relevant features from the packet
            features = calculate_flow_features(packet)
            
            if features:
                print(f"Features extracted: {features}")
                predict_attack(features)
            else:
                print("Failed to extract valid features from packet")
        else:
            print("Non-TCP packet captured, ignoring")

    except Exception as e:
        print(f"Error processing packet: {e}")

if __name__ == '__main__':
    print("Starting packet capture on interface 'lo0' (Loopback)")

    try:
        # Capture packets using pyshark on the loopback interface with a BPF filter
        # Filter to capture all TCP packets originating from port 5001
        capture = pyshark.LiveCapture(interface='lo0', bpf_filter='tcp port 5001')

        # Process packets in real-time
        capture.apply_on_packets(packet_callback)
        
        print("Sniffing function called successfully")
    except Exception as e:
        print(f"Sniffing failed: {e}")
    
    print("Packet capture stopped")
