"""
Main module for real-time DDoS attack detection.
"""
import logging
import sys
from typing import Optional

import pyshark

from app.feature_extraction import calculate_flow_features
from app.model_prediction import predict_attack
from config.settings import Config

# Centralized logging configuration
def setup_logging() -> None:
    """Configure the logging system."""
    Config.ensure_directories()
    
    # Log format
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'
    
    # Basic configuration
    logging.basicConfig(
        level=getattr(logging, Config.LOG_LEVEL.upper()),
        format=log_format,
        datefmt=date_format,
        handlers=[
            logging.FileHandler(Config.DETECTION_LOG),
            logging.StreamHandler(sys.stdout)
        ]
    )


# Configure logging when importing the module
setup_logging()
logger = logging.getLogger(__name__)


def packet_callback(packet) -> None:
    """
    Callback called for each captured packet.
    
    Args:
        packet: Packet captured by pyshark
    """
    try:
        # Validate if it's a TCP packet
        if 'TCP' not in packet:
            logger.debug("Non-TCP packet ignored")
            return
        
        logger.debug(f"TCP packet captured: {packet.ip.src}:{packet.tcp.srcport} -> "
                    f"{packet.ip.dst}:{packet.tcp.dstport}")
        
        # Extract features from packet
        features = calculate_flow_features(packet)
        
        if features:
            logger.debug(f"Features extracted: {len(features)} features")
            # Make prediction
            predict_attack(features)
        else:
            logger.warning("Failed to extract valid features from packet")
            
    except KeyError as e:
        logger.warning(f"Incomplete packet (missing field): {e}")
    except Exception as e:
        logger.error(f"Error processing packet: {e}", exc_info=True)


def start_detection(
    interface: Optional[str] = None,
    bpf_filter: Optional[str] = None
) -> None:
    """
    Start packet capture and detection.
    
    Args:
        interface: Network interface for capture (default: Config.NETWORK_INTERFACE)
        bpf_filter: BPF filter for capture (default: Config.BPF_FILTER)
    """
    interface = interface or Config.NETWORK_INTERFACE
    bpf_filter = bpf_filter or Config.BPF_FILTER
    
    logger.info(f"Starting packet capture on interface '{interface}'")
    logger.info(f"BPF filter: {bpf_filter}")
    
    try:
        # Validate if model is available
        from app.model_prediction import get_predictor
        predictor = get_predictor()
        logger.info("Detection system initialized successfully")
        
        # Start capture
        capture = pyshark.LiveCapture(interface=interface, bpf_filter=bpf_filter)
        
        logger.info("Capture started. Waiting for packets...")
        logger.info("Press Ctrl+C to stop")
        
        # Process packets in real-time
        capture.apply_on_packets(packet_callback)
        
    except KeyboardInterrupt:
        logger.info("Capture interrupted by user")
    except pyshark.capture.capture.TSharkNotFoundException:
        logger.error(
            "TShark not found. Please install Wireshark/TShark:\n"
            "- Linux: sudo apt-get install tshark\n"
            "- macOS: brew install wireshark\n"
            "- Windows: Install Wireshark"
        )
        sys.exit(1)
    except PermissionError:
        logger.error(
            "Permission denied. Run with sudo to capture packets:\n"
            "sudo python3 -m app.detection"
        )
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error starting capture: {e}", exc_info=True)
        sys.exit(1)
    finally:
        logger.info("Detection system stopped")


if __name__ == '__main__':
    start_detection()
