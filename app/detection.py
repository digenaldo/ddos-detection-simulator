from scapy.all import sniff
from app.feature_extraction import calculate_flow_features
from app.model_prediction import predict_attack

def packet_callback(packet):
    # Calcula as features para o pacote capturado
    features = calculate_flow_features(packet)
    
    # Realiza a predição se as features forem válidas
    predict_attack(features)

# Inicia a captura de pacotes
sniff(iface="eth0", prn=packet_callback, store=0)
