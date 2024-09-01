from scapy.all import sniff
import joblib
import numpy as np

# Carregue o modelo treinado
model = joblib.load('random_forest_model.pkl')
scaler = joblib.load('minmax_scaler.pkl')

def packet_callback(packet):
    # Supondo que extraímos features como tempo, tamanho do pacote, etc.
    features = np.array([[len(packet), packet.time, packet.ttl]])  # Exemplo simples

    # Escala os dados
    scaled_features = scaler.transform(features)

    # Predição usando o modelo
    prediction = model.predict(scaled_features)

    if prediction == 1:
        print("Ataque DDoS detectado!")
    else:
        print("Tráfego normal.")

# Captura de pacotes
sniff(iface="eth0", prn=packet_callback)
