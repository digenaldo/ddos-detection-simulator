import joblib
import numpy as np

# Carrega o modelo treinado
model = joblib.load('models/random_forest_model.pkl')
scaler = joblib.load('models/minmax_scaler.pkl')

def predict_attack(features):
    if features is not None:
        # Converte a lista de features para um array numpy e realiza a escalonamento
        features = np.array([features])
        scaled_features = scaler.transform(features)

        # Realiza a predição usando o modelo treinado
        prediction = model.predict(scaled_features)

        if prediction == 1:
            print("DDoS attack detected!")
        else:
            print("Normal traffic.")
