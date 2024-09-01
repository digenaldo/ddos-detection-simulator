import joblib
import numpy as np
import logging

# Configure logging
logging.basicConfig(filename='logs/prediction.log', level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s: %(message)s')

# Load the trained model
try:
    model = joblib.load('models/random_forest_min-max_scaling_model.pkl')
    logging.info("Model loaded successfully.")
except Exception as e:
    logging.error(f"Failed to load model: {e}")

# Load the scaler
try:
    scaler = joblib.load('models/random_forest_min-max_scaling_scaler.pkl')
    logging.info("Scaler loaded successfully.")
except Exception as e:
    logging.error(f"Failed to load scaler: {e}")

def predict_attack(features):
    if features is not None:
        try:
            # Convert the feature list to a numpy array and perform scaling
            logging.debug(f"Original features: {features}")
            features = np.array([features])
            scaled_features = scaler.transform(features)
            logging.debug(f"Scaled features: {scaled_features}")

            # Perform the prediction using the trained model
            prediction = model.predict(scaled_features)
            logging.debug(f"Prediction result: {prediction}")

            if prediction == 1:
                logging.info("DDoS attack detected!")
                print("DDoS attack detected!")
            else:
                logging.info("Normal traffic.")
                print("Normal traffic.")
        except Exception as e:
            logging.error(f"Error during prediction: {e}")
    else:
        logging.warning("Received None as features, skipping prediction.")
