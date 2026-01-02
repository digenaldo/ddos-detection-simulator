"""
Module for model loading and DDoS attack prediction.
"""
import joblib
import numpy as np
import logging
from typing import Optional, List, Tuple
from pathlib import Path

from config.settings import Config

# Logging configuration
logger = logging.getLogger(__name__)


class ModelPredictor:
    """Class to manage ML model and make predictions."""
    
    def __init__(self, model_path: Optional[Path] = None, scaler_path: Optional[Path] = None):
        """
        Initialize the model predictor.
        
        Args:
            model_path: Path to the model file
            scaler_path: Path to the scaler file
        """
        self.model_path = model_path or Config.MODEL_PATH
        self.scaler_path = scaler_path or Config.SCALER_PATH
        self.model = None
        self.scaler = None
        self._load_model()
        self._load_scaler()
    
    def _load_model(self) -> None:
        """Load the trained model."""
        try:
            if not self.model_path.exists():
                raise FileNotFoundError(f"Model not found: {self.model_path}")
            
            self.model = joblib.load(self.model_path)
            logger.info(f"Model loaded successfully: {self.model_path}")
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            raise
    
    def _load_scaler(self) -> None:
        """Load the scaler for normalization."""
        try:
            if not self.scaler_path.exists():
                raise FileNotFoundError(f"Scaler not found: {self.scaler_path}")
            
            self.scaler = joblib.load(self.scaler_path)
            logger.info(f"Scaler loaded successfully: {self.scaler_path}")
        except Exception as e:
            logger.error(f"Error loading scaler: {e}")
            raise
    
    def predict(self, features: List[float]) -> Tuple[int, float]:
        """
        Predict DDoS attack.
        
        Args:
            features: List of features extracted from the flow
            
        Returns:
            Tuple[int, float]: (prediction, confidence)
            - prediction: 0 for normal traffic, 1 for DDoS attack
            - confidence: Prediction confidence
        """
        if self.model is None or self.scaler is None:
            raise RuntimeError("Model or scaler not loaded")
        
        if features is None:
            raise ValueError("Features cannot be None")
        
        try:
            # Basic validation
            if not isinstance(features, (list, np.ndarray)):
                raise TypeError(f"Features must be list or array, got: {type(features)}")
            
            # Convert to numpy array
            features_array = np.array([features])
            
            # Validate dimension
            expected_features = self.scaler.n_features_in_
            if features_array.shape[1] != expected_features:
                raise ValueError(
                    f"Incorrect number of features. Expected: {expected_features}, "
                    f"Got: {features_array.shape[1]}"
                )
            
            # Normalize features
            scaled_features = self.scaler.transform(features_array)
            logger.debug(f"Normalized features: shape={scaled_features.shape}")
            
            # Make prediction
            prediction = self.model.predict(scaled_features)[0]
            
            # Get probability if available
            if hasattr(self.model, 'predict_proba'):
                probabilities = self.model.predict_proba(scaled_features)[0]
                confidence = float(max(probabilities))
            else:
                confidence = 1.0
            
            return int(prediction), confidence
            
        except Exception as e:
            logger.error(f"Error during prediction: {e}", exc_info=True)
            raise


# Global predictor instance
_predictor: Optional[ModelPredictor] = None


def get_predictor() -> ModelPredictor:
    """
    Get the global predictor instance (singleton).
    
    Returns:
        ModelPredictor: Predictor instance
    """
    global _predictor
    if _predictor is None:
        _predictor = ModelPredictor()
    return _predictor


def predict_attack(features: Optional[List[float]]) -> None:
    """
    Convenience function to make attack prediction.
    
    Args:
        features: List of features extracted from the flow
    """
    if features is None:
        logger.warning("Received None as features, skipping prediction")
        return
    
    try:
        predictor = get_predictor()
        prediction, confidence = predictor.predict(features)
        
        if prediction == 1:
            logger.warning(
                f"⚠️  DDoS ATTACK DETECTED! (Confidence: {confidence:.2%})"
            )
            print(f"⚠️  DDoS ATTACK DETECTED! (Confidence: {confidence:.2%})")
        else:
            logger.info(f"✓ Normal traffic (Confidence: {confidence:.2%})")
            print(f"✓ Normal traffic (Confidence: {confidence:.2%})")
            
    except Exception as e:
        logger.error(f"Error processing prediction: {e}", exc_info=True)
        print(f"Error processing prediction: {e}")
