"""
Project configuration for DDoS detection.
"""
import os
from pathlib import Path
from typing import Union

# Project base directory
BASE_DIR = Path(__file__).parent.parent


class Config:
    """Centralized application configuration."""
    
    # General settings
    DEBUG: bool = os.getenv('DEBUG', 'False').lower() == 'true'
    LOG_LEVEL: str = os.getenv('LOG_LEVEL', 'INFO')
    
    # Model paths
    MODELS_DIR: Path = BASE_DIR / 'models'
    MODEL_PATH: Path = MODELS_DIR / os.getenv(
        'MODEL_PATH', 
        'random_forest_min-max_scaling_model.pkl'
    )
    SCALER_PATH: Path = MODELS_DIR / os.getenv(
        'SCALER_PATH', 
        'random_forest_min-max_scaling_scaler.pkl'
    )
    
    # Logging configuration
    LOGS_DIR: Path = BASE_DIR / 'logs'
    DETECTION_LOG: Path = LOGS_DIR / 'detection.log'
    SERVER_LOG: Path = LOGS_DIR / 'server.log'
    PREDICTION_LOG: Path = LOGS_DIR / 'prediction.log'
    
    # Flask server configuration
    FLASK_HOST: str = os.getenv('FLASK_HOST', '0.0.0.0')
    FLASK_PORT: int = int(os.getenv('FLASK_PORT', '5050'))
    
    # Detection configuration
    NETWORK_INTERFACE: str = os.getenv('NETWORK_INTERFACE', 'lo0')
    BPF_FILTER: str = os.getenv('BPF_FILTER', 'tcp port 5050')
    
    # Flow tracking configuration
    FLOW_TIMEOUT: float = float(os.getenv('FLOW_TIMEOUT', '300.0'))  # 5 minutes
    
    @classmethod
    def ensure_directories(cls) -> None:
        """Ensure necessary directories exist."""
        cls.LOGS_DIR.mkdir(exist_ok=True)
        cls.MODELS_DIR.mkdir(exist_ok=True)
    
    @classmethod
    def validate_paths(cls) -> bool:
        """Validate if necessary files exist."""
        if not cls.MODEL_PATH.exists():
            raise FileNotFoundError(f"Model not found: {cls.MODEL_PATH}")
        if not cls.SCALER_PATH.exists():
            raise FileNotFoundError(f"Scaler not found: {cls.SCALER_PATH}")
        return True
