import os

class Config:
    DEBUG = os.getenv('DEBUG', False)
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    MODEL_PATH = os.getenv('MODEL_PATH', 'random_forest_model.pkl')
    SCALER_PATH = os.getenv('SCALER_PATH', 'minmax_scaler.pkl')
