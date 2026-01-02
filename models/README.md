# ML Models Directory

This directory contains the trained machine learning models used for DDoS detection.

## Required Files

- **random_forest_min-max_scaling_model.pkl**: Trained Random Forest classifier model
- **random_forest_min-max_scaling_scaler.pkl**: Min-Max scaler for feature normalization

## Model Information

- **Algorithm**: Random Forest
- **Preprocessing**: Min-Max Scaling
- **Expected Features**: 78 features per flow

## Usage

The models are automatically loaded by the `ModelPredictor` class in `app/model_prediction.py`.

To verify models are working:
```bash
python3 -c "from config.settings import Config; import joblib; model = joblib.load(Config.MODEL_PATH); print('Model loaded successfully!')"
```

## Notes

- Models are versioned in git (see `.gitignore` - models are not ignored)
- If models are missing, the detection system will fail to start
- Models should be trained with the same feature set as used in `app/feature_extraction.py`

