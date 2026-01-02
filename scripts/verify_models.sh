#!/bin/bash
# Script to verify ML models are present and valid

cd "$(dirname "$0")/.." || exit 1

echo "Verifying ML Models..."
echo ""

MODELS_DIR="models"
MODEL_FILE="random_forest_min-max_scaling_model.pkl"
SCALER_FILE="random_forest_min-max_scaling_scaler.pkl"

# Check if models directory exists
if [ ! -d "$MODELS_DIR" ]; then
    echo "❌ Models directory not found: $MODELS_DIR"
    exit 1
fi

# Check if model file exists
if [ ! -f "$MODELS_DIR/$MODEL_FILE" ]; then
    echo "❌ Model file not found: $MODELS_DIR/$MODEL_FILE"
    exit 1
else
    SIZE=$(du -h "$MODELS_DIR/$MODEL_FILE" | cut -f1)
    echo "✅ Model file found: $MODEL_FILE ($SIZE)"
fi

# Check if scaler file exists
if [ ! -f "$MODELS_DIR/$SCALER_FILE" ]; then
    echo "❌ Scaler file not found: $MODELS_DIR/$SCALER_FILE"
    exit 1
else
    SIZE=$(du -h "$MODELS_DIR/$SCALER_FILE" | cut -f1)
    echo "✅ Scaler file found: $SCALER_FILE ($SIZE)"
fi

# Try to load models using Python (if available)
if command -v python3 &> /dev/null; then
    echo ""
    echo "Testing model loading..."
    python3 << EOF
try:
    from pathlib import Path
    from config.settings import Config
    
    print(f"Model path: {Config.MODEL_PATH}")
    print(f"Scaler path: {Config.SCALER_PATH}")
    
    if Config.MODEL_PATH.exists() and Config.SCALER_PATH.exists():
        print("✅ Model paths are valid")
        
        # Try to load (if joblib is available)
        try:
            import joblib
            model = joblib.load(Config.MODEL_PATH)
            scaler = joblib.load(Config.SCALER_PATH)
            print(f"✅ Models loaded successfully!")
            print(f"   Model type: {type(model).__name__}")
            if hasattr(scaler, 'n_features_in_'):
                print(f"   Expected features: {scaler.n_features_in_}")
        except ImportError:
            print("⚠️  joblib not installed (will be available in Docker container)")
        except Exception as e:
            print(f"❌ Error loading models: {e}")
    else:
        print("❌ Model files not found at configured paths")
except Exception as e:
    print(f"❌ Error: {e}")
EOF
fi

echo ""
echo "✅ Model verification complete!"

