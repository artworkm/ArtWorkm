
import json
import joblib

import pandas as pd

from pathlib import Path


# Locate backend/models regardless of the current terminal directory.
MODEL_DIR = Path(__file__).resolve().parent.parent / "models"

MODEL_PATH = MODEL_DIR / "ids_rf.joblib"
FEATURES_PATH = MODEL_DIR / "features.json"


# Load the trained model.
model = joblib.load(MODEL_PATH)

# Load the exact feature names and their order.
with open(FEATURES_PATH, "r") as file:
    feature_names = json.load(file)


def detect(features: dict):
    """
    Run the Random Forest model on one network event.

    Missing feature values are filled with 0.0.
    """

    if not isinstance(features, dict):
        raise ValueError("Features must be provided as a dictionary.")

    # Arrange input features in exactly the training order.
    row = {
        name: float(features.get(name, 0.0))
        for name in feature_names
    }

    # Create a DataFrame with the original feature names.
    input_data = pd.DataFrame([row], columns=feature_names)

    # Predict the attack category.
    prediction = model.predict(input_data)[0]

    # Get prediction probabilities.
    probabilities = model.predict_proba(input_data)[0]
    confidence = float(max(probabilities))

    predicted_label = str(prediction)

    # Assign severity based on the predicted category.
    if predicted_label == "BENIGN":
        severity = "low"
    elif predicted_label in ("DDoS", "DoS", "BruteForce", "Bot"):
        severity = "high"
    else:
        severity = "medium"

    return {
        "model_name": "RandomForest",
        "predicted_label": predicted_label,
        "confidence": confidence,
        "severity": severity,
        "explanation": (
            f"Random Forest classified this event as {predicted_label}."
        )
    }
