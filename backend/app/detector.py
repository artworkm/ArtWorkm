import json
import joblib
import pandas as pd

from pathlib import Path


# Locate backend/models regardless of the current terminal directory.
MODEL_DIR = Path(__file__).resolve().parent.parent / "models"

MODEL_PATH = MODEL_DIR / "ids_rf.joblib"
FEATURES_PATH = MODEL_DIR / "features.json"


# These are loaded only when the first prediction is requested.
model = None
feature_names = None


def load_model():
    """Load the trained model and feature names when needed."""
    global model, feature_names

    if model is None:
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"Model file not found: {MODEL_PATH}"
            )

        if not FEATURES_PATH.exists():
            raise FileNotFoundError(
                f"Feature file not found: {FEATURES_PATH}"
            )

        model = joblib.load(MODEL_PATH)

        with open(FEATURES_PATH, "r") as file:
            feature_names = json.load(file)

    return model, feature_names


def detect(features: dict):
    """
    Run the Random Forest model on one network event.

    Missing feature values are filled with 0.0.
    Returns the original Phase 1B result dictionary.
    """

    if not isinstance(features, dict):
        raise ValueError("Features must be provided as a dictionary.")

    loaded_model, names = load_model()

    # Arrange input features in exactly the training order.
    row = {
        name: float(features.get(name, 0.0))
        for name in names
    }

    input_data = pd.DataFrame([row], columns=names)

    # Predict the attack category.
    prediction = loaded_model.predict(input_data)[0]

    # Get prediction probabilities.
    probabilities = loaded_model.predict_proba(input_data)[0]
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


def predict_flow(features: dict):
    """
    Phase 1C interface.

    Returns:
        (predicted_label, confidence, severity)
    """

    result = detect(features)

    return (
        result["predicted_label"],
        result["confidence"],
        result["severity"]
    )