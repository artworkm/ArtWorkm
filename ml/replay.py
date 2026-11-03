
import json
from pathlib import Path

import joblib
import pandas as pd
import requests


# --------------------------------------------------
# 1. Locate project files
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_PATH = PROJECT_ROOT / "data" / "clean.parquet"
MODEL_PATH = PROJECT_ROOT / "backend" / "models" / "ids_rf.joblib"
FEATURES_PATH = PROJECT_ROOT / "backend" / "models" / "features.json"

API_URL = "http://127.0.0.1:8000/events"
ORG_ID = 1


# --------------------------------------------------
# 2. Load the dataset, model, and feature names
# --------------------------------------------------

print("Loading dataset...")
df = pd.read_parquet(DATA_PATH)

print("Loading Random Forest model...")
model = joblib.load(MODEL_PATH)

with open(FEATURES_PATH, "r") as file:
    feature_names = json.load(file)

print("Dataset loaded:", df.shape)
print("Model loaded successfully!")
print("Number of model features:", len(feature_names))


# --------------------------------------------------
# 3. Select one example from each attack category
# --------------------------------------------------

samples = []

for label in sorted(df["Group"].unique()):
    sample = df[df["Group"] == label].sample(
        n=1,
        random_state=42
    )
    samples.append(sample)

test_data = pd.concat(samples, ignore_index=True)

print("\nSelected test samples:")
print(test_data["Group"].value_counts())


# --------------------------------------------------
# 4. Send each sample to the SentinelAI API
# --------------------------------------------------

print("\nStarting ML replay...\n")

for index, row in test_data.iterrows():

    # Extract the 69 model features
    features = {
        name: float(row[name])
        for name in feature_names
    }

    # Direct prediction from the loaded model
    direct_prediction = str(
        model.predict(pd.DataFrame([features]))[0]
    )

    # Send the event to FastAPI
    payload = {
        "org_id": ORG_ID,
        "event_type": "ml_replay",
        "source_ip": f"10.10.0.{index + 1}",
        "dest_ip": "10.10.0.100",
        "username": "ml_test",
        "success": True,
        "features": features
    }

    response = requests.post(
        API_URL,
        json=payload,
        timeout=30
    )

    response.raise_for_status()
    result = response.json()

    # Extract the ML prediction returned by the API
    ml_detections = [
        detection
        for detection in result["detections"]
        if detection["model_name"] == "RandomForest"
    ]

    if ml_detections:
        api_prediction = ml_detections[0]["predicted_label"]
    else:
        api_prediction = "BENIGN (no ML detection returned)"

    print(f"Sample {index + 1}")
    print(f"  Actual dataset label: {row['Group']}")
    print(f"  Direct model prediction: {direct_prediction}")
    print(f"  API ML prediction: {api_prediction}")
    print(f"  Event ID: {result['event_id']}")
    print("-" * 50)


print("\nML replay completed!")
