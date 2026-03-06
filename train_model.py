import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

print("Script started")

# Load data
data = pd.read_csv("traffic_data.csv")

print("Rows in dataset:", len(data))

# Select features
features = data[["PPS", "Unique_IPs", "TCP_Count", "UDP_Count"]]

# Create model
model = IsolationForest(contamination=0.02, random_state=42)

# Train model
model.fit(features)

# Save model
joblib.dump(model, "anomaly_model.pkl")

print("Model trained and saved successfully.")