from sklearn.ensemble import RandomForestClassifier
import numpy as np

# Example training data (features: [severity, exploitability, impact], labels: [0: low, 1: medium, 2: high])
X_train = np.array([
    [1, 0.5, 0.3],
    [2, 0.7, 0.5],
    [3, 0.9, 0.8],
    [1, 0.4, 0.2],
    [2, 0.6, 0.4]
])
y_train = np.array([0, 1, 2, 0, 1])

# Train a simple RandomForest model
model = RandomForestClassifier()
model.fit(X_train, y_train)

# Function to predict vulnerability severity
# Input: [severity, exploitability, impact]
def predict_severity(features):
    prediction = model.predict([features])
    return prediction[0]
