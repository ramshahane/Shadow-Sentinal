from flask import Flask, request, jsonify
import joblib
import pandas as pd
import numpy as np

app = Flask(__name__)

# Load the trained model
model = joblib.load("ddos_detection_model.pkl")

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.json
        df = pd.DataFrame([data])  # Convert JSON to DataFrame

        # Ensure the input format matches training data
        expected_columns = model.feature_names_in_
        df = df.reindex(columns=expected_columns, fill_value=0)

        prediction = model.predict(df)[0]
        prediction_label = "DDoS" if prediction == 1 else "Benign"

        return jsonify({"prediction": prediction_label})
    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
