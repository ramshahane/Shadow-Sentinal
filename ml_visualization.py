import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import streamlit as st
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_curve, auc
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
import joblib

# Set Streamlit page config
st.set_page_config(page_title="DDoS Detection Model", layout="wide")

# Title
st.title("DDoS Detection Model with Random Forest Classifier")

# Load dataset
st.write("Dataset loaded successfully.")
ddos = pd.read_csv("./ML Model Creation/APA-DDoS-Dataset.csv")

st.write(ddos.info())

st.write(ddos.isna().sum())

st.write(ddos.groupby('Label').size())

# Data preprocessing
ddos_new = ddos.drop(columns=['tcp.dstport', 'ip.proto', 'tcp.flags.syn', 'tcp.flags.reset', 
                              'tcp.flags.ack', 'ip.flags.mf', 'ip.flags.rb', 'tcp.seq', 'tcp.ack', 
                              'frame.time']).copy()

# Rename and label transformation
ddos_new['Label_new'] = ddos_new['Label'].apply(lambda x: 'Benign' if x == 'Benign' else 'DDoS')
ddos_new.drop(columns=['Label'], inplace=True)
ddos_new.rename(columns={'Label_new': 'Label'}, inplace=True)

# Encoding labels
y = ddos_new['Label']
label_encoder = LabelEncoder()
y = label_encoder.fit_transform(y)

X = ddos_new.drop(columns=['Label']).copy()

# OneHotEncoding for categorical columns
categorical_columns = ['ip.src', 'ip.dst']
preprocessor = ColumnTransformer(
    transformers=[('cat', OneHotEncoder(sparse_output=False, handle_unknown='ignore'), categorical_columns)],
    remainder='passthrough'
)


pipeline = Pipeline(steps=[('preprocessor', preprocessor)])

X_encoded = pipeline.fit_transform(X)

encoder = pipeline.named_steps['preprocessor'].named_transformers_['cat']
if hasattr(encoder, 'get_feature_names_out'):
    encoded_column_names = encoder.get_feature_names_out(categorical_columns)
else:
    encoded_column_names = encoder.get_feature_names(categorical_columns)
column_names = list(encoded_column_names) + list(X.columns.difference(categorical_columns))

X = pd.DataFrame(X_encoded, columns=column_names)

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train RandomForest model
rf_model = RandomForestClassifier()
rf_model.fit(X_train, y_train)

# Predictions
y_pred = rf_model.predict(X_test)

# Accuracy
accuracy = accuracy_score(y_test, y_pred)
st.title(f"Accuracy: {accuracy * 100:.2f}%")
# st.write(f"Accuracy: {accuracy * 100:.2f}%")

# Confusion Matrix
conf_matrix = confusion_matrix(y_test, y_pred)

# Plot confusion matrix
fig, ax = plt.subplots(figsize=(8, 6))
sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues', xticklabels=['Benign', 'DDoS'], yticklabels=['Benign', 'DDoS'])
plt.title('Confusion Matrix')
plt.xlabel('Predicted')
plt.ylabel('True')
st.pyplot(fig)

# Precision-Recall curve
precision, recall, _ = precision_recall_curve(y_test, rf_model.predict_proba(X_test)[:, 1])
area = auc(recall, precision)

fig, ax = plt.subplots(figsize=(8, 8))
plt.plot(recall, precision, label=f'Precision-Recall curve (area = {area:.2f})')
plt.xlabel('Recall')
plt.ylabel('Precision')
plt.title('Precision-Recall Curve')
plt.legend(loc='best')
st.pyplot(fig)

# F1 Score curve
f1 = 2 * (precision * recall) / (precision + recall)

fig, ax = plt.subplots(figsize=(8, 8))
plt.plot(recall, f1, label='F1 Score')
plt.xlabel('Recall')
plt.ylabel('F1 Score')
plt.title('F1 Score Curve')
plt.legend(loc='best')
st.pyplot(fig)

# Save the model
# joblib.dump(rf_model, 'ddos_detection_model.pkl')
# st.write("Model saved as ddos_detection_model.pkl")
