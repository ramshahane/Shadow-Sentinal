# block suspicious files, allow only specific extensions

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import pickle

# Sample dataset
data = {
    'extension': ['.txt', '.exe', '.php', '.jpg', '.py'],
    'size': [1024, 5242880, 128, 2048, 4096],
    'content': ['print("Hello")', 'eval(system())', 'base64_decode()', 'safe content', 'os.system()'],
    'label': [0, 1, 1, 0, 1]  # 0 = Normal, 1 = Malicious
}

# Convert data to DataFrame
df = pd.DataFrame(data)

# Feature encoding
df['extension'] = df['extension'].map({'.txt': 0, '.exe': 1, '.php': 2, '.jpg': 3, '.py': 4})
df['content_length'] = df['content'].apply(len)
df.drop(columns=['content'], inplace=True)

# Train-test split
X = df.drop(columns=['label'])
y = df['label']

# Train Random Forest model
model = RandomForestClassifier()
model.fit(X, y)

# Save model
with open('file_detection_model.pkl', 'wb') as f:
    pickle.dump(model, f)
