import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib
from feature_extractor import extract_features

# Load dataset
df = pd.read_csv('urls.csv')

# Feature engineering
X = df['url'].apply(extract_features).tolist()
y = df['label']

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
clf = RandomForestClassifier()
clf.fit(X_train, y_train)

# Save model
joblib.dump(clf, 'model.pkl')

print("Model trained and saved!")
