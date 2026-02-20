import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import pickle
import os

# ===================== 1. SETUP =====================
np.random.seed(42)
N_SAMPLES = 3000

# ===================== 2. MEDICAL FEATURES =====================
gender = np.random.randint(0, 2, N_SAMPLES)        # 0=Female, 1=Male
age = np.random.randint(18, 80, N_SAMPLES)
smoking = np.random.randint(0, 3, N_SAMPLES)       # 0,1,2
bmi = np.random.uniform(18, 45, N_SAMPLES)
hba1c = np.random.uniform(4.5, 13.5, N_SAMPLES)
glucose = np.random.uniform(70, 350, N_SAMPLES)

# ===================== 3. FINGERPRINT FEATURES =====================
ridge_density = np.random.uniform(0.05, 0.45, N_SAMPLES)
complexity_score = np.random.uniform(10, 85, N_SAMPLES)
pattern_type = np.random.randint(0, 3, N_SAMPLES)  # 0=Arch,1=Loop,2=Whorl

# ===================== 4. RISK LOGIC (REALISTIC WEIGHTING) =====================
risk_score = (
    age * 0.3 +
    bmi * 1.5 +
    hba1c * 6.0 +
    glucose * 0.06 +
    smoking * 8 +
    ridge_density * 120 +
    complexity_score * 0.8 +
    pattern_type * 10 +
    gender * 2
)

low = np.percentile(risk_score, 33)
high = np.percentile(risk_score, 66)

def label_risk(score):
    if score < low:
        return 0   # LOW
    elif score < high:
        return 1   # MEDIUM
    else:
        return 2   # HIGH

risk_level = [label_risk(s) for s in risk_score]

# ===================== 5. DATAFRAME =====================
df = pd.DataFrame({
    'gender': gender,
    'age': age,
    'smoking': smoking,
    'bmi': bmi,
    'hba1c': hba1c,
    'glucose': glucose,
    'ridge_density': ridge_density,
    'complexity_score': complexity_score,
    'pattern_type': pattern_type,
    'risk_level': risk_level
})

print("\nSample Training Data:")
print(df.head())

# ===================== 6. TRAIN / TEST SPLIT =====================
X = df[
    ['gender', 'age', 'smoking', 'bmi', 'hba1c', 'glucose',
     'ridge_density', 'complexity_score', 'pattern_type']
]
y = df['risk_level']

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    stratify=y,
    random_state=42
)

# ===================== 7. MODEL =====================
model = RandomForestClassifier(
    n_estimators=400,
    max_depth=14,
    min_samples_split=5,
    random_state=42
)

model.fit(X_train, y_train)

# ===================== 8. EVALUATION =====================
preds = model.predict(X_test)

print("\nAccuracy:", accuracy_score(y_test, preds) * 100)
print("\nClassification Report:")
print(classification_report(y_test, preds))

# ===================== 9. SAVE MODEL =====================
os.makedirs('model', exist_ok=True)

with open('model/diabetes_fingerprint_model.pkl', 'wb') as f:
    pickle.dump(model, f)

print("\n✅ Model saved at model/diabetes_fingerprint_model.pkl")
