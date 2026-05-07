import pandas as pd
import re
import tldextract
import joblib

from Levenshtein import distance
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

# -----------------------------
# LOAD DATASET
# -----------------------------
df = pd.read_csv("phishing.csv")

# convert columns lowercase
df.columns = df.columns.str.lower()

print(df.columns)

# -----------------------------
# CHECK REQUIRED COLUMNS
# -----------------------------
if 'url' not in df.columns:
    raise Exception("❌ Dataset must contain 'url' column")

if 'label' not in df.columns:
    raise Exception("❌ Dataset must contain 'label' column")

# -----------------------------
# LEGIT BRANDS
# -----------------------------
LEGIT_DOMAINS = [
    "google",
    "facebook",
    "amazon",
    "paypal",
    "apple",
    "microsoft",
    "instagram",
    "netflix",
    "twitter",
    "linkedin"
]

# -----------------------------
# FEATURE EXTRACTION
# -----------------------------
def extract_features(url):

    ext = tldextract.extract(str(url))
    domain = ext.domain.lower()

    features = []

    # 1
    features.append(len(url))

    # 2
    features.append(url.count('.'))

    # 3
    features.append(1 if '@' in url else 0)

    # 4
    features.append(url.count('-'))

    # 5
    features.append(1 if "https" in url else 0)

    # 6
    features.append(sum(c.isdigit() for c in url))

    # 7
    features.append(len(re.findall(r'[^\w]', url)))

    # 8
    features.append(
        len(ext.subdomain.split('.'))
        if ext.subdomain else 0
    )

    # 9
    features.append(
        1 if re.search(r'\d+\.\d+\.\d+\.\d+', url)
        else 0
    )

    # 10
    features.append(url.count('='))

    # 11
    features.append(url.count('?'))

    # 12
    features.append(url.count('_'))

    # 13
    features.append(len(ext.suffix))

    # 14
    features.append(len(domain))

    # 15
    features.append(1 if url.startswith('http') else 0)

    # 16 similarity to real brands
    min_distance = min(
        distance(domain, legit)
        for legit in LEGIT_DOMAINS
    )

    features.append(min_distance)

    # 17 digit-letter mix
    features.append(
        1 if re.search(r'[a-z][0-9]|[0-9][a-z]', domain)
        else 0
    )

    # 18 suspicious keywords
    suspicious = [
        'login',
        'secure',
        'verify',
        'account',
        'update',
        'bank'
    ]

    features.append(
        sum(word in url.lower() for word in suspicious)
    )

    # 19 phishing tricks
    features.append(
        1 if any(x in url.lower()
        for x in ['g00gle', 'paypa1', 'faceb00k'])
        else 0
    )

    return features

# -----------------------------
# EXTRACT FEATURES
# -----------------------------
X = df['url'].apply(extract_features)

X = pd.DataFrame(X.tolist())

y = df['label']

print("Feature count:", X.shape[1])

# -----------------------------
# TRAIN TEST SPLIT
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# -----------------------------
# TRAIN MODEL
# -----------------------------
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X_train, y_train)

# -----------------------------
# ACCURACY
# -----------------------------
accuracy = model.score(X_test, y_test)

print(f"Accuracy: {accuracy*100:.2f}%")

# -----------------------------
# SAVE MODEL
# -----------------------------
joblib.dump(model, "phishing_model.pkl")

print("✅ Model saved successfully")