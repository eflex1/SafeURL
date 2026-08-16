import pandas as pd
import re
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import pickle

# 1. CLEANED FEATURE EXTRACTION FUNCTION
def extract_features(url):
    if not isinstance(url, str):
        url = str(url)
    
    # CLEANING: Strip schema and www. so the AI doesn't get confused by browser URLs
    url = url.lower()
    url = re.sub(r'^https?://', '', url)
    url = re.sub(r'^www\.', '', url)
    
    url_length = len(url)
    
    try:
        # Fake a scheme just so urlparse can split the domain and path properly
        parsed_url = urlparse('http://' + url)
        domain = parsed_url.netloc
        path = parsed_url.path
        query = parsed_url.query
        full_path = path + query
        
        dot_count = domain.count('.')
        hyphen_count = domain.count('-')
        has_digits = 1 if any(char.isdigit() for char in domain) else 0
        
        # Expanded suspicious keyword list
        keywords = ['login', 'verify', 'secure', 'account', 'banking', 'update', 'signin', 'admin', 'payment']
        suspicious_keywords_count = sum(full_path.count(kw) for kw in keywords)
        
        is_ip = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0
        subdomain_count = max(0, dot_count - 1) if not is_ip else 0
        path_length = len(full_path)
        
    except Exception:
        # FALLBACK: If the URL is incredibly broken
        domain = url.split('/')[0]
        dot_count = domain.count('.')
        hyphen_count = domain.count('-')
        has_digits = 1 if any(char.isdigit() for char in domain) else 0
        suspicious_keywords_count = 0
        is_ip = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0
        subdomain_count = max(0, dot_count - 1) if not is_ip else 0
        path_length = 0

    return [url_length, dot_count, hyphen_count, has_digits, 
            suspicious_keywords_count, is_ip, subdomain_count, path_length]

print("Loading dataset 'malicious_phish.csv'...")

df = pd.read_csv('malicious_phish.csv')
df = df.dropna()
print(f"Dataset loaded successfully with {len(df)} records!")

# Group labels: 'benign' -> 0 (Safe), everything else -> 1 (Phishing)
df['label'] = df['type'].apply(lambda x: 0 if x == 'benign' else 1)

print("Extracting clean features (this will take a few minutes)...")
X = df['url'].apply(extract_features).tolist()
y = df['label'].tolist()

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print("Training the Random Forest model...")
rf_model = RandomForestClassifier(n_estimators=50, max_depth=20, random_state=42, n_jobs=-1)
rf_model.fit(X_train, y_train)

print("Evaluating model...")
y_pred = rf_model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print(f"\n✅ Model Training Complete!")
print(f"🎯 Detection Accuracy: {accuracy * 100:.2f}%")
print("\nDetailed Report:")
print(classification_report(y_test, y_pred, target_names=['Safe (0)', 'Malicious (1)']))

with open('phishing_model.pkl', 'wb') as f:
    pickle.dump(rf_model, f)
print("\nNew, highly intelligent 'phishing_model.pkl' saved!")