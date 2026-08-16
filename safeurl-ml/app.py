from flask import Flask, request, jsonify
import pickle
import re
from urllib.parse import urlparse

app = Flask(__name__)

# Load our newly trained model
try:
    with open('phishing_model.pkl', 'rb') as f:
        model = pickle.load(f)
except FileNotFoundError:
    print("Error: Model file not found.")

def extract_features(url):
    if not isinstance(url, str):
        url = str(url)
    
    # CLEANING
    url = url.lower()
    url = re.sub(r'^https?://', '', url)
    url = re.sub(r'^www\.', '', url)
    
    url_length = len(url)
    
    try:
        parsed_url = urlparse('http://' + url)
        domain = parsed_url.netloc
        path = parsed_url.path
        query = parsed_url.query
        full_path = path + query
        
        dot_count = domain.count('.')
        hyphen_count = domain.count('-')
        has_digits = 1 if any(char.isdigit() for char in domain) else 0
        
        keywords = ['login', 'verify', 'secure', 'account', 'banking', 'update', 'signin', 'admin', 'payment']
        suspicious_keywords_count = sum(full_path.count(kw) for kw in keywords)
        
        is_ip = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0
        subdomain_count = max(0, dot_count - 1) if not is_ip else 0
        path_length = len(full_path)
    except Exception:
        domain = url.split('/')[0]
        dot_count = domain.count('.')
        hyphen_count = domain.count('-')
        has_digits = 1 if any(char.isdigit() for char in domain) else 0
        suspicious_keywords_count = 0
        is_ip = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0
        subdomain_count = max(0, dot_count - 1) if not is_ip else 0
        path_length = 0

    return [[url_length, dot_count, hyphen_count, has_digits, 
            suspicious_keywords_count, is_ip, subdomain_count, path_length]]

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    url = data.get('url')

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    features = extract_features(url)
    
    probabilities = model.predict_proba(features)[0]
    phishing_prob = float(probabilities[1])

    return jsonify({
        "url": url,
        "phishing_probability": phishing_prob
    })

if __name__ == '__main__':
    app.run(port=5000, debug=True)