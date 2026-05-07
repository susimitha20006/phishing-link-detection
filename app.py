# =========================
# app.py
# =========================

from flask import Flask, render_template, request, make_response
import joblib
import re
import tldextract
from Levenshtein import distance
from datetime import datetime

app = Flask(__name__)

model = joblib.load("phishing_model.pkl")

history = []

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


# =========================
# FEATURE EXTRACTION
# =========================

def extract_features(url):

    ext = tldextract.extract(url)
    domain = ext.domain.lower()

    features = [

        len(url),
        url.count('.'),
        1 if '@' in url else 0,
        url.count('-'),
        1 if "https" in url else 0,
        sum(c.isdigit() for c in url),
        len(re.findall(r'[^\w]', url)),
        len(ext.subdomain.split('.')) if ext.subdomain else 0,
        1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0,
        url.count('='),
        url.count('?'),
        url.count('_'),
        len(ext.suffix),
        len(domain),
        1 if url.startswith('http') else 0

    ]

    # Feature 16
    min_distance = min(distance(domain, legit) for legit in LEGIT_DOMAINS)
    features.append(min_distance)

    # Feature 17
    features.append(
        1 if re.search(r'[a-z][0-9]|[0-9][a-z]', domain) else 0
    )

    # Feature 18
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

    # Feature 19
    keywords = ['login', 'secure', 'verify', 'bank']

    features.append(
        sum(word in url.lower() for word in keywords)
    )

    return features


# =========================
# HOME PAGE
# =========================

@app.route("/", methods=["GET", "POST"])
def home():

    result = ""
    confidence = 0
    reasons = []

    if request.method == "POST":

        url = request.form["url"]

        # Reasons
        if len(url) > 50:
            reasons.append("Long URL")

        if any(word in url.lower() for word in ['login', 'verify', 'bank']):
            reasons.append("Suspicious keywords")

        if any(char.isdigit() for char in url):
            reasons.append("Contains numbers")

        try:

            # Manual fake brand detection
            fake_patterns = [
                "g00gle",
                "paypa1",
                "faceb00k",
                "micr0soft"
            ]

            if any(pattern in url.lower() for pattern in fake_patterns):

                result = "⚠️ Phishing Website (Fake brand detected)"
                confidence = 99

            else:

                features = extract_features(url)

                prob = model.predict_proba([features])[0]

                confidence = round(max(prob) * 100, 2)

                if prob[1] > 0.35:
                    result = f"⚠️ Phishing Website ({confidence}% confidence)"
                else:
                    result = f"✅ Safe Website ({confidence}% confidence)"

        except Exception as e:

            result = f"Error: {str(e)}"

        # Save history
        history.insert(0, {
            "url": url,
            "result": result,
            "reasons": reasons
        })

        # Keep only latest 5
        history[:] = history[:5]

        return render_template(
            "index.html",
            result=result,
            confidence=confidence,
            reasons=reasons,
            history=history
        )

    return render_template(
        "index.html",
        history=history
    )


# =========================
# DOWNLOAD REPORT
# =========================

@app.route("/download_report")
def download_report():

    if not history:
        return "No report available"

    latest = history[0]

    url = latest["url"]
    result = latest["result"]
    reasons = latest["reasons"]

    reasons_html = ""

    for reason in reasons:
        reasons_html += f"<li>{reason}</li>"

    html_report = f"""

    <!DOCTYPE html>

    <html>

    <head>

        <title>Phishing Report</title>

        <style>

            body {{
                background: #0d1117;
                color: white;
                font-family: Arial;
                padding: 40px;
            }}

            .report-box {{
                max-width: 700px;
                margin: auto;
                background: #161b22;
                padding: 30px;
                border-radius: 20px;
                border: 1px solid cyan;
                box-shadow: 0 0 30px cyan;
            }}

            h1 {{
                color: cyan;
                text-align: center;
            }}

            .label {{
                color: cyan;
                font-weight: bold;
                margin-top: 20px;
            }}

            li {{
                color: #ffcc00;
            }}

        </style>

    </head>

    <body>

        <div class="report-box">

            <h1>🛡 AI Phishing Detection Report</h1>

            <p class="label">URL:</p>
            <p>{url}</p>

            <p class="label">Result:</p>
            <p>{result}</p>

            <p class="label">Risk Indicators:</p>

            <ul>
                {reasons_html}
            </ul>

            <p class="label">Generated Time:</p>
            <p>{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>

        </div>

    </body>

    </html>

    """

    response = make_response(html_report)

    response.headers["Content-Disposition"] = \
        "attachment; filename=phishing_report.html"

    response.headers["Content-Type"] = "text/html"

    return response


# =========================
# RUN
# =========================

if __name__ == "__main__":
    app.run(debug=True)