from flask import Flask, request, jsonify
from flask_cors import CORS

import joblib
import re
import os

from pii_detection import predict_pii_entities

app = Flask(__name__)
CORS(app)


# ============================================================
# LOAD MODEL
# ============================================================

MODEL_PATH = os.path.join("model", "privacy_model.pkl")
VECTORIZER_PATH = os.path.join("model", "tfidf_vectorizer.pkl")
PII_MODEL_PATH = os.path.join("model", "pii_entity_model.pkl")

model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)
pii_model = (
    joblib.load(PII_MODEL_PATH)
    if os.path.isfile(PII_MODEL_PATH)
    else None
)


LABELS = {
    0: "LOW",
    1: "MEDIUM",
    2: "HIGH"
}


# ============================================================
# PRIVACY KEYWORDS
# ============================================================

PRIVACY_KEYWORDS = {

    "email": [
        "email",
        "email address",
        "e-mail"
    ],

    "phone": [
        "phone number",
        "telephone number",
        "mobile number",
        "contact number"
    ],

    "address": [
        "home address",
        "street address",
        "postal address",
        "mailing address"
    ],

    "location": [
        "location",
        "gps",
        "geolocation",
        "current location"
    ],

    "password": [
        "password",
        "passcode",
        "login password"
    ],

    "otp": [
        "otp",
        "one-time password",
        "verification code",
        "authentication code"
    ],

    "credit_card": [
        "credit card",
        "credit card number",
        "card number"
    ],

    "bank_account": [
        "bank account",
        "bank account number",
        "bank details",
        "banking information"
    ],

    "government_id": [
        "government id",
        "government identification",
        "national id",
        "passport",
        "driver's license",
        "drivers license",
        "tax id"
    ],

    "medical": [
        "medical record",
        "medical records",
        "health record",
        "health information",
        "medical information",
        "prescription"
    ],

    "date_of_birth": [
        "date of birth",
        "birth date",
        "birthday"
    ]
}


COLLECTION_PHRASES = [
    "enter your",
    "provide your",
    "submit your",
    "upload your",
    "please provide",
    "please enter",
    "type your",
    "fill in your",
    "create an account",
    "register your",
    "give us your"
]


TRACKING_PHRASES = [
    "cookies",
    "tracking",
    "analytics",
    "personalized ads",
    "advertising",
    "third party",
    "third-party"
]


# ============================================================
# TEXT CLEANING
# ============================================================

def normalize_text(text):
    if not isinstance(text, str):
        return ""

    text = text.lower()

    text = re.sub(r"\s+", " ", text)

    return text.strip()


# ============================================================
# PII PATTERN DETECTION
# ============================================================

def detect_pii_patterns(text):

    findings = []

    # Email
    email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"

    if re.search(email_pattern, text):
        findings.append({
            "type": "email",
            "source": "pattern",
            "message": "Email address detected in webpage content."
        })

    # Phone
    phone_pattern = r"(?<!\d)(?:\+63|0)\d{10,11}(?!\d)"

    if re.search(phone_pattern, text):
        findings.append({
            "type": "phone",
            "source": "pattern",
            "message": "Phone number pattern detected."
        })

    # IPv4
    ip_pattern = (
        r"\b"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
        r"(?:\."
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
        r"){3}"
        r"\b"
    )

    if re.search(ip_pattern, text):
        findings.append({
            "type": "ip_address",
            "source": "pattern",
            "message": "IP address detected."
        })

    return findings


# ============================================================
# KEYWORD DETECTION
# ============================================================

def detect_sensitive_categories(text):

    normalized = normalize_text(text)

    detected = []

    for category, keywords in PRIVACY_KEYWORDS.items():

        matched_keywords = []

        for keyword in keywords:

            if keyword in normalized:
                matched_keywords.append(keyword)

        if matched_keywords:

            detected.append({
                "category": category,
                "keywords": matched_keywords
            })

    return detected


# ============================================================
# COLLECTION LANGUAGE
# ============================================================

def detect_collection_indicators(text):

    normalized = normalize_text(text)

    found = []

    for phrase in COLLECTION_PHRASES:

        if phrase in normalized:

            found.append(phrase)

    return list(dict.fromkeys(found))


# ============================================================
# TRACKING INDICATORS
# ============================================================

def detect_tracking_indicators(text):

    normalized = normalize_text(text)

    found = []

    for phrase in TRACKING_PHRASES:

        if phrase in normalized:

            found.append(phrase)

    return list(dict.fromkeys(found))


# ============================================================
# FORM ANALYSIS
# ============================================================

# Structured signals: HTML input types that always mean a specific
# category of data is being collected.
INPUT_TYPE_CATEGORIES = {
    "password": "password",
    "email": "email",
    "tel": "phone"
}


# Structured signals: HTML autocomplete tokens defined by the spec.
AUTOCOMPLETE_CATEGORIES = {
    "one-time-code": "otp",
    "cc-name": "credit_card",
    "cc-number": "credit_card",
    "cc-exp": "credit_card",
    "cc-csc": "credit_card",
    "cc-type": "credit_card",
    "bday": "date_of_birth",
    "bday-day": "date_of_birth",
    "bday-month": "date_of_birth",
    "bday-year": "date_of_birth",
    "email": "email",
    "tel": "phone",
    "tel-national": "phone",
    "street-address": "address",
    "address-line1": "address",
    "address-line2": "address",
    "postal-code": "address"
}


# Textual signals: terms searched inside field labels, placeholders,
# accessible labels, instructions, names, and ids. Checked in order;
# the first matching category wins.
FORM_FIELD_TERMS = {

    "password": [
        "password",
        "passcode",
        "passphrase",
        "login password"
    ],

    "otp": [
        "otp",
        "one-time password",
        "one time password",
        "verification code",
        "authentication code",
        "2fa code",
        "sms code"
    ],

    "credit_card": [
        "credit card",
        "debit card",
        "card number",
        "cardholder",
        "cvv",
        "cvc",
        "expiry date",
        "expiration date"
    ],

    "bank_account": [
        "bank account",
        "bank details",
        "account number",
        "routing number",
        "iban",
        "sort code"
    ],

    "government_id": [
        "government id",
        "national id",
        "passport",
        "driver's license",
        "drivers license",
        "social security",
        "ssn",
        "tax id",
        "tax identification"
    ],

    "medical": [
        "medical",
        "health information",
        "health insurance",
        "medical history",
        "prescription",
        "diagnosis"
    ],

    "date_of_birth": [
        "date of birth",
        "birth date",
        "birthday",
        "bday",
        "dob"
    ],

    "phone": [
        "phone number",
        "phone",
        "telephone",
        "mobile number",
        "cell number",
        "contact number"
    ],

    "email": [
        "email",
        "e-mail"
    ],

    "address": [
        "address",
        "street address",
        "home address",
        "mailing address",
        "postal address",
        "zip code",
        "postal code",
        "apartment",
        "unit number"
    ]
}


# Fields the page uses to collect information about the user. These
# are strong evidence; keyword matches in visible page text are not.
FORM_METADATA_KEYS = (
    "label",
    "placeholder",
    "accessibleLabel",
    "instructions",
    "name",
    "id"
)


def contains_term(text, term):
    return re.search(rf"\b{re.escape(term)}\b", text) is not None


def classify_form_field(field, form_purpose=""):

    input_type = normalize_text(field.get("type", "")).lower()
    autocomplete = normalize_text(field.get("autocomplete", "")).lower()

    if input_type in INPUT_TYPE_CATEGORIES:

        category = INPUT_TYPE_CATEGORIES[input_type]

        return category, [f'HTML input type is "{input_type}"']

    if autocomplete in AUTOCOMPLETE_CATEGORIES:

        category = AUTOCOMPLETE_CATEGORIES[autocomplete]

        return category, [f'autocomplete attribute is "{autocomplete}"']

    field_text = normalize_text(" ".join(
        str(field.get(key, "") or "")
        for key in FORM_METADATA_KEYS
    ))

    for category, terms in FORM_FIELD_TERMS.items():

        for term in terms:

            if contains_term(field_text, term):

                return (
                    category,
                    [f'label, placeholder, or instructions mention "{term}"']
                )

    purpose_text = normalize_text(form_purpose)

    for category, terms in FORM_FIELD_TERMS.items():

        for term in terms:

            if contains_term(purpose_text, term):

                return (
                    category,
                    [f'form purpose mentions "{term}"']
                )

    return None, []


def analyze_forms(forms):

    sensitive_fields = []

    if not isinstance(forms, list):
        return sensitive_fields

    for form in forms:

        if not isinstance(form, dict):
            continue

        fields = form.get("fields", [])

        if not isinstance(fields, list):
            continue

        form_purpose = str(form.get("purpose", "") or "")
        form_action = str(form.get("action", "") or "")
        cross_origin = bool(form.get("crossOriginAction", False))

        for field in fields:

            if not isinstance(field, dict):
                continue

            category, evidence = classify_form_field(
                field,
                form_purpose
            )

            if not category:
                continue

            sensitive_fields.append({
                "category": category,
                "type": field.get("type", ""),
                "name": field.get("name", ""),
                "label": field.get("label", ""),
                "placeholder": field.get("placeholder", ""),
                "accessibleLabel": field.get("accessibleLabel", ""),
                "instructions": field.get("instructions", ""),
                "formPurpose": form_purpose,
                "required": bool(field.get("required", False)),
                "formAction": form_action,
                "crossOriginAction": cross_origin,
                "evidence": evidence
            })

    return sensitive_fields


def build_collection_summary(sensitive_fields, sensitive_categories):

    collected_categories = []

    for field in sensitive_fields:

        if field["category"] not in collected_categories:
            collected_categories.append(field["category"])

    collected_set = set(collected_categories)

    mentioned_only = [
        item["category"]
        for item in sensitive_categories
        if item["category"] not in collected_set
    ]

    cross_origin_fields = [
        field
        for field in sensitive_fields
        if field.get("crossOriginAction")
    ]

    return {
        "collects_sensitive_data": bool(collected_categories),
        "collected_categories": collected_categories,
        "mentioned_only_categories": mentioned_only,
        "sensitive_field_count": len(sensitive_fields),
        "cross_origin_field_count": len(cross_origin_fields)
    }


# ============================================================
# TF-IDF IMPORTANT TERMS
# ============================================================

def get_top_tfidf_terms(text, limit=10):

    features = vectorizer.transform([text])

    values = features.toarray()[0]

    feature_names = vectorizer.get_feature_names_out()

    ranked_indices = values.argsort()[::-1]

    terms = []

    for index in ranked_indices:

        if values[index] <= 0:
            break

        terms.append({
            "term": feature_names[index],
            "score": round(float(values[index]), 4)
        })

        if len(terms) >= limit:
            break

    return terms


# ============================================================
# ML CLASSIFICATION
# ============================================================

def classify_text(text):

    features = vectorizer.transform([text])

    prediction = int(model.predict(features)[0])

    probabilities = model.predict_proba(features)[0]

    result = {
        "risk": LABELS[prediction],
        "confidence": round(
            float(probabilities[prediction]) * 100,
            2
        ),
        "probabilities": {
            LABELS[int(index)]: round(
                float(probability) * 100,
                2
            )
            for index, probability
            in enumerate(probabilities)
        }
    }

    return result


# ============================================================
# RISK INDICATOR SCORE
# ============================================================

def calculate_risk_score(
    prediction,
    sensitive_categories,
    pii_findings,
    sensitive_fields,
    collection_indicators,
    tracking_indicators
):

    score = prediction["confidence"]

    category_names = {
        item["category"]
        for item in sensitive_categories
    }

    high_categories = {
        "password",
        "otp",
        "credit_card",
        "bank_account",
        "government_id",
        "medical"
    }

    medium_categories = {
        "email",
        "phone",
        "address",
        "location",
        "date_of_birth"
    }

    # Strong evidence: a form field actually collects this category.
    collected_categories = {
        field["category"]
        for field in sensitive_fields
    }

    score += len(collected_categories.intersection(high_categories)) * 8
    score += len(collected_categories.intersection(medium_categories)) * 4
    score += min(len(sensitive_fields), 10) * 2

    # Cross-origin form submissions send the data to another domain.
    cross_origin_fields = [
        field
        for field in sensitive_fields
        if field.get("crossOriginAction")
    ]

    score += min(len(cross_origin_fields), 5) * 3

    # Weak evidence: keywords only appear in visible page text.
    mentioned_only = category_names - collected_categories

    score += min(len(mentioned_only), 5) * 1
    score += len(pii_findings) * 3
    score += min(len(collection_indicators), 3) * 2
    score += min(len(tracking_indicators), 3)

    return round(max(0, min(100, score)), 2)


# ============================================================
# EXPLANATION
# ============================================================

def generate_explanation(
    risk,
    sensitive_categories,
    sensitive_fields,
    collection_indicators,
    tracking_indicators,
    pii_findings
):

    reasons = []

    for item in sensitive_categories:

        category = item["category"]

        readable = category.replace("_", " ").title()

        reasons.append(
            f"{readable} information detected."
        )

    for field in sensitive_fields:

        readable = field["category"].replace("_", " ").title()

        reasons.append(
            f"{readable} input field detected in a webpage form. "
            f"This page asks you to provide this information."
        )

    collected_categories = {
        field["category"]
        for field in sensitive_fields
    }

    for item in sensitive_categories:

        if item["category"] in collected_categories:
            continue

        readable = item["category"].replace("_", " ").title()

        reasons.append(
            f"{readable} was only mentioned in the page text. "
            f"No form field was found that collects it."
        )

    if collection_indicators:

        reasons.append(
            "Language indicating collection or submission of user information was detected."
        )

    if tracking_indicators:

        reasons.append(
            "Tracking or third-party data-usage indicators were detected."
        )

    if pii_findings:

        reasons.append(
            "Potential personally identifiable information patterns were detected."
        )

    if not reasons:

        if risk == "LOW":
            reasons.append(
                "No major privacy-sensitive indicators were detected."
            )

        elif risk == "MEDIUM":
            reasons.append(
                "Some privacy-related content was detected, but no major sensitive indicators were found."
            )

        else:
            reasons.append(
                "The machine-learning model classified the webpage as high privacy risk."
            )

    # Remove duplicates while preserving order
    reasons = list(dict.fromkeys(reasons))

    return reasons


# ============================================================
# /predict
# ============================================================

@app.route("/predict", methods=["POST"])
def predict():

    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "error": "Invalid JSON request."
        }), 400

    text = data.get("text")

    if not isinstance(text, str) or not text.strip():
        return jsonify({
            "error": "No valid text provided."
        }), 400

    text = text[:50000]

    prediction = classify_text(text)

    return jsonify(prediction)


# ============================================================
# /analyze
# ============================================================

@app.route("/analyze", methods=["POST"])
def analyze():

    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "error": "Invalid JSON request."
        }), 400

    text = data.get("text", "")
    title = data.get("title", "")
    forms = data.get("forms", [])
    external_resources = data.get(
        "externalResources",
        []
    )

    if not isinstance(text, str):
        return jsonify({
            "error": "Text must be a string."
        }), 400

    combined_text = f"{title}\n{text}"

    combined_text = combined_text[:50000]

    # -----------------------------
    # ML
    # -----------------------------

    prediction = classify_text(combined_text)

    # -----------------------------
    # Privacy Detection
    # -----------------------------

    sensitive_categories = detect_sensitive_categories(
        combined_text
    )

    pii_findings = detect_pii_patterns(
        combined_text
    )

    pii_entities = (
        predict_pii_entities(pii_model, text[:50000])
        if pii_model is not None
        else []
    )

    collection_indicators = detect_collection_indicators(
        combined_text
    )

    tracking_indicators = detect_tracking_indicators(
        combined_text
    )

    sensitive_fields = analyze_forms(forms)

    collection_summary = build_collection_summary(
        sensitive_fields,
        sensitive_categories
    )

    # -----------------------------
    # TF-IDF terms
    # -----------------------------

    tfidf_terms = get_top_tfidf_terms(
        combined_text
    )

    risk_score = calculate_risk_score(
        prediction,
        sensitive_categories,
        pii_findings,
        sensitive_fields,
        collection_indicators,
        tracking_indicators
    )

    # -----------------------------
    # Explanation
    # -----------------------------

    explanation = generate_explanation(
        prediction["risk"],
        sensitive_categories,
        sensitive_fields,
        collection_indicators,
        tracking_indicators,
        pii_findings
    )

    # -----------------------------
    # Recommendation
    # -----------------------------

    if prediction["risk"] == "HIGH":

        recommendation = (
            "Avoid submitting sensitive information unless "
            "the website is trusted and the request is necessary."
        )

    elif prediction["risk"] == "MEDIUM":

        recommendation = (
            "Review what information the website is requesting "
            "before submitting it."
        )

    else:

        recommendation = (
            "No major privacy-risk indicators were detected. "
            "Continue normal privacy precautions."
        )

    if collection_summary["collects_sensitive_data"]:

        collected = ", ".join(
            category.replace("_", " ")
            for category in collection_summary["collected_categories"]
        )

        recommendation += (
            f" This page asks for: {collected}."
        )

    if collection_summary["cross_origin_field_count"] > 0:

        recommendation += (
            " Some sensitive fields are submitted to a different "
            "domain than the page itself."
        )

    return jsonify({

        "risk": prediction["risk"],

        "risk_score": risk_score,

        "confidence": prediction["confidence"],

        "probabilities": prediction["probabilities"],

        "detected_information": sensitive_categories,

        "pii_patterns": pii_findings,

        "pii_entities": pii_entities,

        "pii_entity_model_loaded": pii_model is not None,

        "sensitive_form_fields": sensitive_fields,

        "collection_summary": collection_summary,

        "collection_indicators": collection_indicators,

        "tracking_indicators": tracking_indicators,

        "external_resource_count": len(
            external_resources
        ),

        "tfidf_terms": tfidf_terms,

        "explanation": explanation,

        "recommendation": recommendation

    })


# ============================================================
# HOME
# ============================================================

@app.route("/", methods=["GET"])
def home():

    return jsonify({
        "status": "running",
        "service": "Privacy Breach Detection API",
        "models": [
            "TF-IDF + Logistic Regression risk classifier",
            "PII token detector"
        ]
    })


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )