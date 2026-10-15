import os

import joblib
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)
from sklearn.model_selection import train_test_split


# ============================================================
# PATHS
# ============================================================

DATASET_PATH = "dataset/privacy_dataset.csv"
MODEL_DIR = "model"

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "privacy_model.pkl"
)

VECTORIZER_PATH = os.path.join(
    MODEL_DIR,
    "tfidf_vectorizer.pkl"
)


# ============================================================
# LOAD DATASET
# ============================================================

df = pd.read_csv(DATASET_PATH)


print("=" * 60)
print("PRIVACY BREACH DETECTOR - MODEL TRAINING")
print("=" * 60)

print("\nDataset loaded successfully.")

print(
    f"Number of samples: {len(df)}"
)


# ============================================================
# DATA VALIDATION
# ============================================================

required_columns = {
    "text",
    "label"
}

if not required_columns.issubset(df.columns):

    raise ValueError(
        "Dataset must contain 'text' and 'label' columns."
    )


df = df.dropna(
    subset=["text", "label"]
)


print("\nClass distribution:")

print(
    df["label"].value_counts()
    .sort_index()
)


# ============================================================
# WARN ABOUT SMALL DATASET
# ============================================================

if len(df) < 100:

    print("\nWARNING:")
    print(
        "The dataset is very small for a capstone "
        "machine-learning evaluation."
    )

    print(
        "Expand the dataset before using final "
        "accuracy/performance results."
    )


# ============================================================
# INPUT / OUTPUT
# ============================================================

X = df["text"].astype(str)

y = df["label"].astype(int)


# ============================================================
# TRAIN TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(

    X,
    y,

    test_size=0.2,

    random_state=42,

    stratify=y
)


print("\nTraining samples:", len(X_train))

print("Testing samples:", len(X_test))


# ============================================================
# TF-IDF
# ============================================================

vectorizer = TfidfVectorizer(

    lowercase=True,

    stop_words="english",

    ngram_range=(1, 2),

    sublinear_tf=True,

    min_df=1

)


X_train_tfidf = vectorizer.fit_transform(
    X_train
)

X_test_tfidf = vectorizer.transform(
    X_test
)


print("\nTF-IDF completed.")

print(
    "Number of TF-IDF features:",
    len(vectorizer.get_feature_names_out())
)


# ============================================================
# LOGISTIC REGRESSION
# ============================================================

model = LogisticRegression(

    max_iter=2000,

    C=1.0
)


model.fit(
    X_train_tfidf,
    y_train
)


print(
    "\nLogistic Regression training completed."
)


# ============================================================
# PREDICTION
# ============================================================

predictions = model.predict(
    X_test_tfidf
)


# ============================================================
# ACCURACY
# ============================================================

accuracy = accuracy_score(
    y_test,
    predictions
)


print(
    f"\nAccuracy: {accuracy * 100:.2f}%"
)


# ============================================================
# CLASSIFICATION REPORT
# ============================================================

print(
    "\nClassification Report:"
)

print(
    classification_report(

        y_test,

        predictions,

        labels=[0, 1, 2],

        target_names=[
            "Low Risk",
            "Medium Risk",
            "High Risk"
        ],

        zero_division=0
    )
)


# ============================================================
# CONFUSION MATRIX
# ============================================================

print(
    "\nConfusion Matrix:"
)

cm = confusion_matrix(

    y_test,

    predictions,

    labels=[0, 1, 2]
)

print(cm)


# ============================================================
# SAVE MODEL
# ============================================================

os.makedirs(
    MODEL_DIR,
    exist_ok=True
)


joblib.dump(
    model,
    MODEL_PATH
)


joblib.dump(
    vectorizer,
    VECTORIZER_PATH
)


print("\nModel saved to:")

print(MODEL_PATH)


print("\nTF-IDF vectorizer saved to:")

print(VECTORIZER_PATH)


print("\nTraining finished.")