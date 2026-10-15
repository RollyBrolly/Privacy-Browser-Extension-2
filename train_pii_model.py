import ast
import csv
import os
import random
from collections import Counter

import joblib
import numpy as np
from sklearn.feature_extraction import FeatureHasher
from sklearn.linear_model import SGDClassifier

from pii_detection import labels_from_spans, token_features, tokenize_with_offsets


DATASET_PATH = os.path.join("dataset", "pii-masking-200k.csv")
MODEL_DIR = "model"
MODEL_PATH = os.path.join(MODEL_DIR, "pii_entity_model.pkl")
BATCH_SIZE = 8192
EPOCHS = 2
TEST_FRACTION = 0.2


def parse_spans(raw_spans, text):
    try:
        spans = ast.literal_eval(raw_spans)
    except (SyntaxError, ValueError, TypeError):
        return None

    if not isinstance(spans, list):
        return None

    previous_end = 0

    for span in spans:
        if (
            not isinstance(span, (list, tuple))
            or len(span) != 3
            or not isinstance(span[0], int)
            or not isinstance(span[1], int)
            or not isinstance(span[2], str)
            or span[0] < previous_end
            or span[1] < span[0]
            or span[1] > len(text)
        ):
            return None

        previous_end = span[1]

    return spans


def iter_dataset():
    with open(DATASET_PATH, encoding="utf-8-sig", newline="") as dataset_file:
        reader = csv.DictReader(dataset_file)
        required_columns = {"unmasked_text", "span_labels"}

        if not required_columns.issubset(reader.fieldnames or []):
            raise ValueError(
                "Dataset must contain 'unmasked_text' and 'span_labels' columns."
            )

        for row_index, row in enumerate(reader):
            text = row.get("unmasked_text") or ""
            spans = parse_spans(row.get("span_labels") or "", text)
            yield row_index, text, spans


def make_training_examples(text, spans):
    tokens = tokenize_with_offsets(text)
    labels = labels_from_spans(tokens, spans)
    features = [
        token_features(tokens, token_index)
        for token_index in range(len(tokens))
    ]
    return features, labels


def flush_batch(hasher, classifier, features, labels, class_weights, classes):
    if not features:
        return

    token_matrix = hasher.transform(features)
    sample_weights = np.asarray(
        [class_weights[label] for label in labels],
        dtype=np.float32,
    )

    if not hasattr(classifier, "classes_"):
        classifier.partial_fit(
            token_matrix,
            labels,
            classes=classes,
            sample_weight=sample_weights,
        )
    else:
        classifier.partial_fit(
            token_matrix,
            labels,
            sample_weight=sample_weights,
        )

    features.clear()
    labels.clear()


def main():
    if not os.path.isfile(DATASET_PATH):
        raise FileNotFoundError(f"Dataset not found: {DATASET_PATH}")

    print("Scanning annotations and counting token labels...")
    label_counts = Counter()
    valid_documents = 0
    invalid_documents = 0

    for _, text, spans in iter_dataset():
        if spans is None:
            invalid_documents += 1
            continue

        tokens = tokenize_with_offsets(text)
        label_counts.update(labels_from_spans(tokens, spans))
        valid_documents += 1

    if not valid_documents or not label_counts:
        raise ValueError("No valid annotated documents were found.")

    classes = np.asarray(sorted(label_counts))
    total_tokens = sum(label_counts.values())
    class_weights = {
        label: min(
            20.0,
            total_tokens / (len(classes) * count),
        )
        for label, count in label_counts.items()
    }

    print(f"Valid documents: {valid_documents}")
    print(f"Skipped invalid annotations: {invalid_documents}")
    print(f"Token labels: {dict(label_counts)}")

    hasher = FeatureHasher(
        n_features=2**18,
        input_type="string",
        alternate_sign=False,
    )
    classifier = SGDClassifier(
        loss="log_loss",
        alpha=1e-5,
        random_state=42,
    )

    for epoch in range(EPOCHS):
        features = []
        labels = []
        split_random = random.Random(42)
        trained_documents = 0

        for _, text, spans in iter_dataset():
            is_test_document = split_random.random() < TEST_FRACTION

            if spans is None or is_test_document:
                continue

            document_features, document_labels = make_training_examples(
                text,
                spans,
            )
            features.extend(document_features)
            labels.extend(document_labels)
            trained_documents += 1

            if len(labels) >= BATCH_SIZE:
                flush_batch(
                    hasher,
                    classifier,
                    features,
                    labels,
                    class_weights,
                    classes,
                )

        flush_batch(
            hasher,
            classifier,
            features,
            labels,
            class_weights,
            classes,
        )
        print(
            f"Training pass {epoch + 1}/{EPOCHS} completed "
            f"({trained_documents} documents)."
        )

    print("Evaluating on held-out documents...")
    split_random = random.Random(42)
    true_positive = 0
    false_positive = 0
    false_negative = 0
    correct_tokens = 0
    evaluated_tokens = 0
    features = []
    labels = []

    for _, text, spans in iter_dataset():
        is_test_document = split_random.random() < TEST_FRACTION

        if spans is None or not is_test_document:
            continue

        document_features, document_labels = make_training_examples(text, spans)
        features.extend(document_features)
        labels.extend(document_labels)

        if len(labels) >= BATCH_SIZE:
            token_matrix = hasher.transform(features)
            predictions = classifier.predict(token_matrix)
            true_positive += sum(
                actual != "O" and predicted != "O"
                for actual, predicted in zip(labels, predictions)
            )
            false_positive += sum(
                actual == "O" and predicted != "O"
                for actual, predicted in zip(labels, predictions)
            )
            false_negative += sum(
                actual != "O" and predicted == "O"
                for actual, predicted in zip(labels, predictions)
            )
            correct_tokens += sum(
                actual == predicted
                for actual, predicted in zip(labels, predictions)
            )
            evaluated_tokens += len(labels)
            features.clear()
            labels.clear()

    if labels:
        token_matrix = hasher.transform(features)
        predictions = classifier.predict(token_matrix)
        true_positive += sum(
            actual != "O" and predicted != "O"
            for actual, predicted in zip(labels, predictions)
        )
        false_positive += sum(
            actual == "O" and predicted != "O"
            for actual, predicted in zip(labels, predictions)
        )
        false_negative += sum(
            actual != "O" and predicted == "O"
            for actual, predicted in zip(labels, predictions)
        )
        correct_tokens += sum(
            actual == predicted
            for actual, predicted in zip(labels, predictions)
        )
        evaluated_tokens += len(labels)

    precision = true_positive / max(true_positive + false_positive, 1)
    recall = true_positive / max(true_positive + false_negative, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-12)
    accuracy = correct_tokens / max(evaluated_tokens, 1)

    print(f"Held-out token accuracy: {accuracy * 100:.2f}%")
    print(f"PII-token precision: {precision * 100:.2f}%")
    print(f"PII-token recall: {recall * 100:.2f}%")
    print(f"PII-token F1: {f1 * 100:.2f}%")

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(
        {
            "hasher": hasher,
            "classifier": classifier,
        },
        MODEL_PATH,
    )
    print(f"PII entity model saved to: {MODEL_PATH}")


if __name__ == "__main__":
    main()