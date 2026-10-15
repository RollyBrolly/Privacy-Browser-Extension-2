import re


TOKEN_PATTERN = re.compile(r"\w+|[^\w\s]", re.UNICODE)
PII_CONFIDENCE_THRESHOLD = 0.9
KNOWN_PII_PATTERNS = (
    (
        "email",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
    ("phone", re.compile(r"(?<!\d)(?:\+63|0)\d{10,11}(?!\d)")),
    (
        "ip_address",
        re.compile(
            r"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
            r"(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b"
        ),
    ),
)
FIELD_LABELS = {
    "email",
    "e-mail",
    "mail",
    "phone",
    "telephone",
    "address",
    "name",
    "password",
}


def tokenize_with_offsets(text):
    return [
        (match.group(0), match.start(), match.end())
        for match in TOKEN_PATTERN.finditer(text)
    ]


def labels_from_spans(tokens, spans):
    labels = ["O"] * len(tokens)
    span_index = 0
    previous_entity_span = -1

    for token_index, (_, token_start, token_end) in enumerate(tokens):
        while (
            span_index < len(spans)
            and spans[span_index][1] <= token_start
        ):
            span_index += 1

        if span_index >= len(spans):
            continue

        span_start, span_end, span_label = spans[span_index]

        if (
            span_label != "O"
            and token_start < span_end
            and token_end > span_start
        ):
            labels[token_index] = (
                "I-PII"
                if previous_entity_span == span_index
                else "B-PII"
            )
            previous_entity_span = span_index
        else:
            previous_entity_span = -1

    return labels


def token_features(tokens, token_index):
    token = tokens[token_index][0]
    lowered = token.lower()
    shape = "".join(
        "X" if character.isupper()
        else "x" if character.islower()
        else "d" if character.isdigit()
        else character
        for character in token
    )

    features = [
        f"word={lowered}",
        f"shape={shape}",
        f"isupper={token.isupper()}",
        f"istitle={token.istitle()}",
        f"isdigit={token.isdigit()}",
        f"hasdigit={any(character.isdigit() for character in token)}",
    ]

    for length in range(1, 5):
        if len(lowered) >= length:
            features.append(f"prefix{length}={lowered[:length]}")
            features.append(f"suffix{length}={lowered[-length:]}")

    for distance in (1, 2):
        previous_index = token_index - distance
        next_index = token_index + distance

        if previous_index >= 0:
            previous = tokens[previous_index][0]
            features.append(f"prev{distance}={previous.lower()}")

        if next_index < len(tokens):
            following = tokens[next_index][0]
            features.append(f"next{distance}={following.lower()}")

    return features


def extract_entity_spans(tokens, labels):
    entities = []
    active_start = None
    active_end = None

    for (_, token_start, token_end), label in zip(tokens, labels):
        if label == "B-PII":
            if active_start is not None:
                entities.append((active_start, active_end))
            active_start = token_start
            active_end = token_end
        elif label == "I-PII":
            if active_start is None:
                active_start = token_start
            active_end = token_end
        elif active_start is not None:
            entities.append((active_start, active_end))
            active_start = None
            active_end = None

    if active_start is not None:
        entities.append((active_start, active_end))

    return entities


def predict_pii_entities(artifact, text):
    tokens = tokenize_with_offsets(text)

    if not tokens:
        return []

    features = [
        token_features(tokens, token_index)
        for token_index in range(len(tokens))
    ]
    token_matrix = artifact["hasher"].transform(features)
    classifier = artifact["classifier"]
    probabilities = classifier.predict_proba(token_matrix)
    pii_indexes = [
        index
        for index, label in enumerate(classifier.classes_)
        if label != "O"
    ]
    pii_probabilities = probabilities[:, pii_indexes].sum(axis=1)
    labels = []
    previous_is_pii = False

    for probability in pii_probabilities:
        is_pii = probability >= PII_CONFIDENCE_THRESHOLD
        labels.append(
            ("I-PII" if previous_is_pii else "B-PII")
            if is_pii
            else "O"
        )
        previous_is_pii = is_pii

    model_spans = extract_entity_spans(tokens, labels)
    pattern_spans = [
        (match.start(), match.end(), category)
        for category, pattern in KNOWN_PII_PATTERNS
        for match in pattern.finditer(text)
    ]
    entities = []

    for start, end in model_spans:
        field_label = text[start:end].strip(" \t\r\n:;,.-").casefold()
        overlaps_pattern = any(
            start < pattern_end and end > pattern_start
            for pattern_start, pattern_end, _ in pattern_spans
        )

        if field_label not in FIELD_LABELS and not overlaps_pattern:
            entities.append((start, end, "possible_pii"))

    entities.extend(pattern_spans)
    entities.sort(key=lambda entity: (entity[0], entity[1]))

    return [
        {
            "type": category,
            "start": start,
            "end": end,
        }
        for start, end, category in entities
    ]