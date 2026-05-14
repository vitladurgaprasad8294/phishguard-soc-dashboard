import math
import re
from collections import Counter, defaultdict


TRAINING_DATA = [
    ("verify your account login password reset account suspended", "Phishing"),
    ("urgent bank account locked click here verify immediately", "Phishing"),
    ("confirm identity payment failed update payment login", "Phishing"),
    ("invoice pdf exe open attachment payment urgent", "Phishing"),
    ("lottery winner prize free money claim now", "Spam"),
    ("crypto profit investment opportunity guaranteed income", "Spam"),
    ("loan approved earn money work from home congratulations", "Spam"),
    ("newsletter discount sale offer coupon webinar", "Marketing"),
    ("promotion limited offer subscribe unsubscribe campaign", "Marketing"),
    ("welcome booking ticket receipt account created successfully", "Safe"),
    ("project meeting submit report by friday professor", "Safe"),
    ("otp login notification order confirmed payment received", "Safe"),
]


def tokenize(text):
    text = (text or "").lower()
    return re.findall(r"[a-z0-9]{2,}", text)


class SimpleNaiveBayes:
    def __init__(self):
        self.class_counts = Counter()
        self.token_counts = defaultdict(Counter)
        self.vocab = set()
        self.total_docs = 0

    def fit(self, data):
        for text, label in data:
            self.total_docs += 1
            self.class_counts[label] += 1
            tokens = tokenize(text)
            self.vocab.update(tokens)
            self.token_counts[label].update(tokens)

    def predict_proba(self, text):
        tokens = tokenize(text)
        if not tokens:
            return {"Safe": 1.0}

        scores = {}
        vocab_size = max(len(self.vocab), 1)

        for label in self.class_counts:
            log_prob = math.log(self.class_counts[label] / self.total_docs)
            total_tokens = sum(self.token_counts[label].values())

            for token in tokens:
                count = self.token_counts[label][token]
                log_prob += math.log((count + 1) / (total_tokens + vocab_size))

            scores[label] = log_prob

        max_score = max(scores.values())
        exp_scores = {label: math.exp(score - max_score) for label, score in scores.items()}
        total = sum(exp_scores.values())
        return {label: value / total for label, value in exp_scores.items()}

    def predict(self, text):
        probs = self.predict_proba(text)
        label = max(probs, key=probs.get)
        return {
            "prediction": label,
            "confidence": round(probs[label] * 100, 2),
            "probabilities": {k: round(v * 100, 2) for k, v in probs.items()}
        }


_MODEL = None


def get_model():
    global _MODEL
    if _MODEL is None:
        _MODEL = SimpleNaiveBayes()
        _MODEL.fit(TRAINING_DATA)
    return _MODEL


def classify_with_ml(subject, body):
    text = f"{subject or ''} {body or ''}"
    return get_model().predict(text)
