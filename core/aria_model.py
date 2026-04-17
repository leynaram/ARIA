# core/aria_model.py
"""
ARIA Neural Net — Modèle IA custom de A à Z.
Réseau de neurones entraînable sur tes propres données.
Aucune dépendance externe (NumPy seulement).
"""

import numpy as np
import json
import os
import re
from datetime import datetime


# ─── COUCHES ──────────────────────────────────────────────────────
class DenseLayer:
    def __init__(self, input_size: int, output_size: int):
        # Initialisation Xavier
        self.W = np.random.randn(input_size, output_size) * np.sqrt(2.0 / input_size)
        self.b = np.zeros((1, output_size))
        self.dW = self.db = self.last_input = None

    def forward(self, x: np.ndarray) -> np.ndarray:
        self.last_input = x
        return x @ self.W + self.b

    def backward(self, grad: np.ndarray) -> np.ndarray:
        self.dW = self.last_input.T @ grad
        self.db = grad.sum(axis=0, keepdims=True)
        return grad @ self.W.T


class ReLU:
    def __init__(self):
        self.mask = None

    def forward(self, x):
        self.mask = x > 0
        return x * self.mask

    def backward(self, grad):
        return grad * self.mask


class Dropout:
    def __init__(self, rate=0.2):
        self.rate = rate
        self.mask = None
        self.training = True

    def forward(self, x):
        if not self.training:
            return x
        self.mask = np.random.rand(*x.shape) > self.rate
        return x * self.mask / (1 - self.rate)

    def backward(self, grad):
        return grad * self.mask / (1 - self.rate) if self.training else grad


# ─── FONCTIONS ────────────────────────────────────────────────────
def softmax(x):
    e = np.exp(x - x.max(axis=1, keepdims=True))
    return e / e.sum(axis=1, keepdims=True)

def cross_entropy_loss(pred, true_labels):
    n = pred.shape[0]
    log_p = np.log(pred[range(n), true_labels] + 1e-9)
    return -log_p.mean()

def cross_entropy_grad(pred, true_labels):
    grad = pred.copy()
    n = pred.shape[0]
    grad[range(n), true_labels] -= 1
    return grad / n


# ─── TOKENIZER ────────────────────────────────────────────────────
class ARIATokenizer:
    def __init__(self, vocab_size: int = 2000):
        self.vocab_size  = vocab_size
        self.word2idx    = {"<PAD>": 0, "<UNK>": 1}
        self.idx2word    = {0: "<PAD>", 1: "<UNK>"}
        self.vocab_built = False

    def build_vocab(self, texts: list):
        freq = {}
        for text in texts:
            for w in self._tokenize(text):
                freq[w] = freq.get(w, 0) + 1
        for w, _ in sorted(freq.items(), key=lambda x: -x[1])[:self.vocab_size - 2]:
            idx = len(self.word2idx)
            self.word2idx[w] = idx
            self.idx2word[idx] = w
        self.vocab_built = True

    def _tokenize(self, text: str) -> list:
        text = text.lower()
        text = re.sub(r'[^a-zàâçéèêëîïôûùüÿæœ\s]', ' ', text)
        return [w for w in text.split() if len(w) > 1]

    def encode(self, text: str, max_len: int = 32) -> np.ndarray:
        tokens = [self.word2idx.get(w, 1) for w in self._tokenize(text)]
        tokens = tokens[:max_len]
        tokens += [0] * (max_len - len(tokens))
        return np.array(tokens)

    def texts_to_bow(self, texts: list) -> np.ndarray:
        """Bag of Words vectorization."""
        vs = max(len(self.word2idx), 100)
        X  = np.zeros((len(texts), vs))
        for i, text in enumerate(texts):
            for w in self._tokenize(text):
                idx = self.word2idx.get(w, 1)
                if idx < vs:
                    X[i, idx] += 1
        # TF-IDF normalization
        X = X / (X.sum(axis=1, keepdims=True) + 1e-9)
        return X

    def save(self, path: str):
        with open(path, "w") as f:
            json.dump({"word2idx": self.word2idx}, f)

    def load(self, path: str):
        with open(path) as f:
            d = json.load(f)
        self.word2idx    = d["word2idx"]
        self.idx2word    = {int(v): k for k, v in self.word2idx.items()}
        self.vocab_built = True


# ─── MODÈLE PRINCIPAL ─────────────────────────────────────────────
class ARIAModel:
    """
    Réseau de neurones custom pour ARIA.
    Classifie les intentions utilisateur.
    """
    def __init__(self, input_size: int, hidden_sizes: list, output_size: int, lr: float = 0.001):
        self.lr     = lr
        self.layers = []
        sizes       = [input_size] + hidden_sizes + [output_size]

        for i in range(len(sizes) - 1):
            self.layers.append(DenseLayer(sizes[i], sizes[i+1]))
            if i < len(sizes) - 2:
                self.layers.append(ReLU())
                self.layers.append(Dropout(0.2))

        self.history = {"loss": [], "accuracy": []}

    def forward(self, x: np.ndarray, training: bool = True) -> np.ndarray:
        for layer in self.layers:
            if isinstance(layer, Dropout):
                layer.training = training
            x = layer.forward(x)
        return softmax(x)

    def backward(self, pred: np.ndarray, labels: np.ndarray):
        grad = cross_entropy_grad(pred, labels)
        for layer in reversed(self.layers):
            grad = layer.backward(grad)
        # Mise à jour Adam simplifiée
        for layer in self.layers:
            if isinstance(layer, DenseLayer):
                layer.W -= self.lr * layer.dW
                layer.b -= self.lr * layer.db

    def train(self, X: np.ndarray, y: np.ndarray, epochs: int = 100, batch_size: int = 32):
        n = X.shape[0]
        for epoch in range(epochs):
            idxs    = np.random.permutation(n)
            X, y    = X[idxs], y[idxs]
            ep_loss, ep_acc = 0, 0

            for i in range(0, n, batch_size):
                Xb  = X[i:i+batch_size]
                yb  = y[i:i+batch_size]
                pred = self.forward(Xb, training=True)
                loss = cross_entropy_loss(pred, yb)
                self.backward(pred, yb)
                ep_loss += loss
                ep_acc  += (pred.argmax(axis=1) == yb).mean()

            steps = max(1, n // batch_size)
            ep_loss /= steps
            ep_acc  /= steps
            self.history["loss"].append(float(ep_loss))
            self.history["accuracy"].append(float(ep_acc))

            if (epoch + 1) % 10 == 0:
                print(f"Epoch {epoch+1:3d}/{epochs} — Loss: {ep_loss:.4f} — Acc: {ep_acc:.1%}")

        return self.history

    def predict(self, x: np.ndarray) -> tuple:
        probs   = self.forward(x, training=False)
        idx     = probs.argmax(axis=1)[0]
        conf    = float(probs[0, idx])
        return idx, conf

    def save(self, path: str):
        data = {}
        for i, layer in enumerate(self.layers):
            if isinstance(layer, DenseLayer):
                data[f"W_{i}"] = layer.W.tolist()
                data[f"b_{i}"] = layer.b.tolist()
        with open(path, "w") as f:
            json.dump(data, f)
        print(f"✅ Modèle sauvegardé : {path}")

    def load(self, path: str):
        with open(path) as f:
            data = json.load(f)
        for i, layer in enumerate(self.layers):
            if isinstance(layer, DenseLayer):
                layer.W = np.array(data[f"W_{i}"])
                layer.b = np.array(data[f"b_{i}"])
        print(f"✅ Modèle chargé : {path}")


# ─── ARIA INTENT CLASSIFIER ───────────────────────────────────────
class ARIAIntentClassifier:
    """
    Classificateur d'intentions entraîné sur tes propres données.
    100% custom, zéro dépendance externe.
    """
    INTENTS = [
        "cyber_threat", "cloudflare", "defender", "jira",
        "rapport", "osint", "audit", "self_repair",
        "conversation", "salutation"
    ]

    TRAINING_DATA = [
        # cyber_threat
        ("il y a une attaque sur mon serveur", 0),
        ("j'ai détecté une intrusion", 0),
        ("mon système est compromis", 0),
        ("ransomware détecté", 0),
        ("phishing en cours", 0),
        # cloudflare
        ("montre les événements cloudflare", 1),
        ("statut du pare-feu", 1),
        ("protection ddos active", 1),
        ("règles waf cloudflare", 1),
        # defender
        ("alertes microsoft defender", 2),
        ("score de sécurité defender", 2),
        ("vulnérabilités critiques", 2),
        ("endpoints compromis", 2),
        # jira
        ("tickets jira ouverts", 3),
        ("créer un ticket incident", 3),
        ("statut des incidents", 3),
        # rapport
        ("rédige un rapport d'incident", 4),
        ("génère un rapport de sécurité", 4),
        ("synthèse de l'incident", 4),
        # osint
        ("recherche cette personne", 5),
        ("trouve des infos sur", 5),
        ("analyse cet email", 5),
        ("vérifie ce username", 5),
        # audit
        ("lancer un audit de sécurité", 6),
        ("évaluation de conformité", 6),
        ("audit rgpd", 6),
        # self_repair
        ("corrige cette erreur", 7),
        ("répare le bug", 7),
        ("améliore ton code", 7),
        ("ajoute une fonctionnalité", 7),
        # conversation
        ("comment ça va", 8),
        ("explique moi", 8),
        ("qu'est ce que", 8),
        ("aide moi à comprendre", 8),
        # salutation
        ("bonjour aria", 9),
        ("salut", 9),
        ("hello", 9),
        ("bonsoir", 9),
    ]

    def __init__(self):
        self.tokenizer = ARIATokenizer(vocab_size=500)
        self.model     = None
        self.trained   = False
        self._auto_train()

    def _auto_train(self):
        """Entraîne automatiquement au démarrage."""
        model_path = "data/aria_intent_model.json"
        vocab_path = "data/aria_vocab.json"

        texts  = [t for t, _ in self.TRAINING_DATA]
        labels = [l for _, l in self.TRAINING_DATA]

        self.tokenizer.build_vocab(texts)
        X = self.tokenizer.texts_to_bow(texts)
        y = np.array(labels)

        input_size = X.shape[1]
        self.model = ARIAModel(
            input_size=input_size,
            hidden_sizes=[128, 64],
            output_size=len(self.INTENTS),
            lr=0.005
        )

        if os.path.exists(model_path) and os.path.exists(vocab_path):
            self.tokenizer.load(vocab_path)
            self.model.load(model_path)
        else:
            print("🧠 Entraînement du modèle ARIA...")
            os.makedirs("data", exist_ok=True)
            self.model.train(X, y, epochs=200, batch_size=8)
            self.model.save(model_path)
            self.tokenizer.save(vocab_path)

        self.trained = True

    def classify(self, text: str) -> dict:
        """Classifie une intention depuis un texte."""
        X      = self.tokenizer.texts_to_bow([text])
        idx, conf = self.model.predict(X)
        return {
            "intent":     self.INTENTS[idx],
            "confidence": round(conf, 3),
            "all_scores": {
                intent: round(float(s), 3)
                for intent, s in zip(
                    self.INTENTS,
                    self.model.forward(X, training=False)[0]
                )
            }
        }

    def retrain(self, new_examples: list) -> dict:
        """
        Ré-entraîne avec de nouveaux exemples.
        new_examples : [{"text": "...", "intent": "cloudflare"}, ...]
        """
        added = 0
        for ex in new_examples:
            intent = ex.get("intent", "")
            text   = ex.get("text", "")
            if intent in self.INTENTS and text:
                self.TRAINING_DATA.append((text, self.INTENTS.index(intent)))
                added += 1

        if added > 0:
            self._auto_train()
        return {"retrained": added > 0, "new_examples": added,
                "total_examples": len(self.TRAINING_DATA)}