# core/aria_learner.py
"""
Système d'apprentissage autonome d'ARIA.
Elle apprend de chaque conversation, feedback et incident réel.
"""

import os
import json
import numpy as np
from datetime import datetime
from collections import defaultdict


class ARIALearner:
    """
    ARIA apprend de 3 sources :
    1. Feedback utilisateur (👍 👎)
    2. Patterns de menaces détectées
    3. Nouvelles réglementations / CVE
    """

    def __init__(self):
        self.memory_path    = "data/aria_memory.json"
        self.feedback_path  = "data/aria_feedback.json"
        self.knowledge_path = "data/aria_knowledge.json"
        self.memory         = self._load(self.memory_path, {
            "conversations": [],
            "learned_patterns": {},
            "threat_counters": defaultdict(int),
            "best_responses": {}
        })
        self.feedback  = self._load(self.feedback_path, {"positive": [], "negative": []})
        self.knowledge = self._load(self.knowledge_path, {"cyber_facts": [], "custom_rules": []})

    def _load(self, path: str, default):
        os.makedirs("data", exist_ok=True)
        try:
            with open(path) as f:
                return json.load(f)
        except:
            return default

    def _save(self, path: str, data):
        with open(path, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    # ─── APPRENTISSAGE PAR FEEDBACK ───────────────────────────────
    def record_feedback(self, question: str, response: str,
                        positive: bool, user_id: str = "anonymous"):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "question":  question,
            "response":  response,
            "user":      user_id
        }
        key = "positive" if positive else "negative"
        self.feedback[key].append(entry)
        self._save(self.feedback_path, self.feedback)

        # Si réponse positive → la mémoriser comme référence
        if positive:
            topic = self._extract_topic(question)
            self.memory["best_responses"][topic] = {
                "question": question,
                "response": response,
                "score":    self.memory["best_responses"].get(topic, {}).get("score", 0) + 1
            }
            self._save(self.memory_path, self.memory)
        return {"recorded": True, "type": key}

    # ─── APPRENTISSAGE PAR CONVERSATION ───────────────────────────
    def learn_from_conversation(self, question: str, response: str,
                                 intents: list):
        # Comptabilise les patterns de menaces
        for intent in intents:
            if intent in ("cf_events", "def_alerts", "def_vulns"):
                self.memory["threat_counters"][intent] = \
                    self.memory["threat_counters"].get(intent, 0) + 1

        # Stocke la conversation
        self.memory["conversations"].append({
            "timestamp": datetime.now().isoformat(),
            "question":  question[:200],
            "intents":   intents
        })

        # Garde seulement les 500 dernières
        if len(self.memory["conversations"]) > 500:
            self.memory["conversations"] = self.memory["conversations"][-500:]

        self._save(self.memory_path, self.memory)

    # ─── APPRENTISSAGE DE NOUVELLES CONNAISSANCES ─────────────────
    def teach(self, topic: str, content: str, source: str = "manual") -> dict:
        """
        Enseigne manuellement un nouveau fait à ARIA.
        Ex: teach("CVE-2024-1234", "Vulnérabilité critique dans Apache...")
        """
        fact = {
            "topic":     topic,
            "content":   content,
            "source":    source,
            "timestamp": datetime.now().isoformat(),
            "uses":      0
        }
        # Remplace si déjà connu
        self.knowledge["cyber_facts"] = [
            f for f in self.knowledge["cyber_facts"] if f["topic"] != topic
        ]
        self.knowledge["cyber_facts"].append(fact)
        self._save(self.knowledge_path, self.knowledge)
        return {"learned": True, "topic": topic}

    # ─── APPRENTISSAGE AUTOMATIQUE CVE / MENACES ──────────────────
    def auto_learn_threats(self, threat_data: list) -> dict:
        """
        Apprend automatiquement depuis les données Defender/Cloudflare.
        threat_data : liste d'alertes ou événements
        """
        learned = 0
        for threat in threat_data:
            title    = threat.get("title", threat.get("ruleId", ""))
            severity = threat.get("severity", "unknown")
            if title and len(title) > 5:
                self.teach(
                    topic   = f"THREAT:{title}",
                    content = f"Menace détectée : {title} | Sévérité : {severity} | "
                              f"Détectée le {datetime.now().strftime('%d/%m/%Y')}",
                    source  = "auto_defender"
                )
                learned += 1
        return {"auto_learned": learned}

    # ─── RÉCUPÈRE LA MEILLEURE RÉPONSE ────────────────────────────
    def get_best_response(self, question: str) -> str | None:
        """Cherche si ARIA a déjà eu une bonne réponse sur ce sujet."""
        topic = self._extract_topic(question)
        best  = self.memory["best_responses"].get(topic)
        if best and best.get("score", 0) >= 2:
            return best["response"]

        # Cherche dans la base de connaissances
        q_lower = question.lower()
        for fact in self.knowledge["cyber_facts"]:
            if fact["topic"].lower() in q_lower or \
               any(w in q_lower for w in fact["topic"].lower().split()):
                fact["uses"] += 1
                self._save(self.knowledge_path, self.knowledge)
                return f"📚 **{fact['topic']}**\n\n{fact['content']}"
        return None

    # ─── STATS D'APPRENTISSAGE ────────────────────────────────────
    def get_stats(self) -> dict:
        total_conv   = len(self.memory["conversations"])
        pos_feedback = len(self.feedback["positive"])
        neg_feedback = len(self.feedback["negative"])
        satisfaction = round(
            pos_feedback / (pos_feedback + neg_feedback) * 100, 1
        ) if (pos_feedback + neg_feedback) > 0 else 0

        top_threats = sorted(
            self.memory["threat_counters"].items(),
            key=lambda x: x[1], reverse=True
        )[:5]

        return {
            "conversations_analysées": total_conv,
            "connaissances_acquises":  len(self.knowledge["cyber_facts"]),
            "meilleures_réponses":     len(self.memory["best_responses"]),
            "feedback_positif":        pos_feedback,
            "feedback_négatif":        neg_feedback,
            "taux_satisfaction":       f"{satisfaction}%",
            "menaces_top5":            dict(top_threats),
            "dernière_mise_à_jour":    datetime.now().isoformat()
        }

    def _extract_topic(self, text: str) -> str:
        keywords = ["ransomware", "phishing", "ddos", "xss", "sql", "cve",
                    "rgpd", "nis2", "dora", "cloudflare", "defender", "mfa"]
        text_l = text.lower()
        for kw in keywords:
            if kw in text_l:
                return kw
        words = [w for w in text_l.split() if len(w) > 4]
        return words[0] if words else "general"


# ─── RÉENTRAÎNEMENT AUTOMATIQUE ───────────────────────────────────
class ARIAAutoTrainer:
    """
    Réentraîne le modèle ARIA automatiquement
    quand suffisamment de nouveau feedback est accumulé.
    """
    RETRAIN_THRESHOLD = 10  # Réentraîne après 10 nouveaux feedbacks

    def __init__(self, learner: ARIALearner):
        self.learner       = learner
        self.retrain_count = 0

    def check_and_retrain(self) -> dict:
        pos  = len(self.learner.feedback["positive"])
        neg  = len(self.learner.feedback["negative"])
        total = pos + neg

        if total > 0 and total % self.RETRAIN_THRESHOLD == 0:
            return self._retrain()
        return {"retrained": False, "feedback_count": total,
                "next_retrain": self.RETRAIN_THRESHOLD - (total % self.RETRAIN_THRESHOLD)}

    def _retrain(self) -> dict:
        """Génère de nouveaux exemples d'entraînement depuis le feedback positif."""
        try:
            from core.aria_model import ARIAIntentClassifier
            classifier = ARIAIntentClassifier()

            new_examples = []
            for entry in self.learner.feedback["positive"]:
                topic  = self.learner._extract_topic(entry["question"])
                intent_map = {
                    "ransomware": "cyber_threat", "phishing": "cyber_threat",
                    "cloudflare": "cloudflare",   "defender": "defender",
                    "jira":       "jira",          "rapport":  "rapport",
                    "rgpd":       "rapport",       "nis2":     "rapport",
                    "dora":       "rapport",
                }
                intent = intent_map.get(topic, "conversation")
                new_examples.append({"text": entry["question"], "intent": intent})

            if new_examples:
                result = classifier.retrain(new_examples)
                return {"retrained": True, "new_examples": len(new_examples), **result}
        except Exception as e:
            return {"retrained": False, "error": str(e)}
        return {"retrained": False}