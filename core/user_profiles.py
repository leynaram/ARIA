import json
import os
import numpy as np
from datetime import datetime

PROFILES_FILE = "data/voice_profiles.json"
os.makedirs("data", exist_ok=True)

# Niveaux d'accès et ce qu'ils peuvent voir
ACCESS_LEVELS = {
    "admin": {
        "label": "Administrateur",
        "color": "#ff3366",
        "can_access": ["cloudflare", "defender", "jira", "chat", "vulnerabilities", "alerts"],
        "sensitive_data": True
    },
    "analyst": {
        "label": "Analyste SOC",
        "color": "#00d4ff",
        "can_access": ["cloudflare", "defender", "alerts", "chat"],
        "sensitive_data": True
    },
    "developer": {
        "label": "Développeur",
        "color": "#00ff88",
        "can_access": ["chat", "jira"],
        "sensitive_data": False
    },
    "guest": {
        "label": "Invité",
        "color": "#4a7a9b",
        "can_access": ["chat"],
        "sensitive_data": False
    }
}

# Postes → niveau d'accès automatique
ROLE_TO_ACCESS = {
    "rssi": "admin",
    "responsable sécurité": "admin",
    "soc": "analyst",
    "analyste": "analyst",
    "ingénieur sécurité": "analyst",
    "développeur": "developer",
    "dev": "developer",
    "chef de projet": "developer",
    "stagiaire": "guest",
    "autre": "guest"
}


class UserProfileManager:
    def __init__(self):
        self.profiles = self._load()

    def _load(self):
        if os.path.exists(PROFILES_FILE):
            with open(PROFILES_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                # Reconvertit les embeddings en numpy arrays
                for uid, p in data.items():
                    if p.get("embedding"):
                        p["embedding"] = np.array(p["embedding"])
                return data
        return {}

    def _save(self):
        data = {}
        for uid, p in self.profiles.items():
            data[uid] = {**p}
            if isinstance(p.get("embedding"), np.ndarray):
                data[uid]["embedding"] = p["embedding"].tolist()
        with open(PROFILES_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def enroll(self, user_id: str, first_name: str, role: str,
               reason: str, embedding: np.ndarray):
        """Enregistre un nouveau profil utilisateur."""
        access = "guest"
        for keyword, level in ROLE_TO_ACCESS.items():
            if keyword in role.lower():
                access = level
                break

        self.profiles[user_id] = {
            "user_id": user_id,
            "first_name": first_name,
            "role": role,
            "reason": reason,
            "access_level": access,
            "embedding": embedding,
            "enrolled_at": datetime.now().isoformat(),
            "last_seen": datetime.now().isoformat(),
            "login_count": 1
        }
        self._save()
        return self.profiles[user_id]

    def identify(self, embedding: np.ndarray, threshold: float = 0.82):
        """
        Compare l'embedding vocal aux profils stockés.
        Retourne le profil si trouvé, None sinon.
        """
        if not self.profiles:
            return None, 0.0

        best_match = None
        best_score = 0.0

        for uid, profile in self.profiles.items():
            stored_emb = profile.get("embedding")
            if stored_emb is None:
                continue
            if not isinstance(stored_emb, np.ndarray):
                stored_emb = np.array(stored_emb)

            # Similarité cosinus
            score = float(np.dot(embedding, stored_emb) /
                         (np.linalg.norm(embedding) * np.linalg.norm(stored_emb) + 1e-8))

            if score > best_score:
                best_score = score
                best_match = profile

        if best_score >= threshold:
            # Met à jour last_seen
            best_match["last_seen"] = datetime.now().isoformat()
            best_match["login_count"] = best_match.get("login_count", 0) + 1
            self._save()
            return best_match, best_score

        return None, best_score

    def get_profile(self, user_id: str):
        return self.profiles.get(user_id)

    def list_profiles(self):
        return [
            {k: v for k, v in p.items() if k != "embedding"}
            for p in self.profiles.values()
        ]

    def delete_profile(self, user_id: str):
        if user_id in self.profiles:
            del self.profiles[user_id]
            self._save()
            return True
        return False

    def can_access(self, profile: dict, resource: str) -> bool:
        if not profile:
            return False
        level = profile.get("access_level", "guest")
        allowed = ACCESS_LEVELS.get(level, {}).get("can_access", [])
        return resource in allowed

    def can_see_sensitive(self, profile: dict) -> bool:
        if not profile:
            return False
        level = profile.get("access_level", "guest")
        return ACCESS_LEVELS.get(level, {}).get("sensitive_data", False)