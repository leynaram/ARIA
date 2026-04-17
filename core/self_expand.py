import os
import json
import requests
from core.self_repair import write_file

OLLAMA_HOST  = os.getenv("OLLAMA_HOST",  "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:1b")


def _tpl_port_scanner() -> str:
    return '''import socket, concurrent.futures
from datetime import datetime

COMMON_PORTS = {21:"FTP",22:"SSH",80:"HTTP",443:"HTTPS",3306:"MySQL",3389:"RDP"}

class PortScanner:
    def scan(self, target: str, ports: list = None, timeout: float = 1.0) -> dict:
        if not ports:
            ports = list(COMMON_PORTS.keys())
        open_ports = []
        def check(port):
            try:
                s = socket.socket()
                s.settimeout(timeout)
                ok = s.connect_ex((target, port)) == 0
                s.close()
                return port, ok
            except:
                return port, False
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
            for port, is_open in ex.map(check, ports):
                if is_open:
                    open_ports.append({"port": port, "service": COMMON_PORTS.get(port, "Unknown")})
        return {"target": target, "open_ports": open_ports, "open_count": len(open_ports)}
'''


def _tpl_password_analyzer() -> str:
    return '''import re, hashlib, requests

class PasswordAnalyzer:
    def analyze(self, password: str) -> dict:
        score, tips = 0, []
        if len(password) >= 8:  score += 1
        else: tips.append("Minimum 8 caractères")
        if len(password) >= 12: score += 1
        if re.search(r"[A-Z]", password): score += 1
        else: tips.append("Ajoutez des majuscules")
        if re.search(r"[0-9]", password): score += 1
        else: tips.append("Ajoutez des chiffres")
        if re.search(r"[^a-zA-Z0-9]", password): score += 2
        else: tips.append("Ajoutez des caractères spéciaux")
        levels = {0:"Très faible",1:"Faible",2:"Faible",3:"Moyen",
                  4:"Moyen",5:"Fort",6:"Fort",7:"Très fort"}
        return {"score": score, "max": 7, "level": levels.get(score,"?"), "tips": tips}
'''


def _tpl_ssl_checker() -> str:
    return '''import ssl, socket
from datetime import datetime

class SSLChecker:
    def check(self, domain: str) -> dict:
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(10)
                s.connect((domain, 443))
                cert = s.getpeercert()
            expiry   = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.utcnow()).days
            return {"domain": domain, "valid": True, "days_left": days_left,
                    "expires": cert["notAfter"],
                    "status": "ok" if days_left > 30 else "warning"}
        except Exception as e:
            return {"domain": domain, "valid": False, "error": str(e)}
'''


FEATURE_CATALOG = {
    "scanner_ports": {
        "name":        "Scanner de ports",
        "description": "Scanne les ports ouverts d'une IP/domaine",
        "category":    "Cyber",
        "complexity":  "Moyenne",
        "files":       ["core/port_scanner.py"],
        "route":       "/api/scan/ports",
        "template":    _tpl_port_scanner,
    },
    "password_analyzer": {
        "name":        "Analyseur de mots de passe",
        "description": "Évalue la solidité et détecte les fuites",
        "category":    "Cyber",
        "complexity":  "Faible",
        "files":       ["core/password_analyzer.py"],
        "route":       "/api/security/password",
        "template":    _tpl_password_analyzer,
    },
    "ssl_checker": {
        "name":        "Vérificateur SSL/TLS",
        "description": "Analyse les certificats SSL d'un domaine",
        "category":    "Cyber",
        "complexity":  "Faible",
        "files":       ["core/ssl_checker.py"],
        "route":       "/api/scan/ssl",
        "template":    _tpl_ssl_checker,
    },
    "ip_reputation": {
        "name":        "Réputation IP",
        "description": "Vérifie la réputation d'une IP",
        "category":    "Cyber",
        "complexity":  "Faible",
        "files":       ["core/ip_reputation.py"],
        "route":       "/api/threat/ip",
        "template":    None,
    },
    "log_analyzer": {
        "name":        "Analyseur de logs",
        "description": "Détecte des anomalies dans des logs",
        "category":    "Analyse",
        "complexity":  "Élevée",
        "files":       ["core/log_analyzer.py"],
        "route":       "/api/analyze/logs",
        "template":    None,
    },
}


class SelfExpandEngine:
    def __init__(self):
        self.installed_features = self._load_installed()

    def _load_installed(self) -> list:
        try:
            with open("data/installed_features.json") as f:
                return json.load(f)
        except:
            return []

    def _save_installed(self):
        os.makedirs("data", exist_ok=True)
        with open("data/installed_features.json", "w") as f:
            json.dump(self.installed_features, f, indent=2)

    def list_available(self) -> list:
        return [{
            "id":          key,
            "name":        feat["name"],
            "description": feat["description"],
            "category":    feat["category"],
            "complexity":  feat["complexity"],
            "installed":   key in self.installed_features
        } for key, feat in FEATURE_CATALOG.items()]

    def install_feature(self, feature_id: str) -> dict:
        if feature_id not in FEATURE_CATALOG:
            return {"error": f"Fonctionnalité '{feature_id}' inconnue"}
        if feature_id in self.installed_features:
            return {"status": "already_installed", "message": "Déjà installée"}

        feat = FEATURE_CATALOG[feature_id]
        code = feat["template"]() if feat.get("template") else self._generate_code_llm(feat)

        if not code:
            return {"error": "Génération de code échouée"}

        target_file = feat["files"][0]
        result = write_file(target_file, code, check=False)
        if "error" in result:
            return result

        self.installed_features.append(feature_id)
        self._save_installed()

        return {
            "status":           "installed",
            "feature":          feat["name"],
            "file":             target_file,
            "route":            feat["route"],
            "message":          f"✅ {feat['name']} installée avec succès !",
            "restart_required": True
        }

    def _generate_code_llm(self, feat: dict) -> str:
        prompt = f"Génère du code Python pour : {feat['name']}. {feat['description']}. Renvoie UNIQUEMENT le code."
        try:
            r = requests.post(
                f"{OLLAMA_HOST}/api/generate",
                json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False,
                      "options": {"num_predict": 500, "temperature": 0.2}},
                timeout=120
            )
            resp = r.json().get("response", "")
            if "```python" in resp:
                return resp.split("```python")[1].split("```")[0].strip()
            return resp.strip() if len(resp) > 50 else None
        except Exception as e:
            print(f"LLM error: {e}")
            return None

    def propose_features(self, user_request: str) -> list:
        kws = {
            "scanner_ports":     ["port", "scan", "réseau", "ouvert"],
            "password_analyzer": ["mot de passe", "password", "solidité"],
            "ssl_checker":       ["ssl", "tls", "certificat", "https"],
            "ip_reputation":     ["ip", "réputation", "blacklist"],
            "log_analyzer":      ["log", "journal", "anomalie"],
        }
        req = user_request.lower()
        suggestions = [
            {"id": fid, "name": FEATURE_CATALOG[fid]["name"],
             "description": FEATURE_CATALOG[fid]["description"],
             "installed": fid in self.installed_features}
            for fid, words in kws.items()
            if any(w in req for w in words)
        ]
        if not suggestions:
            suggestions = [
                {"id": k, "name": v["name"], "description": v["description"],
                 "installed": k in self.installed_features}
                for k, v in FEATURE_CATALOG.items()
                if k not in self.installed_features
            ][:5]
        return suggestions