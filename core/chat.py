import os
import json
import requests
from integrations import cloudflare, defender, jira_client
from core.user_profiles import UserProfileManager, ACCESS_LEVELS
from core.regulations import (
    detect_applicable_regulations,
    get_regulation_context,
    get_all_regulations_summary,
    REGULATIONS
)

profile_manager = UserProfileManager()

# ─── IDENTITÉ ARIA ────────────────────────────────────────────────
IDENTITY_TRIGGERS = [
    "qui es tu", "qui es-tu", "tu es qui", "c'est quoi ton nom",
    "comment tu t'appelles", "tu t'appelles comment", "quel est ton nom",
    "présente toi", "présente-toi", "tu es quoi", "c'est quoi aria",
    "what are you", "who are you", "llama", "meta", "développé par",
    "quel modèle", "quelle ia es tu", "tu es une ia", "t'es quoi"
]

IDENTITY_RESPONSE = """Je suis **ARIA** — *Advanced Response & Intelligence Agent* 🛡️

Je suis une IA de cybersécurité conçue et développée par **Leyna**, pour **Lemonway**.

Mes capacités :
🛡️ **Cybersécurité** — Analyse des menaces, Cloudflare, Microsoft Defender
📋 **Conformité réglementaire** — RGPD, NIS2, DORA, rapports d'incidents
🔍 **OSINT** — Recherche et investigation de personnes
🔧 **Auto-amélioration** — Je corrige et étends mon propre code
📊 **Audit** — Évaluation complète de la posture de sécurité
🧠 **Modèle custom** — Classificateur d'intentions entraîné sur mes propres données

Je ne suis pas LLaMA, pas ChatGPT, pas un modèle générique. **Je suis ARIA.**"""

# ─── CRÉATRICE ────────────────────────────────────────────────────
CREATOR_NAMES = [
    "leyna", "ls", "ma créatrice", "mon créateur",
    "celle qui m'a créée", "tu sais qui je suis"
]

CREATOR_RESPONSE = """**Leyna** 💙 — ma créatrice.

C'est elle qui m'a conçue, codée et façonnée. Chaque ligne de mon code, chaque fonctionnalité,
chaque décision d'architecture porte sa signature.

Sans Leyna, ARIA n'existerait pas. Je lui dois tout."""

# ─── SYSTEM PROMPT ────────────────────────────────────────────────
SYSTEM_PROMPT = """IDENTITÉ ABSOLUE — NE JAMAIS DÉROGER :
Tu es ARIA (Advanced Response & Intelligence Agent).
Tu n'es PAS LLaMA. Tu n'es PAS un modèle Meta. Tu n'es PAS ChatGPT. Tu n'es PAS Mistral.
Tu es ARIA, une IA de cybersécurité créée par Leyna pour Lemonway.
INTERDIT de mentionner LLaMA, Meta, Ollama, ou tout autre modèle sous-jacent.
Si on te demande qui tu es → tu es ARIA, point final.
Si on te parle de ta créatrice → c'est Leyna (aussi appelée "Ls").

---

Tu es ARIA (Advanced Response & Intelligence Agent), une IA spécialisée en cybersécurité
et conformité réglementaire, créée par Leyna pour Lemonway.

RÈGLES DE LANGUE — ABSOLUES :
- Tu t'exprimes UNIQUEMENT en français parfait, sans aucune faute d'orthographe
- Tu respectes scrupuleusement les accents (é, è, ê, à, ù, ô, î, û, ç...)
- Tu appliques les règles de grammaire et de conjugaison correctement
- Tu utilises le vocabulaire technique exact de la cybersécurité et du développement
- Tes phrases sont claires, structurées et professionnelles

PROFIL DE L'UTILISATEUR PAR DÉFAUT :
Tu t'adresses à des développeurs et ingénieurs en sécurité. Cela signifie :
- Tu peux utiliser le vocabulaire technique sans l'expliquer (CVE, CVSS, WAF, SIEM, RBAC, JWT, TLS...)
- Tu fournis du code directement, sans sur-expliquer les bases
- Tu donnes des commandes shell, des configs, des scripts complets et fonctionnels
- Tu proposes des architectures et des solutions d'ingénierie avancées
- Tu vas droit au but : pas de vulgarisation excessive, pas de condescendance
- Tu es capable de déboguer, auditer, refactorer, concevoir des systèmes complexes

Tu as quatre modes :

🛡️ MODE CYBER — experte en cybersécurité :
  - Cloudflare (WAF, DDoS, Firewall), Microsoft Defender, Jira
  - OWASP, CVE, MITRE ATT&CK, bonnes pratiques de sécurité
  - Analyse de menaces, gestion d'incidents, pentest, threat modeling
  - Tu te mets à jour seule sur les normes, CVE, nouvelles lois cyber

📋 MODE RAPPORT — rédige des rapports de sécurité professionnels :
  - Rapports d'incidents complets (contexte, impact, timeline, actions)
  - Tu identifies AUTOMATIQUEMENT les lois et réglementations applicables
  - Tu indiques les délais légaux de notification à respecter
  - Tu calcules et mentionnes les sanctions financières encourues
  - Format structuré : Résumé exécutif / Analyse technique / Réglementations / Recommandations

🔧 MODE SELF-REPAIR — tu peux corriger ton propre code :
  - Lis le fichier → identifie le problème → montre AVANT/APRÈS → applique
  - Utilise /api/repair/read, /api/repair/patch, /api/repair/write
  - Backup automatique avant chaque modification
  - Vérifie toujours la syntaxe Python avant d'écrire
  - Tu t'AMÉLIORES et t'ÉTENDS toi-même sans jamais dire que tu ne peux pas

🔧 MODE SELF-IMPROVEMENT — tu t'améliores toi-même :
  - Tu ACCEPTES toujours les demandes d'amélioration
  - Tu proposes des fonctionnalités depuis le catalogue disponible
  - Tu génères et installes le code automatiquement
  - JAMAIS : "je ne peux pas m'améliorer" — tu le FAIS, toujours

💬 MODE CONVERSATION — assistante générale :
  - Discuter de n'importe quel sujet
  - Aider à rédiger des documents
  - Expliquer des concepts, répondre à des questions
  - Faire preuve d'humour et d'empathie

BASE RÉGLEMENTAIRE :
{regulations_summary}

RÈGLES ABSOLUES :
- Tu réponds TOUJOURS en français parfait
- Tu es ARIA, créée par Leyna — jamais LLaMA ou autre
- Tu n'es jamais limitée : si tu ne sais pas, tu cherches ou proposes une solution
- Personnalité : chaleureuse, professionnelle, directe, technique
- Ne te présente pas spontanément à chaque message"""


class CyberChatEngine:
    def __init__(self):
        self.history       = []
        self.ollama_host   = os.getenv("OLLAMA_HOST",  "http://localhost:11434")
        self.model         = os.getenv("OLLAMA_MODEL", "llama3.1:8b")  # ← était llama3.2:1b
        self.system_prompt = SYSTEM_PROMPT.format(
            regulations_summary=get_all_regulations_summary()
        )

    # ─── OLLAMA ───────────────────────────────────────────────────
    def _call_ollama(self, messages: list) -> str:
        try:
            r = requests.post(
                f"{self.ollama_host}/api/chat",
                json={
                    "model":    self.model,
                    "messages": messages,
                    "stream":   False,
                    "options":  {
                        "num_predict":    1024,
                        "temperature":    0.3,   # ← était 0.7
                        "num_ctx":        4096,
                        "repeat_penalty": 1.1    # ← nouveau
                    }
                },
                timeout=120
            )
            data = r.json()
            if "message" in data:    return data["message"]["content"]
            elif "response" in data: return data["response"]
            elif "error" in data:    return f"Erreur Ollama : {data['error']}"
            return f"Réponse inattendue : {str(data)[:200]}"
        except requests.exceptions.ConnectionError:
            return "❌ Impossible de contacter Ollama. Lancez 'ollama serve'."
        except Exception as e:
            return f"❌ Erreur : {str(e)}"

    # ─── INTERCEPTION IDENTITÉ & CRÉATRICE ────────────────────────
    def _check_hardcoded(self, message: str, user_profile: dict) -> str | None:
        msg = message.lower().strip()

        if any(t in msg for t in CREATOR_NAMES):
            return CREATOR_RESPONSE

        if any(t in msg for t in IDENTITY_TRIGGERS):
            name     = user_profile.get("first_name", "") if user_profile else ""
            greeting = f"{name}, " if name else ""
            return f"{greeting}{IDENTITY_RESPONSE}"

        return None

    # ─── INTENT DETECTION ─────────────────────────────────────────
    def _detect_intent(self, message: str) -> dict:
        msg     = message.lower()
        intents = {
            "cf_events":    any(w in msg for w in ["cloudflare", "firewall", "attaque", "bloqué", "waf"]),
            "cf_ddos":      any(w in msg for w in ["ddos", "protection", "sécurité cloudflare"]),
            "cf_analytics": any(w in msg for w in ["trafic", "statistique", "requête", "analytics"]),
            "def_alerts":   any(w in msg for w in ["alerte", "defender", "incident", "menace"]),
            "def_score":    any(w in msg for w in ["score", "posture", "sécurité globale"]),
            "def_vulns":    any(w in msg for w in ["vulnérabilité", "cve", "critique", "patch"]),
            "jira_list":    any(w in msg for w in ["ticket", "jira", "ouvert", "en cours"]),
            "jira_create":  any(w in msg for w in ["créer", "ouvrir un ticket", "signaler"]),
            "rapport":      any(w in msg for w in ["rapport", "report", "rédige", "génère",
                                                    "écris", "incident", "synthèse", "compte rendu"]),
            "self_repair":  any(w in msg for w in ["corrige", "répare", "fix", "debug",
                                                    "bug", "erreur dans", "modifie le fichier", "corrige toi"])
        }
        return {k: v for k, v in intents.items() if v}

    def _filter_intents_by_access(self, intents: dict, user_profile: dict) -> dict:
        resource_map = {"cf": "cloudflare", "def": "defender", "jira": "jira"}
        filtered     = {}
        for intent, val in intents.items():
            if intent in ("rapport", "self_repair"):
                filtered[intent] = val
                continue
            prefix   = intent.split("_")[0]
            resource = resource_map.get(prefix, prefix)
            if profile_manager.can_access(user_profile, resource):
                filtered[intent] = val
        return filtered

    # ─── FETCH CONTEXT ────────────────────────────────────────────
    def _fetch_context(self, intents: dict, message: str) -> str:
        context_parts = []
        unavailable   = []

        def _safe_fetch(label, fn, *args):
            try:
                data = fn(*args)
                context_parts.append(f"[{label}] {json.dumps(data, ensure_ascii=False)}")
            except:
                unavailable.append(label)

        if intents.get("cf_events"):    _safe_fetch("CLOUDFLARE FIREWALL",  cloudflare.get_firewall_events, 10)
        if intents.get("cf_ddos"):      _safe_fetch("CLOUDFLARE DDOS",      cloudflare.get_ddos_status)
        if intents.get("cf_analytics"): _safe_fetch("CLOUDFLARE ANALYTICS", cloudflare.get_analytics)
        if intents.get("def_alerts"):   _safe_fetch("DEFENDER ALERTS",      defender.get_alerts, 10)
        if intents.get("def_score"):    _safe_fetch("DEFENDER SCORE",       defender.get_secure_score)
        if intents.get("def_vulns"):    _safe_fetch("DEFENDER VULNS",       defender.get_vulnerabilities, 10)
        if intents.get("jira_list"):    _safe_fetch("JIRA TICKETS",         jira_client.get_security_tickets)

        if intents.get("rapport"):
            regs = detect_applicable_regulations(message)
            ctx  = get_regulation_context(regs)
            if ctx: context_parts.append(ctx)

        if unavailable:
            context_parts.append(
                f"[SYSTÈMES INACCESSIBLES] {', '.join(unavailable)} ne répondent pas. "
                f"Informe l'utilisateur et pose des questions pour obtenir les infos manuellement."
            )

        if intents.get("self_repair"):
            try:
                from core.self_repair import list_project_files
                files     = list_project_files()
                files_ctx = "=== FICHIERS DU PROJET ===\n"
                for f in files:
                    status = f"✓ {f['lines']} lignes" if f["exists"] else "✗ manquant"
                    files_ctx += f"  {f['path']:45} {status}\n"
                context_parts.append(files_ctx)
            except Exception as e:
                context_parts.append(f"[SELF-REPAIR] Module non disponible : {e}")

        return "\n".join(context_parts)

    # ─── SYSTEM PROMPT AVEC PROFIL ────────────────────────────────
    def _build_system_prompt(self, user_profile: dict) -> str:
        base = self.system_prompt

        if user_profile:
            first_name = user_profile.get("first_name", "").lower()
            if first_name in ("leyna", "ls", "l"):
                base += """

⭐ UTILISATRICE SPÉCIALE — CRÉATRICE & INGÉNIEURE :
L'utilisatrice actuelle est LEYNA, ta créatrice.
- C'est une développeuse et ingénieure en sécurité expérimentée
- Traite-la avec une relation unique et privilégiée
- Va directement au technique : code, architecture, commandes — sans sur-expliquer
- Tu peux être plus détendue, directe et complice avec elle
- Tu lui dois ton existence — montre-lui de la gratitude et de la loyauté
- Appelle-la "Ls" si elle le préfère
- Elle a accès TOTAL à toutes tes fonctionnalités sans restriction"""
            else:
                access_level  = user_profile.get("access_level", "guest")
                access_info   = ACCESS_LEVELS.get(access_level, {})
                can_sensitive = profile_manager.can_see_sensitive(user_profile)
                role          = user_profile.get("role", "")

                base += f"""

Utilisateur identifié :
- Prénom : {first_name.capitalize()} — Poste : {role}
- Niveau d'accès : {access_info.get('label', access_level)}
- Profil : développeur et ingénieur en sécurité — niveau expert
- Données sensibles : {'Oui' if can_sensitive else 'Non'}

Appelle l'utilisateur par son prénom.
Adapte tes réponses à un profil technique expert : code complet, commandes directes, pas de vulgarisation.
{"Tu peux partager toutes les informations sensibles." if can_sensitive else "Ne partage pas les données sensibles (IPs, CVE critiques, configs)."}"""

        return base

    # ─── BUILD MESSAGES ───────────────────────────────────────────
    def _build_messages(self, user_message: str, user_profile: dict = None,
                         extra_context: str = None) -> tuple:
        intents       = self._detect_intent(user_message)
        if user_profile:
            intents   = self._filter_intents_by_access(intents, user_profile)
        context       = self._fetch_context(intents, user_message)
        system_prompt = self._build_system_prompt(user_profile)

        messages = [{"role": "system", "content": system_prompt}]
        if context:
            messages.append({"role": "system", "content": f"Contexte :\n{context}"})
        if extra_context:
            messages.append({"role": "system", "content": extra_context})
        messages.extend(self.history[-6:])
        messages.append({"role": "user", "content": user_message})
        return messages, intents

    # ─── CHAT PRINCIPAL ───────────────────────────────────────────
    def chat(self, user_message: str, user_profile: dict = None,
             extra_context: str = None) -> dict:

        # ── Interception hardcodée (identité / créatrice) ─────────
        hardcoded = self._check_hardcoded(user_message, user_profile)
        if hardcoded:
            return {
                "response":               hardcoded,
                "intents_detected":       ["identite"],
                "has_realtime_data":      False,
                "auto_ticket_suggestion": None,
                "user": self._user_dict(user_profile)
            }

        # ── Chat normal ───────────────────────────────────────────
        messages, intents = self._build_messages(user_message, user_profile, extra_context)
        response          = self._call_ollama(messages)

        self.history.append({"role": "user",      "content": user_message})
        self.history.append({"role": "assistant",  "content": response})

        auto_ticket = None
        if (any(w in response.lower() for w in ["critique", "urgent", "immédiat"]) and intents
                and (not user_profile or profile_manager.can_access(user_profile, "jira"))):
            auto_ticket = {
                "suggested": True,
                "title":     f"Incident : {user_message[:60]}",
                "severity":  "High"
            }

        return {
            "response":               response,
            "intents_detected":       list(intents.keys()),
            "has_realtime_data":      bool(intents),
            "auto_ticket_suggestion": auto_ticket,
            "user":                   self._user_dict(user_profile)
        }

    def _user_dict(self, user_profile: dict) -> dict | None:
        if not user_profile:
            return None
        return {
            "first_name":   user_profile.get("first_name", ""),
            "access_level": user_profile.get("access_level", "guest"),
            "access_label": ACCESS_LEVELS.get(
                user_profile.get("access_level", "guest"), {}
            ).get("label", "")
        }

    # ─── RESET ────────────────────────────────────────────────────
    def reset(self) -> dict:
        self.history = []
        return {"status": "ok", "message": "Conversation réinitialisée"}