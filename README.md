# 🛡️ ARIA — Advanced Response & Intelligence Agent

> Agent IA de cybersécurité autonome, conçu et développé par **Leyna Rahmouni** pour **Lemonway**.

---

## 🚀 Présentation

ARIA est un agent de cybersécurité intelligent qui surveille en temps réel l'infrastructure d'une organisation et assiste les équipes sécurité dans leurs missions quotidiennes.

Elle intègre nativement :
- ☁️ **Cloudflare** — WAF, DDoS, Firewall, Analytics
- 🛡️ **Microsoft Defender** — Alertes, Score de sécurité, Vulnérabilités
- 📋 **Jira** — Gestion et création de tickets d'incidents
- 📡 **Scanner réseau** — Cartographie et analyse de posture WiFi
- 🕵️ **OSINT** — Recherche et investigation de personnes
- 📄 **Audit** — Rapport de sécurité complet avec export PDF
- 📚 **Conformité** — RGPD, NIS2, DORA — détection automatique et calcul des sanctions
- 🧠 **Apprentissage** — ARIA apprend de chaque interaction
- 🔧 **Self-repair** — ARIA peut lire et corriger son propre code

---

## 🧰 Stack technique

| Composant | Technologie |
|---|---|
| Backend | Python 3.11, Flask |
| Frontend | JavaScript vanilla, HTML/CSS |
| LLM | Groq API / Ollama (local) |
| Intégrations | Cloudflare API, Microsoft Graph, Jira REST API |
| PDF | ReportLab |
| Réseau | Socket, Nmap, ARP |

---

## ⚙️ Installation

### Prérequis

- Python 3.10+
- [Ollama](https://ollama.com) installé et en cours d'exécution (**obligatoire si tu n'utilises pas Groq**)
- Accès aux APIs : Cloudflare, Microsoft Defender, Jira

---

### 1. Cloner le repo

```bash
git clone https://github.com/leynaram/ARIA.git
cd ARIA
```

### 2. Installer les dépendances Python

```bash
pip install -r requirements.txt
```

### 3. Configurer les variables d'environnement

Copie le fichier exemple et remplis tes clés :

```bash
cp .env.example .env
```

Contenu du `.env` :

```env
# ── LLM ───────────────────────────────────────
# Option 1 : Groq (recommandé — rapide et gratuit)
GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxxxx
GROQ_MODEL=llama-3.3-70b-versatile

# Option 2 : Ollama (local)
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3.1:8b

# ── Cloudflare ────────────────────────────────
CF_API_TOKEN=ton_token_cloudflare
CF_ZONE_ID=ton_zone_id

# ── Microsoft Defender (Azure AD) ─────────────
AZURE_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AZURE_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AZURE_CLIENT_SECRET=ton_secret_azure

# ── Jira ──────────────────────────────────────
JIRA_URL=https://tonentreprise.atlassian.net
JIRA_EMAIL=ton@email.com
JIRA_API_TOKEN=ton_token_jira
JIRA_PROJECT_KEY=SEC
```

---

### 4. Installer et lancer Ollama (si tu n'utilises pas Groq)

> ⚠️ **Ollama est obligatoire si tu veux faire tourner ARIA en local sans clé API externe.**

```bash
# 1. Télécharger Ollama
# → https://ollama.com/download

# 2. Lancer le serveur Ollama
ollama serve

# 3. Télécharger le modèle (dans un autre terminal)
ollama pull llama3.1:8b

# 4. Vérifier que ça fonctionne
ollama list
```

> Si tu utilises **Groq** (recommandé pour la vitesse), tu n'as pas besoin d'Ollama. Il suffit de remplir `GROQ_API_KEY` dans le `.env`.

---

### 5. Lancer ARIA

```bash
python app.py
```

Puis ouvre ton navigateur sur : [http://localhost:5000](http://localhost:5000)

---

## 🔑 Obtenir les clés API

| Service | Lien |
|---|---|
| Groq (gratuit) | [console.groq.com](https://console.groq.com) |
| Cloudflare | My Profile → API Tokens |
| Azure / Defender | portal.azure.com → App registrations |
| Jira | Account Settings → Security → API tokens |

---

## 📁 Structure du projet

```
ARIA/
├── app.py                  # Serveur Flask principal
├── requirements.txt        # Dépendances Python
├── .env                    # Variables d'environnement (non versionné)
├── .env.example            # Template de configuration
├── core/
│   ├── chat.py             # Moteur de conversation ARIA
│   ├── audit.py            # Module d'audit de sécurité
│   ├── network_scanner.py  # Scanner réseau WiFi
│   ├── osint.py            # Module OSINT
│   ├── pdf_generator.py    # Génération de rapports PDF
│   ├── regulations.py      # Base réglementaire RGPD/NIS2/DORA
│   ├── self_repair.py      # Auto-correction du code
│   ├── self_expand.py      # Auto-extension des fonctionnalités
│   ├── aria_learner.py     # Apprentissage par feedback
│   └── user_profiles.py   # Gestion des profils et accès
├── integrations/
│   ├── cloudflare.py       # Client Cloudflare API
│   ├── defender.py         # Client Microsoft Defender
│   └── jira_client.py      # Client Jira API
└── static/
    ├── index.html          # Interface principale
    ├── login.html          # Page de connexion
    └── js/
        ├── avatar.js       # Animation avatar ARIA
        └── voice.js        # Reconnaissance vocale
```

---

## 👩‍💻 Auteure

**Leyna Rahmouni** — Ingénieure DevSecOps @ Lemonway  
Conception, développement et déploiement complets du projet.

---

## ⚠️ Avertissement

Ce projet est à usage interne. Les clés API et données sensibles ne doivent jamais être committées dans le repo. Utilise toujours le fichier `.env` (ignoré par git).
