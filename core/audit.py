# core/audit.py
"""
Moteur d'audit de sécurité pour ARIA.
Frameworks : ISO 27001, OWASP Top 10, NIST CSF, ANSSI
"""

from datetime import datetime

# ── FRAMEWORKS D'AUDIT ────────────────────────────────────────────
AUDIT_FRAMEWORKS = {
    "complet": "Audit complet (ISO 27001 + OWASP + NIST + ANSSI)",
    "iso27001": "ISO/IEC 27001:2022 — Système de management de la sécurité",
    "owasp": "OWASP Top 10 — Sécurité applicative web",
    "nist": "NIST CSF 2.0 — Cybersecurity Framework",
    "anssi": "Guide ANSSI — Hygiène informatique (42 règles)"
}

# ── DOMAINES ET QUESTIONS D'AUDIT ─────────────────────────────────
AUDIT_DOMAINS = {
    "gouvernance": {
        "label": "🏛️ Gouvernance & Organisation",
        "weight": 10,
        "questions": [
            {
                "id": "gov_1",
                "question": "Disposez-vous d'une politique de sécurité des systèmes d'information (PSSI) formalisée et à jour ?",
                "options": ["Oui, formalisée et validée par la direction", "En cours de rédaction", "Informelle / non documentée", "Non"],
                "scores": [10, 6, 3, 0],
                "recommandation": "Rédigez une PSSI couvrant : périmètre, responsabilités, règles d'usage, gestion des incidents. Faites-la valider par la direction. (Réf: ISO 27001 A.5)"
            },
            {
                "id": "gov_2",
                "question": "Avez-vous un responsable de la sécurité (RSSI ou équivalent) clairement désigné ?",
                "options": ["Oui, RSSI dédié à temps plein", "Oui, RSSI à temps partiel", "Rôle informel partagé", "Non"],
                "scores": [10, 7, 3, 0],
                "recommandation": "Désignez un RSSI avec des responsabilités claires, un budget et un reporting direct à la direction. (Réf: ISO 27001 A.6, NIS2 Art.20)"
            },
            {
                "id": "gov_3",
                "question": "Les employés reçoivent-ils une formation/sensibilisation à la cybersécurité ?",
                "options": ["Formation annuelle obligatoire", "Formation occasionnelle", "Sensibilisation informelle", "Aucune formation"],
                "scores": [10, 6, 3, 0],
                "recommandation": "Mettez en place un programme de sensibilisation annuel obligatoire incluant : phishing, mots de passe, RGPD, gestion des incidents. (Réf: ISO 27001 A.6.3)"
            }
        ]
    },
    "access_control": {
        "label": "🔐 Contrôle d'accès & Identités",
        "weight": 15,
        "questions": [
            {
                "id": "acc_1",
                "question": "Utilisez-vous l'authentification multi-facteurs (MFA) ?",
                "options": ["MFA partout (tous systèmes)", "MFA sur systèmes critiques seulement", "MFA sur VPN uniquement", "Pas de MFA"],
                "scores": [10, 7, 4, 0],
                "recommandation": "Déployez le MFA sur tous les comptes, en priorité : comptes admin, accès distants, emails, cloud. (Réf: OWASP A07, NIST CSF PR.AC, ANSSI Règle 12)"
            },
            {
                "id": "acc_2",
                "question": "Appliquez-vous le principe du moindre privilège pour les accès ?",
                "options": ["Oui, revue régulière des accès", "Partiellement appliqué", "Peu appliqué", "Non"],
                "scores": [10, 6, 2, 0],
                "recommandation": "Auditez et réduisez les droits au strict nécessaire. Supprimez les comptes inactifs. Planifiez des revues d'accès trimestrielles. (Réf: ISO 27001 A.8.2)"
            },
            {
                "id": "acc_3",
                "question": "Avez-vous une politique de gestion des mots de passe (longueur, complexité, rotation) ?",
                "options": ["Politique stricte + gestionnaire de mots de passe", "Politique définie mais non contrôlée", "Quelques règles informelles", "Aucune politique"],
                "scores": [10, 6, 2, 0],
                "recommandation": "Imposez des mots de passe de 12+ caractères. Déployez un gestionnaire (Bitwarden, KeePass). Bannissez les mots de passe réutilisés. (Réf: ANSSI Règle 8)"
            }
        ]
    },
    "reseau": {
        "label": "🌐 Sécurité Réseau & Infrastructure",
        "weight": 15,
        "questions": [
            {
                "id": "net_1",
                "question": "Votre réseau est-il segmenté (DMZ, VLAN, zones de confiance) ?",
                "options": ["Segmentation complète avec DMZ", "Segmentation partielle", "Segmentation basique", "Pas de segmentation"],
                "scores": [10, 6, 3, 0],
                "recommandation": "Segmentez le réseau en zones : DMZ (services exposés), LAN (interne), Admin (SI critique). Bloquez les flux non nécessaires. (Réf: ANSSI Règle 22, NIST CSF PR.AC-5)"
            },
            {
                "id": "net_2",
                "question": "Disposez-vous d'un pare-feu applicatif (WAF) pour vos applications web ?",
                "options": ["WAF managé (Cloudflare, AWS WAF...)", "WAF on-premise configuré", "Firewall réseau uniquement", "Aucun pare-feu applicatif"],
                "scores": [10, 8, 3, 0],
                "recommandation": "Déployez un WAF devant toutes vos applications web publiques. Activez la protection DDoS, les règles OWASP et le rate limiting. (Réf: OWASP Top 10)"
            },
            {
                "id": "net_3",
                "question": "Chiffrez-vous les communications (TLS, VPN, HTTPS) ?",
                "options": ["TLS 1.3 partout + VPN pour accès distants", "HTTPS + VPN", "HTTPS uniquement", "Chiffrement partiel ou absent"],
                "scores": [10, 7, 4, 0],
                "recommandation": "Forcez HTTPS (HSTS) sur tous les services web. Utilisez TLS 1.2+ minimum. Déployez un VPN pour tous les accès distants. (Réf: ISO 27001 A.8.24)"
            }
        ]
    },
    "vulnerabilites": {
        "label": "🔓 Gestion des Vulnérabilités",
        "weight": 15,
        "questions": [
            {
                "id": "vuln_1",
                "question": "Effectuez-vous des scans de vulnérabilités réguliers ?",
                "options": ["Scans automatisés continus", "Scans mensuels", "Scans occasionnels", "Jamais"],
                "scores": [10, 7, 3, 0],
                "recommandation": "Mettez en place des scans automatisés hebdomadaires (Nessus, OpenVAS, Qualys). Corrigez les vulnérabilités critiques sous 24h, high sous 7 jours. (Réf: NIST CSF ID.RA)"
            },
            {
                "id": "vuln_2",
                "question": "Avez-vous un processus de gestion des correctifs (patch management) ?",
                "options": ["Patches critiques < 24h, autres < 30j", "Patches appliqués mensuellement", "Patches irréguliers", "Pas de processus"],
                "scores": [10, 6, 2, 0],
                "recommandation": "Définissez des SLA de patching : Critique < 24h, High < 7j, Medium < 30j. Automatisez avec WSUS, Ansible ou autre outil. (Réf: ANSSI Règle 30)"
            },
            {
                "id": "vuln_3",
                "question": "Réalisez-vous des tests d'intrusion (pentest) ?",
                "options": ["Pentest annuel par tiers certifié", "Pentest interne régulier", "Tests ponctuels", "Jamais"],
                "scores": [10, 6, 3, 0],
                "recommandation": "Réalisez un pentest externe annuel par un prestataire certifié PASSI (ANSSI). Complétez avec du Bug Bounty pour les applications critiques. (Réf: ISO 27001 A.8.8)"
            }
        ]
    },
    "donnees": {
        "label": "💾 Protection des Données",
        "weight": 15,
        "questions": [
            {
                "id": "data_1",
                "question": "Chiffrez-vous les données sensibles au repos (bases de données, fichiers) ?",
                "options": ["Chiffrement complet (AES-256)", "Chiffrement partiel des données critiques", "Chiffrement minimal", "Pas de chiffrement"],
                "scores": [10, 6, 2, 0],
                "recommandation": "Chiffrez toutes les données sensibles avec AES-256. Chiffrez les disques des postes de travail (BitLocker, FileVault). Gérez les clés de chiffrement de façon sécurisée. (Réf: RGPD Art.32, ISO 27001 A.8.24)"
            },
            {
                "id": "data_2",
                "question": "Effectuez-vous des sauvegardes régulières avec test de restauration ?",
                "options": ["Sauvegardes 3-2-1 + tests mensuels", "Sauvegardes quotidiennes sans test", "Sauvegardes hebdomadaires", "Sauvegardes irrégulières"],
                "scores": [10, 6, 3, 0],
                "recommandation": "Appliquez la règle 3-2-1 : 3 copies, 2 supports différents, 1 hors site. Testez la restauration mensuellement. Isolez les sauvegardes du réseau principal (air gap). (Réf: ISO 27001 A.8.13)"
            },
            {
                "id": "data_3",
                "question": "Avez-vous cartographié vos données personnelles (registre des traitements RGPD) ?",
                "options": ["Registre complet et à jour", "Registre partiel", "En cours de création", "Non"],
                "scores": [10, 5, 2, 0],
                "recommandation": "Tenez un registre des traitements à jour (obligatoire RGPD Art.30). Documentez : finalité, base légale, durée de conservation, destinataires. (Réf: RGPD Art.30)"
            }
        ]
    },
    "incidents": {
        "label": "🚨 Gestion des Incidents",
        "weight": 15,
        "questions": [
            {
                "id": "inc_1",
                "question": "Disposez-vous d'un plan de réponse aux incidents (PRI) formalisé ?",
                "options": ["PRI testé et à jour", "PRI rédigé non testé", "Procédures informelles", "Aucun plan"],
                "scores": [10, 6, 2, 0],
                "recommandation": "Rédigez un PRI couvrant : détection, confinement, éradication, récupération, retour d'expérience. Testez-le via des exercices de simulation (TTX). (Réf: NIST CSF RS, ISO 27001 A.5.26)"
            },
            {
                "id": "inc_2",
                "question": "Avez-vous un SOC ou un système de monitoring de sécurité (SIEM) ?",
                "options": ["SOC 24/7 + SIEM", "SIEM avec alertes", "Logs collectés sans analyse", "Aucun monitoring"],
                "scores": [10, 6, 2, 0],
                "recommandation": "Déployez au minimum un SIEM (Splunk, Elastic SIEM, Microsoft Sentinel) avec des règles de détection. Centralisez tous les logs. Définissez des alertes sur les IOCs critiques. (Réf: NIS2 Art.21, ANSSI)"
            },
            {
                "id": "inc_3",
                "question": "Connaissez-vous vos obligations légales de notification en cas d'incident ?",
                "options": ["Procédures documentées par réglementation", "Connaissance partielle", "Connaissance vague", "Non"],
                "scores": [10, 5, 2, 0],
                "recommandation": "Documentez les délais légaux : RGPD (72h CNIL), NIS2 (24h alerte / 72h notif), DORA (4h alerte / 24h rapport). Préparez des modèles de notification. (Réf: RGPD Art.33, NIS2 Art.23)"
            }
        ]
    },
    "cloud_tiers": {
        "label": "☁️ Cloud & Tiers",
        "weight": 10,
        "questions": [
            {
                "id": "cld_1",
                "question": "Gérez-vous les risques liés à vos prestataires et fournisseurs cloud ?",
                "options": ["Due diligence + contrats DPA + audits", "Contrats DPA signés", "Revue minimale", "Aucune gestion"],
                "scores": [10, 6, 2, 0],
                "recommandation": "Cartographiez vos prestataires critiques. Signez des DPA (Data Processing Agreement) avec tous les sous-traitants. Évaluez leur sécurité annuellement. (Réf: RGPD Art.28, DORA Art.28)"
            },
            {
                "id": "cld_2",
                "question": "Avez-vous une stratégie de sortie (exit plan) pour vos fournisseurs cloud critiques ?",
                "options": ["Exit plan documenté et testé", "Exit plan documenté", "Réflexion en cours", "Non"],
                "scores": [10, 6, 2, 0],
                "recommandation": "Documentez un plan de sortie pour chaque fournisseur critique. Évitez le vendor lock-in. Assurez la portabilité des données. (Réf: DORA Art.28)"
            }
        ]
    },
    "physique": {
        "label": "🏢 Sécurité Physique",
        "weight": 5,
        "questions": [
            {
                "id": "phy_1",
                "question": "L'accès physique à vos locaux et salles serveurs est-il contrôlé ?",
                "options": ["Badge + biométrie + vidéosurveillance", "Badge + journalisation", "Badge simple", "Accès non contrôlé"],
                "scores": [10, 7, 3, 0],
                "recommandation": "Sécurisez l'accès aux salles serveurs avec badge nominatif + journalisation. Installez une vidéosurveillance. Appliquez le clean desk policy. (Réf: ISO 27001 A.7)"
            }
        ]
    }
}


class AuditEngine:
    def __init__(self):
        self.sessions = {}  # session_id -> état de l'audit

    def start_audit(self, session_id: str, framework: str = "complet") -> dict:
        """Démarre un nouvel audit."""
        all_questions = []
        for domain_key, domain in AUDIT_DOMAINS.items():
            for q in domain["questions"]:
                all_questions.append({
                    **q,
                    "domain": domain_key,
                    "domain_label": domain["label"],
                    "weight": domain["weight"]
                })

        self.sessions[session_id] = {
            "framework": framework,
            "started_at": datetime.now().isoformat(),
            "questions": all_questions,
            "current_index": 0,
            "answers": {},
            "scores": {},
            "status": "in_progress"
        }
        return self._get_current_question(session_id)

    def answer_question(self, session_id: str, answer_index: int) -> dict:
        """Enregistre une réponse et passe à la suivante."""
        audit = self.sessions.get(session_id)
        if not audit:
            return {"error": "Audit non trouvé"}

        current_q = audit["questions"][audit["current_index"]]
        score = current_q["scores"][answer_index]
        answer_text = current_q["options"][answer_index]

        audit["answers"][current_q["id"]] = {
            "question": current_q["question"],
            "answer": answer_text,
            "score": score,
            "max_score": max(current_q["scores"]),
            "recommandation": current_q["recommandation"] if score < max(current_q["scores"]) else None,
            "domain": current_q["domain"]
        }

        audit["current_index"] += 1

        # Audit terminé ?
        if audit["current_index"] >= len(audit["questions"]):
            audit["status"] = "completed"
            return self._generate_report(session_id)

        return self._get_current_question(session_id)

    def _get_current_question(self, session_id: str) -> dict:
        audit = self.sessions[session_id]
        q     = audit["questions"][audit["current_index"]]
        total = len(audit["questions"])
        idx   = audit["current_index"]
        progress = round((idx / total) * 100)

        return {
            "status": "question",
            "progress": progress,
            "current": idx + 1,
            "total": total,
            "domain": q["domain_label"],
            "question_id": q["id"],
            "question": q["question"],
            "options": q["options"],
            "message": f"**Question {idx+1}/{total}** — {q['domain_label']}\n\n{q['question']}\n\n" +
                       "\n".join([f"{i+1}. {opt}" for i, opt in enumerate(q["options"])]) +
                       "\n\n*Répondez avec le numéro de votre choix (1, 2, 3 ou 4)*"
        }

    def _generate_report(self, session_id: str) -> dict:
        """Génère le rapport d'audit complet avec scoring."""
        audit = self.sessions[session_id]

        # Calcul des scores par domaine
        domain_scores = {}
        for domain_key, domain in AUDIT_DOMAINS.items():
            domain_answers = [v for v in audit["answers"].values() if v["domain"] == domain_key]
            if not domain_answers:
                continue
            total_score = sum(a["score"] for a in domain_answers)
            total_max   = sum(a["max_score"] for a in domain_answers)
            pct         = round((total_score / total_max) * 100) if total_max > 0 else 0
            domain_scores[domain_key] = {
                "label":       AUDIT_DOMAINS[domain_key]["label"],
                "score":       total_score,
                "max":         total_max,
                "percentage":  pct,
                "level":       _get_level(pct),
                "weight":      domain["weight"]
            }

        # Score global pondéré
        total_weighted = sum(
            d["percentage"] * AUDIT_DOMAINS[k]["weight"]
            for k, d in domain_scores.items()
        )
        total_weight = sum(AUDIT_DOMAINS[k]["weight"] for k in domain_scores)
        global_score = round(total_weighted / total_weight) if total_weight > 0 else 0

        # Recommandations prioritaires (score < 50%)
        critical_recs = [
            v for v in audit["answers"].values()
            if v.get("recommandation") and v["score"] < (v["max_score"] * 0.5)
        ]

        audit["report"] = {
            "global_score":   global_score,
            "global_level":   _get_level(global_score),
            "domain_scores":  domain_scores,
            "critical_recs":  critical_recs,
            "completed_at":   datetime.now().isoformat()
        }

        return {
            "status":       "completed",
            "report":       audit["report"],
            "answers":      audit["answers"],
            "message":      _format_report_message(audit["report"], critical_recs)
        }

    def get_status(self, session_id: str) -> dict:
        audit = self.sessions.get(session_id)
        if not audit:
            return {"status": "not_started"}
        if audit["status"] == "completed":
            return {"status": "completed", "report": audit.get("report")}
        return {"status": "in_progress", "current": audit["current_index"] + 1, "total": len(audit["questions"])}


def _get_level(pct: int) -> dict:
    if pct >= 80:
        return {"label": "Excellent", "color": "#00ff88", "emoji": "🟢"}
    elif pct >= 60:
        return {"label": "Satisfaisant", "color": "#00d4ff", "emoji": "🔵"}
    elif pct >= 40:
        return {"label": "Insuffisant", "color": "#ffc800", "emoji": "🟡"}
    else:
        return {"label": "Critique", "color": "#ff3366", "emoji": "🔴"}


def _format_report_message(report: dict, critical_recs: list) -> str:
    level = report["global_level"]
    msg   = f"# 🔍 Rapport d'Audit de Sécurité\n\n"
    msg  += f"## Score Global : **{report['global_score']}/100** {level['emoji']} {level['label']}\n\n"
    msg  += "---\n\n## 📊 Résultats par domaine\n\n"

    for key, d in report["domain_scores"].items():
        bar   = "█" * (d["percentage"] // 10) + "░" * (10 - d["percentage"] // 10)
        emoji = d["level"]["emoji"]
        msg  += f"{emoji} **{d['label']}** — {d['percentage']}%\n`{bar}` {d['score']}/{d['max']} pts\n\n"

    if critical_recs:
        msg += "---\n\n## 🚨 Priorités immédiates\n\n"
        for i, rec in enumerate(critical_recs[:5], 1):
            msg += f"**{i}. {rec['question'][:60]}...**\n"
            msg += f"   → {rec['recommandation'][:150]}...\n\n"

    msg += "---\n\n*Tapez **'exporter rapport'** pour obtenir le rapport complet en texte.*"
    return msg
# ─── SECURITY AUDIT ENGINE (audit automatique via APIs) ───────────
from integrations import cloudflare, defender, jira_client

class SecurityAuditEngine:
    def __init__(self):
        self.raw_data = {}

    def run(self) -> dict:
        self._collect_data()

        results = {
            "global_score":  0,
            "global_status": "critical",
            "domains":       {},
            "recommendations": [],
            "regulations":   ["RGPD", "NIS2", "DORA"],
            "raw_data":      self.raw_data
        }

        scores = []

        # ── Cloudflare ────────────────────────────────────────────
        cf_checks = []
        if "cf_error" not in self.raw_data:
            waf      = self.raw_data.get("cf_waf", {})
            ddos     = self.raw_data.get("cf_ddos", {})
            analytics= self.raw_data.get("cf_analytics", {})
            threats  = analytics.get("threats", 0)

            cf_checks = [
                {"label": "WAF activé",           "status": "pass" if waf.get("enabled") else "fail",
                 "detail": "WAF actif" if waf.get("enabled") else "WAF désactivé",
                 "remediation": "Activer le WAF dans Cloudflare > Security > WAF"},
                {"label": "Protection DDoS",       "status": "pass" if ddos.get("enabled") else "fail",
                 "detail": "DDoS actif" if ddos.get("enabled") else "DDoS inactif",
                 "remediation": "Activer la protection DDoS dans Cloudflare"},
                {"label": "Menaces < 100/24h",     "status": "pass" if threats < 100 else ("warning" if threats < 500 else "fail"),
                 "detail": f"{threats} menaces/24h",
                 "remediation": "Renforcer les règles WAF" if threats >= 100 else ""},
            ]
            cf_score = round(sum(10 if c["status"]=="pass" else (5 if c["status"]=="warning" else 0) for c in cf_checks) / len(cf_checks) * 10)
            scores.append(cf_score)
        else:
            cf_score = 0
            cf_checks = [{"label": "Cloudflare inaccessible", "status": "unknown",
                          "detail": str(self.raw_data.get("cf_error","")), "remediation": "Vérifier la connexion Cloudflare"}]

        results["domains"]["cloudflare"] = {
            "label":  "☁️ Protection périmétrique (Cloudflare)",
            "checks": cf_checks,
            "score":  cf_score,
            "status": _score_to_status(cf_score)
        }

        # ── Defender ─────────────────────────────────────────────
        def_checks = []
        if "def_error" not in self.raw_data:
            score_data = self.raw_data.get("def_score", {})
            alerts     = self.raw_data.get("def_alerts", {}).get("alerts", [])
            vulns      = self.raw_data.get("def_vulns", {}).get("vulnerabilities", [])
            sec_score  = score_data.get("percentage", 0)
            crit_alerts= [a for a in alerts if a.get("severity","").lower() in ["high","critical"] and a.get("status","").lower() != "resolved"]
            crit_vulns = [v for v in vulns if v.get("severity","").lower() == "critical"]

            def_checks = [
                {"label": "Score sécurité > 70%",       "status": "pass" if sec_score>=70 else ("warning" if sec_score>=50 else "fail"),
                 "detail": f"Score : {sec_score}%", "remediation": "Appliquer les recommandations Defender"},
                {"label": "Alertes critiques résolues",  "status": "pass" if not crit_alerts else "fail",
                 "detail": f"{len(crit_alerts)} alerte(s) critique(s) non résolue(s)",
                 "remediation": f"Traiter : {', '.join([a.get('title','?')[:30] for a in crit_alerts[:2]])}" if crit_alerts else ""},
                {"label": "Vulnérabilités patchées",     "status": "pass" if not crit_vulns else ("warning" if len(crit_vulns)<=3 else "fail"),
                 "detail": f"{len(crit_vulns)} CVE critique(s)",
                 "remediation": "Plan de patching urgent" if crit_vulns else ""},
            ]
            def_score = round(sum(10 if c["status"]=="pass" else (5 if c["status"]=="warning" else 0) for c in def_checks) / len(def_checks) * 10)
            scores.append(def_score)
        else:
            def_score  = 0
            def_checks = [{"label": "Defender inaccessible", "status": "unknown",
                           "detail": str(self.raw_data.get("def_error","")), "remediation": "Vérifier la connexion Defender"}]

        results["domains"]["defender"] = {
            "label":  "🛡️ Sécurité endpoints (Defender)",
            "checks": def_checks,
            "score":  def_score,
            "status": _score_to_status(def_score)
        }

        # ── Jira ─────────────────────────────────────────────────
        jira_checks = []
        if "jira_error" not in self.raw_data:
            tickets      = self.raw_data.get("jira_tickets", {}).get("tickets", [])
            crit_open    = [t for t in tickets if t.get("priority","").lower() in ["highest","high"]
                            and t.get("status","").lower() in ["open","to do","in progress"]]
            jira_checks  = [
                {"label": "Incidents tracés dans Jira",      "status": "pass" if tickets else "warning",
                 "detail": f"{len(tickets)} ticket(s)", "remediation": "Mettre en place un process de ticketing"},
                {"label": "Pas de tickets critiques en retard","status": "pass" if not crit_open else "warning",
                 "detail": f"{len(crit_open)} ticket(s) critique(s) en cours",
                 "remediation": "Accélérer le traitement des tickets haute priorité" if crit_open else ""},
            ]
            jira_score = round(sum(10 if c["status"]=="pass" else (5 if c["status"]=="warning" else 0) for c in jira_checks) / len(jira_checks) * 10)
            scores.append(jira_score)
        else:
            jira_score  = 0
            jira_checks = [{"label": "Jira inaccessible", "status": "unknown",
                            "detail": str(self.raw_data.get("jira_error","")), "remediation": "Vérifier la connexion Jira"}]

        results["domains"]["gouvernance"] = {
            "label":  "📋 Gouvernance & Tickets (Jira)",
            "checks": jira_checks,
            "score":  jira_score,
            "status": _score_to_status(jira_score)
        }

        # ── Score global ──────────────────────────────────────────
        results["global_score"]  = round(sum(scores) / len(scores)) if scores else 0
        results["global_status"] = _score_to_status(results["global_score"])

        # ── Recommandations ───────────────────────────────────────
        priority = 1
        for domain in results["domains"].values():
            for check in domain["checks"]:
                if check["status"] in ["fail","warning"] and check.get("remediation"):
                    results["recommendations"].append({
                        "priority": priority,
                        "domain":   domain["label"],
                        "issue":    check["label"],
                        "action":   check["remediation"],
                        "severity": "Critique" if check["status"] == "fail" else "Important",
                        "status":   check["status"]
                    })
                    priority += 1

        return results

    def _collect_data(self):
        try:
            self.raw_data["cf_analytics"] = cloudflare.get_analytics()
            self.raw_data["cf_ddos"]      = cloudflare.get_ddos_status()
            self.raw_data["cf_waf"]       = cloudflare.get_waf_rules()
        except Exception as e:
            self.raw_data["cf_error"] = str(e)

        try:
            self.raw_data["def_score"]  = defender.get_secure_score()
            self.raw_data["def_alerts"] = defender.get_alerts(50)
            self.raw_data["def_vulns"]  = defender.get_vulnerabilities(50)
        except Exception as e:
            self.raw_data["def_error"] = str(e)

        try:
            self.raw_data["jira_tickets"] = jira_client.get_security_tickets(limit=50)
        except Exception as e:
            self.raw_data["jira_error"] = str(e)


def _score_to_status(score: float) -> str:
    if score >= 80: return "good"
    if score >= 50: return "warning"
    return "critical"