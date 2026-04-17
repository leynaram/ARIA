# core/regulations.py
"""
Base de connaissances réglementaire pour ARIA.
Contient les lois, articles et sanctions applicables aux incidents de sécurité.
"""

REGULATIONS = {
    "RGPD": {
        "nom_complet": "Règlement Général sur la Protection des Données (UE) 2016/679",
        "domaine": "Protection des données personnelles",
        "autorité": "CNIL (France) / EDPB (Europe)",
        "articles": {
            "Art. 5": "Principes relatifs au traitement des données personnelles (licéité, loyauté, transparence)",
            "Art. 25": "Protection des données dès la conception et par défaut (Privacy by Design)",
            "Art. 32": "Sécurité du traitement — mesures techniques et organisationnelles appropriées",
            "Art. 33": "Notification d'une violation à l'autorité de contrôle sous 72h",
            "Art. 34": "Communication d'une violation aux personnes concernées",
            "Art. 35": "Analyse d'impact relative à la protection des données (AIPD/DPIA)",
            "Art. 83(4)": "Violations des obligations — sanctions niveau 1",
            "Art. 83(5)": "Violations des principes de base — sanctions niveau 2",
        },
        "sanctions": {
            "niveau_1": {
                "description": "Violations des obligations (Art. 8, 11, 25-39, 42, 43)",
                "montant_max": "10 000 000 €",
                "pourcentage_ca": "2% du CA annuel mondial",
                "règle": "Le montant le plus élevé s'applique"
            },
            "niveau_2": {
                "description": "Violations des principes de base, droits des personnes, transferts (Art. 5, 6, 7, 9, 12-22, 44-49)",
                "montant_max": "20 000 000 €",
                "pourcentage_ca": "4% du CA annuel mondial",
                "règle": "Le montant le plus élevé s'applique"
            }
        },
        "délai_notification": "72 heures après prise de connaissance",
        "mots_clés": ["donnée personnelle", "fuite", "breach", "rgpd", "gdpr", "vie privée", "utilisateur", "client", "email", "identité"]
    },

    "NIS2": {
        "nom_complet": "Directive (UE) 2022/2555 — Network and Information Security 2",
        "domaine": "Cybersécurité des entités essentielles et importantes",
        "autorité": "ANSSI (France)",
        "transposition_france": "Transposée en droit français — loi en cours",
        "articles": {
            "Art. 21": "Mesures de gestion des risques cybersécurité",
            "Art. 23": "Obligations de signalement des incidents",
            "Art. 32": "Sanctions administratives pour entités essentielles",
            "Art. 33": "Sanctions administratives pour entités importantes",
            "Art. 20": "Gouvernance — responsabilité des organes de direction",
        },
        "sanctions": {
            "entités_essentielles": {
                "montant_max": "10 000 000 €",
                "pourcentage_ca": "2% du CA annuel mondial"
            },
            "entités_importantes": {
                "montant_max": "7 000 000 €",
                "pourcentage_ca": "1.4% du CA annuel mondial"
            }
        },
        "délai_notification": "24h (alerte précoce) — 72h (notification) — 1 mois (rapport final)",
        "mots_clés": ["infrastructure", "réseau", "système d'information", "nis2", "anssi", "entité essentielle", "cyberattaque", "ransomware"]
    },

    "DORA": {
        "nom_complet": "Digital Operational Resilience Act (UE) 2022/2554",
        "domaine": "Résilience opérationnelle numérique — secteur financier",
        "autorité": "ACPR / AMF (France) — BCE (Europe)",
        "applicable_depuis": "17 janvier 2025",
        "articles": {
            "Art. 9":  "Protection et prévention — sécurité des SI",
            "Art. 10": "Détection des anomalies",
            "Art. 17": "Processus de gestion des incidents liés aux TIC",
            "Art. 19": "Signalement des incidents majeurs liés aux TIC",
            "Art. 26": "Tests de résilience opérationnelle numérique",
            "Art. 28": "Gestion des risques liés aux prestataires TIC tiers",
        },
        "sanctions": {
            "général": {
                "montant_max": "1% du chiffre d'affaires journalier mondial moyen",
                "durée_max": "Appliqué pendant 6 mois maximum",
                "astreinte_journalière": "1% du CA journalier mondial moyen"
            },
            "personnes_physiques": {
                "montant_max": "1 000 000 €"
            }
        },
        "délai_notification": "4 heures (alerte initiale) — 24h (rapport intermédiaire) — 1 mois (rapport final)",
        "mots_clés": ["financier", "banque", "fintech", "paiement", "dora", "tiers", "fournisseur", "prestataire", "résilience", "lemonway"]
    },

    "LPM": {
        "nom_complet": "Loi de Programmation Militaire 2024-2030 (France)",
        "domaine": "Cybersécurité des opérateurs d'importance vitale (OIV)",
        "autorité": "ANSSI",
        "articles": {
            "Art. L1332-6-1": "Obligations de sécurité des OIV",
            "Art. L1332-6-2": "Signalement des incidents aux autorités",
            "Art. L1332-6-3": "Contrôles et audits ANSSI",
        },
        "sanctions": {
            "général": {
                "montant_max": "150 000 €",
                "récidive": "300 000 €"
            }
        },
        "délai_notification": "Immédiat — sans délai",
        "mots_clés": ["oiv", "infrastructure critique", "état", "défense", "énergie", "transport"]
    },

    "PCI-DSS": {
        "nom_complet": "Payment Card Industry Data Security Standard v4.0",
        "domaine": "Sécurité des données de paiement par carte",
        "autorité": "PCI Security Standards Council",
        "articles": {
            "Req. 6":  "Développement et maintenance de systèmes sécurisés",
            "Req. 8":  "Identification et authentification des accès",
            "Req. 10": "Journalisation et surveillance des accès",
            "Req. 12": "Politique de sécurité de l'information",
        },
        "sanctions": {
            "général": {
                "amendes_mensuelles": "5 000 $ à 100 000 $ par mois",
                "coût_forensique": "Variable selon investigation",
                "perte_accréditation": "Possible révocation de l'accréditation carte"
            }
        },
        "mots_clés": ["carte", "paiement", "cb", "visa", "mastercard", "pan", "cvv", "pci", "transaction"]
    },

    "eIDAS": {
        "nom_complet": "Règlement (UE) 910/2014 — Electronic Identification and Trust Services",
        "domaine": "Identité numérique et services de confiance",
        "autorité": "ANSSI / ENISA",
        "sanctions": {
            "général": {
                "description": "Sanctions définies par chaque État membre"
            }
        },
        "mots_clés": ["identité numérique", "signature électronique", "eidas", "authentification", "certificat"]
    }
}


def detect_applicable_regulations(incident_description: str) -> list:
    """Détecte automatiquement les réglementations applicables à un incident."""
    desc = incident_description.lower()
    applicable = []

    for reg_name, reg_data in REGULATIONS.items():
        mots_clés = reg_data.get("mots_clés", [])
        if any(mot in desc for mot in mots_clés):
            applicable.append(reg_name)

    # Si aucune réglementation détectée, RGPD et NIS2 par défaut
    if not applicable:
        applicable = ["RGPD", "NIS2"]

    return applicable


def get_regulation_context(regulations: list) -> str:
    """Retourne le contexte réglementaire formaté pour le prompt ARIA."""
    if not regulations:
        return ""

    context = "=== RÉGLEMENTATIONS APPLICABLES ===\n\n"
    for reg_name in regulations:
        reg = REGULATIONS.get(reg_name)
        if not reg:
            continue
        context += f"📋 {reg_name} — {reg['nom_complet']}\n"
        context += f"   Autorité : {reg.get('autorité', 'N/A')}\n"
        context += f"   Délai notification : {reg.get('délai_notification', 'N/A')}\n"
        context += f"   Sanctions :\n"
        for niveau, details in reg.get("sanctions", {}).items():
            montant = details.get("montant_max", details.get("amendes_mensuelles", "Variable"))
            ca = details.get("pourcentage_ca", "")
            context += f"     - {niveau.replace('_', ' ').title()} : jusqu'à {montant}"
            if ca:
                context += f" ou {ca}"
            context += "\n"
        context += "\n"

    return context


def get_all_regulations_summary() -> str:
    """Résumé de toutes les réglementations pour le prompt système."""
    summary = ""
    for reg_name, reg in REGULATIONS.items():
        sanctions = reg.get("sanctions", {})
        max_sanction = ""
        for niveau, details in sanctions.items():
            montant = details.get("montant_max", "")
            if montant:
                max_sanction = montant
                break
        summary += f"- {reg_name}: {reg['nom_complet']} | Sanction max: {max_sanction}\n"
    return summary