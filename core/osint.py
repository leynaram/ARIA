# core/osint.py
"""
Module OSINT pour ARIA.
Recherche de personnes via sources publiques.
"""

import os
import requests
import json
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─── CONFIG ───────────────────────────────────────────────────────
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

SOCIAL_PLATFORMS = [
    "twitter.com", "linkedin.com", "instagram.com", "facebook.com",
    "github.com", "reddit.com", "tiktok.com", "youtube.com",
    "twitch.tv", "medium.com", "pinterest.com", "snapchat.com"
]


class OSINTEngine:

    def search_person(self, query: str) -> dict:
        """
        Recherche complète d'une personne.
        query : nom, email, username, téléphone, entreprise...
        """
        query_type = self._detect_query_type(query)
        results    = {
            "query":      query,
            "query_type": query_type,
            "timestamp":  datetime.now().isoformat(),
            "sources":    {}
        }

        # Lance toutes les recherches en parallèle
        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = {
                executor.submit(self._search_google_dorks, query, query_type): "google_dorks",
                executor.submit(self._check_social_networks, query, query_type): "social_networks",
                executor.submit(self._search_hibp, query): "data_breaches",
                executor.submit(self._search_username, query): "username_check",
                executor.submit(self._search_email_info, query): "email_info",
                executor.submit(self._search_phone, query): "phone_info",
            }
            for future in as_completed(futures):
                key = futures[future]
                try:
                    results["sources"][key] = future.result()
                except Exception as e:
                    results["sources"][key] = {"error": str(e)}

        results["summary"] = self._build_summary(results)
        return results

    # ─── DÉTECTION DU TYPE ────────────────────────────────────────
    def _detect_query_type(self, query: str) -> str:
        if re.match(r'^[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}$', query):
            return "email"
        if re.match(r'^\+?[\d\s\-().]{7,15}$', query):
            return "phone"
        if re.match(r'^@?[\w.]{3,30}$', query) and " " not in query:
            return "username"
        return "name"

    # ─── GOOGLE DORKS ─────────────────────────────────────────────
    def _search_google_dorks(self, query: str, query_type: str) -> dict:
        """Génère les Google Dorks optimisés selon le type."""
        dorks = []

        if query_type == "email":
            dorks = [
                f'"{query}"',
                f'"{query}" site:linkedin.com',
                f'"{query}" site:github.com',
                f'"{query}" filetype:pdf',
                f'"{query}" "curriculum vitae" OR "CV" OR "resume"',
            ]
        elif query_type == "username":
            u = query.lstrip("@")
            dorks = [
                f'"{u}" site:twitter.com OR site:instagram.com OR site:reddit.com',
                f'"{u}" site:github.com',
                f'"{u}" site:linkedin.com',
                f'"@{u}" social media',
            ]
        elif query_type == "phone":
            dorks = [
                f'"{query}"',
                f'"{query}" site:pagesjaunes.fr OR site:annuaire.com',
                f'"{query}" "contact" OR "coordonnées"',
            ]
        else:  # name
            dorks = [
                f'"{query}" site:linkedin.com/in',
                f'"{query}" site:twitter.com',
                f'"{query}" site:github.com',
                f'"{query}" "curriculum vitae" OR "CV" OR "portfolio"',
                f'"{query}" site:malt.fr OR site:freelance.com',
                f'"{query}" -site:facebook.com',
            ]

        return {
            "dorks":       dorks,
            "search_urls": [f"https://www.google.com/search?q={d.replace(' ', '+')}" for d in dorks],
            "count":       len(dorks)
        }

    # ─── RÉSEAUX SOCIAUX ──────────────────────────────────────────
    def _check_social_networks(self, query: str, query_type: str) -> dict:
        """Vérifie la présence sur les réseaux sociaux."""
        found    = []
        not_found= []
        username = query.lstrip("@").split("@")[0].split(" ")[0].lower()

        def check_url(platform, url):
            try:
                r = requests.get(url, headers=HEADERS, timeout=5, allow_redirects=True)
                return r.status_code == 200
            except:
                return None  # inconnu

        platforms_urls = {
            "GitHub":    f"https://github.com/{username}",
            "Twitter/X": f"https://twitter.com/{username}",
            "Instagram": f"https://www.instagram.com/{username}/",
            "Reddit":    f"https://www.reddit.com/user/{username}",
            "TikTok":    f"https://www.tiktok.com/@{username}",
            "Pinterest": f"https://www.pinterest.com/{username}/",
            "Medium":    f"https://medium.com/@{username}",
            "Twitch":    f"https://www.twitch.tv/{username}",
            "Dev.to":    f"https://dev.to/{username}",
            "Keybase":   f"https://keybase.io/{username}",
        }

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {executor.submit(check_url, p, u): (p, u) for p, u in platforms_urls.items()}
            for future in as_completed(futures):
                platform, url = futures[future]
                result = future.result()
                entry  = {"platform": platform, "url": url}
                if result is True:
                    found.append(entry)
                elif result is False:
                    not_found.append({"platform": platform})

        return {
            "username_checked": username,
            "found":            found,
            "not_found_count":  len(not_found),
            "total_checked":    len(platforms_urls)
        }

    # ─── HAVE I BEEN PWNED ────────────────────────────────────────
    def _search_hibp(self, query: str) -> dict:
        """Vérifie si un email est dans des fuites de données."""
        if "@" not in query:
            return {"skipped": "Pas un email"}

        hibp_key = os.getenv("HIBP_API_KEY", "")
        if not hibp_key:
            return {
                "note":       "Clé API HaveIBeenPwned non configurée",
                "check_url":  f"https://haveibeenpwned.com/account/{query}",
                "manual":     True
            }

        try:
            r = requests.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{query}",
                headers={**HEADERS, "hibp-api-key": hibp_key},
                timeout=10
            )
            if r.status_code == 200:
                breaches = r.json()
                return {
                    "breached": True,
                    "count":    len(breaches),
                    "breaches": [{"name": b["Name"], "date": b.get("BreachDate","?"),
                                  "data": b.get("DataClasses",[])} for b in breaches[:10]]
                }
            elif r.status_code == 404:
                return {"breached": False, "message": "Aucune fuite détectée ✓"}
            else:
                return {"error": f"HIBP status {r.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    # ─── USERNAME CHECK ───────────────────────────────────────────
    def _search_username(self, query: str) -> dict:
        """Sherlock-like : vérifie le username sur 20+ sites."""
        if " " in query or "@" in query:
            return {"skipped": "Pas un username"}

        username = query.lstrip("@").lower()
        sites    = {
            "GitHub":       f"https://github.com/{username}",
            "GitLab":       f"https://gitlab.com/{username}",
            "HackerNews":   f"https://news.ycombinator.com/user?id={username}",
            "ProductHunt":  f"https://www.producthunt.com/@{username}",
            "Replit":       f"https://replit.com/@{username}",
            "Codepen":      f"https://codepen.io/{username}",
            "Behance":      f"https://www.behance.net/{username}",
            "Dribbble":     f"https://dribbble.com/{username}",
            "Fiverr":       f"https://www.fiverr.com/{username}",
            "Gravatar":     f"https://en.gravatar.com/{username}",
        }

        found = []
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {
                executor.submit(requests.get, url,
                                headers=HEADERS, timeout=5): (site, url)
                for site, url in sites.items()
            }
            for future in as_completed(futures):
                site, url = futures[future]
                try:
                    r = future.result()
                    if r.status_code == 200:
                        found.append({"site": site, "url": url})
                except:
                    pass

        return {"username": username, "found": found, "count": len(found)}

    # ─── EMAIL INFO ───────────────────────────────────────────────
    def _search_email_info(self, query: str) -> dict:
        """Extrait des infos depuis un email."""
        if "@" not in query:
            return {"skipped": "Pas un email"}

        parts  = query.split("@")
        domain = parts[1] if len(parts) > 1 else ""
        user   = parts[0]

        # Infos sur le domaine
        domain_info = {"domain": domain}
        try:
            r = requests.get(f"https://ipapi.co/{domain}/json/", timeout=5)
            if r.status_code == 200:
                domain_info["location"] = r.json().get("country_name", "")
        except:
            pass

        # Patterns courants dans le username
        patterns = []
        if "." in user:
            p = user.split(".")
            patterns.append(f"Format probable : {p[0].capitalize()} {p[-1].capitalize()}")
        if "_" in user:
            p = user.split("_")
            patterns.append(f"Format probable : {p[0].capitalize()} {p[-1].capitalize()}")

        return {
            "email":      query,
            "username":   user,
            "domain":     domain,
            "patterns":   patterns,
            "search_urls": [
                f"https://www.google.com/search?q=%22{query}%22",
                f"https://www.google.com/search?q=%22{user}%22+site:linkedin.com",
            ]
        }

    # ─── PHONE INFO ───────────────────────────────────────────────
    def _search_phone(self, query: str) -> dict:
        """Recherche d'infos sur un numéro de téléphone."""
        cleaned = re.sub(r'[\s\-().+]', '', query)
        if not cleaned.isdigit() or len(cleaned) < 7:
            return {"skipped": "Pas un numéro valide"}

        return {
            "number":       query,
            "cleaned":      cleaned,
            "search_urls": [
                f"https://www.google.com/search?q=%22{query}%22",
                f"https://www.truecaller.com/search/fr/{cleaned}",
                f"https://www.pagesjaunes.fr/pagesblanches/recherche?quoiqui={cleaned}",
                f"https://sync.me/search/?number={cleaned}",
            ],
            "note": "Vérification manuelle recommandée sur ces sources"
        }

    # ─── RÉSUMÉ ───────────────────────────────────────────────────
    def _build_summary(self, results: dict) -> dict:
        social = results["sources"].get("social_networks", {})
        found  = social.get("found", [])
        breaches = results["sources"].get("data_breaches", {})
        username = results["sources"].get("username_check", {})

        total_profiles = len(found) + len(username.get("found", []))
        is_breached    = breaches.get("breached", False)

        risk = "Faible"
        if is_breached and total_profiles > 5:  risk = "Élevé"
        elif is_breached or total_profiles > 3: risk = "Moyen"

        return {
            "profiles_found":   total_profiles,
            "social_platforms": [p["platform"] for p in found],
            "data_breaches":    breaches.get("count", 0) if is_breached else 0,
            "exposure_risk":    risk,
            "query_type":       results["query_type"]
        }