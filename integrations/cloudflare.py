import requests
import os
from datetime import datetime, timedelta

CF_API = "https://api.cloudflare.com/client/v4"

def get_headers():
    return {
        "Authorization": f"Bearer {os.getenv('CF_API_TOKEN')}",
        "Content-Type": "application/json"
    }

def get_zone_id():
    return os.getenv("CF_ZONE_ID")

def get_firewall_events(limit=20):
    """Récupère les derniers événements firewall."""
    try:
        url = f"{CF_API}/zones/{get_zone_id()}/firewall/events"
        r = requests.get(url, headers=get_headers(), params={"per_page": limit}, timeout=10)
        data = r.json()
        if data.get("success"):
            events = data.get("result", [])
            return {
                "status": "ok",
                "count": len(events),
                "events": [
                    {
                        "action": e.get("action"),
                        "rule_id": e.get("rule_id"),
                        "ip": e.get("ip"),
                        "country": e.get("country"),
                        "timestamp": e.get("occurred_at"),
                        "threat_score": e.get("threat_score", 0)
                    } for e in events
                ]
            }
        return {"status": "error", "message": data.get("errors", "Erreur Cloudflare")}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def get_ddos_status():
    """Vérifie le statut de protection DDoS."""
    try:
        url = f"{CF_API}/zones/{get_zone_id()}/settings/security_level"
        r = requests.get(url, headers=get_headers(), timeout=10)
        data = r.json()
        if data.get("success"):
            level = data["result"]["value"]
            return {"status": "ok", "security_level": level}
        return {"status": "error"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def get_waf_rules(limit=10):
    """Liste les règles WAF actives."""
    try:
        url = f"{CF_API}/zones/{get_zone_id()}/firewall/rules"
        r = requests.get(url, headers=get_headers(), params={"per_page": limit}, timeout=10)
        data = r.json()
        if data.get("success"):
            return {
                "status": "ok",
                "rules": [
                    {
                        "id": rule.get("id"),
                        "description": rule.get("description"),
                        "action": rule.get("action"),
                        "paused": rule.get("paused")
                    } for rule in data.get("result", [])
                ]
            }
        return {"status": "error"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def get_analytics():
    """Statistiques de trafic des dernières 24h."""
    try:
        since = (datetime.utcnow() - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
        url = f"{CF_API}/zones/{get_zone_id()}/analytics/dashboard"
        r = requests.get(url, headers=get_headers(), params={"since": since}, timeout=10)
        data = r.json()
        if data.get("success"):
            totals = data["result"].get("totals", {})
            return {
                "status": "ok",
                "requests": totals.get("requests", {}).get("all", 0),
                "threats": totals.get("threats", {}).get("all", 0),
                "bandwidth_gb": round(totals.get("bandwidth", {}).get("all", 0) / 1e9, 2)
            }
        return {"status": "error"}
    except Exception as e:
        return {"status": "error", "message": str(e)}