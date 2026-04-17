import requests
import os

GRAPH_API = "https://graph.microsoft.com/v1.0"
SECURITY_API = "https://api.securitycenter.microsoft.com/api"

def get_token():
    """Obtient un token OAuth2 Azure AD."""
    tenant = os.getenv("DEFENDER_TENANT_ID")
    url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": os.getenv("DEFENDER_CLIENT_ID"),
        "client_secret": os.getenv("DEFENDER_CLIENT_SECRET"),
        "scope": "https://api.securitycenter.microsoft.com/.default"
    }
    r = requests.post(url, data=data, timeout=10)
    return r.json().get("access_token")

def get_alerts(limit=10):
    """Récupère les alertes de sécurité actives."""
    try:
        token = get_token()
        headers = {"Authorization": f"Bearer {token}"}
        url = f"{SECURITY_API}/alerts?$top={limit}&$filter=status ne 'Resolved'"
        r = requests.get(url, headers=headers, timeout=15)
        data = r.json()
        alerts = data.get("value", [])
        return {
            "status": "ok",
            "count": len(alerts),
            "alerts": [
                {
                    "id": a.get("id"),
                    "title": a.get("title"),
                    "severity": a.get("severity"),
                    "status": a.get("status"),
                    "machine": a.get("computerDnsName"),
                    "category": a.get("category"),
                    "created": a.get("alertCreationTime")
                } for a in alerts
            ]
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

def get_secure_score():
    """Score de sécurité global Microsoft."""
    try:
        token = get_token()
        headers = {"Authorization": f"Bearer {token}"}
        url = f"{SECURITY_API}/configurationScore"
        r = requests.get(url, headers=headers, timeout=15)
        data = r.json()
        score_data = data.get("value", [{}])[0] if data.get("value") else {}
        return {
            "status": "ok",
            "score": score_data.get("score", 0),
            "max": score_data.get("maxScore", 100),
            "percentage": round((score_data.get("score", 0) / max(score_data.get("maxScore", 1), 1)) * 100, 1)
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

def get_vulnerabilities(limit=10):
    """Liste les vulnérabilités critiques."""
    try:
        token = get_token()
        headers = {"Authorization": f"Bearer {token}"}
        url = f"{SECURITY_API}/vulnerabilities?$filter=severity eq 'Critical'&$top={limit}"
        r = requests.get(url, headers=headers, timeout=15)
        data = r.json()
        vulns = data.get("value", [])
        return {
            "status": "ok",
            "count": len(vulns),
            "vulnerabilities": [
                {
                    "id": v.get("id"),
                    "name": v.get("name"),
                    "severity": v.get("severity"),
                    "cvss_score": v.get("cvssV3"),
                    "exposed_machines": v.get("exposedMachinesCount", 0)
                } for v in vulns
            ]
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}