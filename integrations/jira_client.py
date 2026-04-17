from jira import JIRA
import os
from datetime import datetime

def get_client():
    return JIRA(
        server=os.getenv("JIRA_URL"),
        basic_auth=(os.getenv("JIRA_EMAIL"), os.getenv("JIRA_API_TOKEN"))
    )

def create_security_incident(title: str, description: str, severity: str = "High"):
    """Crée un ticket d'incident de sécurité dans Jira."""
    try:
        jira = get_client()
        priority_map = {"Critical": "Highest", "High": "High", "Medium": "Medium", "Low": "Low"}
        issue = jira.create_issue(
            project=os.getenv("JIRA_PROJECT_KEY", "SEC"),
            summary=f"[SECURITY] {title}",
            description=f"**Incident détecté par CyberAI**\n\n{description}\n\n_Créé automatiquement le {datetime.now().strftime('%d/%m/%Y %H:%M')}_",
            issuetype={"name": "Bug"},
            priority={"name": priority_map.get(severity, "High")},
            labels=["cybersecurity", "auto-detected"]
        )
        return {
            "status": "ok",
            "ticket_id": issue.key,
            "url": f"{os.getenv('JIRA_URL')}/browse/{issue.key}"
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

def get_security_tickets(status: str = "Open", limit: int = 10):
    """Récupère les tickets de sécurité ouverts."""
    try:
        jira = get_client()
        project = os.getenv("JIRA_PROJECT_KEY", "SEC")
        jql = f'project = {project} AND labels = "cybersecurity" AND status != "Done" ORDER BY priority DESC'
        issues = jira.search_issues(jql, maxResults=limit)
        return {
            "status": "ok",
            "count": len(issues),
            "tickets": [
                {
                    "id": i.key,
                    "title": i.fields.summary,
                    "status": i.fields.status.name,
                    "priority": i.fields.priority.name,
                    "assignee": str(i.fields.assignee) if i.fields.assignee else "Non assigné",
                    "created": str(i.fields.created)[:10]
                } for i in issues
            ]
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

def update_ticket(ticket_id: str, comment: str, transition: str = None):
    """Ajoute un commentaire et/ou change le statut d'un ticket."""
    try:
        jira = get_client()
        issue = jira.issue(ticket_id)
        jira.add_comment(issue, f"[CyberAI] {comment}")
        if transition:
            transitions = jira.transitions(issue)
            for t in transitions:
                if t["name"].lower() == transition.lower():
                    jira.transition_issue(issue, t["id"])
                    break
        return {"status": "ok", "ticket_id": ticket_id}
    except Exception as e:
        return {"status": "error", "message": str(e)}