# core/self_repair.py
"""
Module de self-repair pour ARIA.
Permet à l'IA de lire, corriger et réécrire ses propres fichiers.
"""

import os
import ast
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

# Fichiers que ARIA peut modifier
ALLOWED_FILES = [
    "app.py",
    "core/chat.py",
    "core/audit.py",
    "core/regulations.py",
    "core/pdf_generator.py",
    "core/self_repair.py",
    "core/voice.py",
    "core/user_profiles.py",
    "integrations/cloudflare.py",
    "integrations/defender.py",
    "integrations/jira_client.py",
    "static/index.html",
    "static/js/avatar.js",
    "static/js/voice.js",
]

BACKUP_DIR = "backups"
BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _full_path(relative_path: str) -> str:
    return os.path.join(BASE_DIR, relative_path)


def list_project_files() -> list:
    """Liste tous les fichiers du projet."""
    files = []
    for f in ALLOWED_FILES:
        full = _full_path(f)
        exists = os.path.exists(full)
        size   = os.path.getsize(full) if exists else 0
        files.append({
            "path":   f,
            "exists": exists,
            "size":   size,
            "lines":  _count_lines(full) if exists else 0
        })
    return files


def read_file(relative_path: str) -> dict:
    """Lit le contenu d'un fichier."""
    if relative_path not in ALLOWED_FILES:
        return {"error": f"Fichier non autorisé : {relative_path}"}
    full = _full_path(relative_path)
    if not os.path.exists(full):
        return {"error": f"Fichier introuvable : {relative_path}"}
    try:
        with open(full, "r", encoding="utf-8") as f:
            content = f.read()
        return {
            "path":    relative_path,
            "content": content,
            "lines":   content.count("\n") + 1,
            "size":    len(content)
        }
    except Exception as e:
        return {"error": str(e)}


def check_syntax(code: str, filename: str = "unknown.py") -> dict:
    """Vérifie la syntaxe Python d'un code."""
    if not filename.endswith(".py"):
        return {"valid": True, "message": "Fichier non-Python, syntaxe non vérifiée"}
    try:
        ast.parse(code)
        return {"valid": True, "message": "Syntaxe Python valide ✓"}
    except SyntaxError as e:
        return {
            "valid":   False,
            "message": f"Erreur de syntaxe ligne {e.lineno} : {e.msg}",
            "line":    e.lineno,
            "detail":  str(e)
        }


def backup_file(relative_path: str) -> dict:
    """Crée une sauvegarde du fichier avant modification."""
    full = _full_path(relative_path)
    if not os.path.exists(full):
        return {"error": "Fichier source introuvable"}

    backup_path = os.path.join(BASE_DIR, BACKUP_DIR)
    os.makedirs(backup_path, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = relative_path.replace("/", "_").replace("\\", "_")
    dest      = os.path.join(backup_path, f"{safe_name}.{timestamp}.bak")

    shutil.copy2(full, dest)
    return {"backup": dest, "status": "ok"}


def write_file(relative_path: str, new_content: str, check: bool = True) -> dict:
    """
    Écrit le contenu corrigé dans un fichier.
    Crée une backup automatique avant toute modification.
    """
    if relative_path not in ALLOWED_FILES:
        return {"error": f"Fichier non autorisé : {relative_path}"}

    # Vérification syntaxe Python
    if check and relative_path.endswith(".py"):
        syntax = check_syntax(new_content, relative_path)
        if not syntax["valid"]:
            return {"error": f"Syntaxe invalide — écriture annulée : {syntax['message']}"}

    # Backup automatique
    bk = backup_file(relative_path)
    if "error" in bk and os.path.exists(_full_path(relative_path)):
        return {"error": f"Backup échoué : {bk['error']}"}

    # Écriture
    full = _full_path(relative_path)
    try:
        with open(full, "w", encoding="utf-8") as f:
            f.write(new_content)
        return {
            "status":  "ok",
            "message": f"✅ Fichier {relative_path} corrigé avec succès",
            "backup":  bk.get("backup", ""),
            "lines":   new_content.count("\n") + 1
        }
    except Exception as e:
        return {"error": str(e)}


def apply_patch(relative_path: str, old_snippet: str, new_snippet: str) -> dict:
    """
    Remplace un extrait de code par un autre dans un fichier.
    Plus sûr que réécrire tout le fichier.
    """
    result = read_file(relative_path)
    if "error" in result:
        return result

    content = result["content"]
    if old_snippet not in content:
        return {"error": "Extrait non trouvé dans le fichier. Vérifiez le code à remplacer."}

    new_content = content.replace(old_snippet, new_snippet, 1)
    return write_file(relative_path, new_content)


def restore_backup(backup_path: str, relative_path: str) -> dict:
    """Restaure un fichier depuis une backup."""
    if not os.path.exists(backup_path):
        return {"error": "Backup introuvable"}
    full = _full_path(relative_path)
    shutil.copy2(backup_path, full)
    return {"status": "ok", "message": f"Fichier {relative_path} restauré depuis {backup_path}"}


def list_backups(relative_path: str = None) -> list:
    """Liste les backups disponibles."""
    backup_path = os.path.join(BASE_DIR, BACKUP_DIR)
    if not os.path.exists(backup_path):
        return []
    backups = []
    for f in sorted(os.listdir(backup_path), reverse=True):
        if relative_path:
            safe = relative_path.replace("/", "_").replace("\\", "_")
            if not f.startswith(safe):
                continue
        backups.append({
            "file":      f,
            "full_path": os.path.join(backup_path, f),
            "size":      os.path.getsize(os.path.join(backup_path, f))
        })
    return backups[:20]


def get_project_summary() -> str:
    """Retourne un résumé du projet pour le contexte ARIA."""
    files = list_project_files()
    summary = "=== STRUCTURE DU PROJET ARIA ===\n"
    for f in files:
        status = f"✓ {f['lines']} lignes" if f["exists"] else "✗ manquant"
        summary += f"  {f['path']:45} {status}\n"
    return summary


def _count_lines(path: str) -> int:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return sum(1 for _ in f)
    except:
        return 0