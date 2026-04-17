from flask import Flask, request, jsonify, send_from_directory, session, send_file
from flask_cors import CORS
from dotenv import load_dotenv
from datetime import datetime
import os, uuid, io
import numpy as np

# ─── INIT ─────────────────────────────────────────────────────────
load_dotenv()

app = Flask(__name__, static_folder="static")
CORS(app)
app.secret_key = os.getenv("SECRET_KEY", "supersecret_change_moi")

# ─── IMPORTS MÉTIER ───────────────────────────────────────────────
from core.chat          import CyberChatEngine
from core.voice         import speak
from core.voice_id      import extract_embedding
from core.user_profiles import UserProfileManager, ACCESS_LEVELS
from core.audit         import AuditEngine, SecurityAuditEngine
from core.pdf_generator import generate_audit_pdf
from core.self_repair   import (read_file, write_file, apply_patch,
                                 check_syntax, list_project_files,
                                 list_backups, restore_backup)
from core.osint         import OSINTEngine
from core.self_expand   import SelfExpandEngine
from core.ai_engine     import AIEngine
from core.aria_model    import ARIAIntentClassifier
from core.aria_learner  import ARIALearner, ARIAAutoTrainer
from core.network_scanner import NetworkScanner
from integrations       import cloudflare, defender, jira_client

# ─── INSTANCES ────────────────────────────────────────────────────
chat_engine     = CyberChatEngine()
profile_manager = UserProfileManager()
audit_engine    = AuditEngine()
osint_engine    = OSINTEngine()
expand_engine   = SelfExpandEngine()
ai_engine       = AIEngine()
aria_classifier = ARIAIntentClassifier()
learner         = ARIALearner()
auto_trainer    = ARIAAutoTrainer(learner)
net_scanner     = NetworkScanner()

# ─── STATIC ───────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory("static", "index.html")

@app.route("/js/<path:filename>")
def js_files(filename):
    return send_from_directory("static/js", filename)

# ─── HEALTH ───────────────────────────────────────────────────────
@app.route("/api/health")
def health():
    return jsonify({
        "status":   "ok",
        "agent":    "ARIA",
        "version":  "3.0",
        "provider": ai_engine.get_info()
    })

# ─── ENROLLMENT ───────────────────────────────────────────────────
def _handle_enrollment(user_message: str, step: str):
    if step == "ask_name":
        session["enrollment_step"] = "wait_name"
        return {"response": "Je ne vous reconnais pas encore. Quel est votre prénom ?",
                "has_realtime_data": False, "enrollment": True}
    if step == "wait_name":
        session["enrollment_name"] = user_message.strip().capitalize()
        session["enrollment_step"] = "wait_role"
        return {"response": f"Enchanté {session['enrollment_name']} ! Quel est votre poste ?",
                "has_realtime_data": False, "enrollment": True}
    if step == "wait_role":
        session["enrollment_role"] = user_message.strip()
        session["enrollment_step"] = "wait_reason"
        return {"response": "Parfait ! Et pour quelle raison utilisez-vous ARIA ?",
                "has_realtime_data": False, "enrollment": True}
    if step == "wait_reason":
        session["enrollment_reason"] = user_message.strip()
        return _finalize_enrollment()
    return {"response": "Une erreur est survenue.", "has_realtime_data": False}


def _finalize_enrollment():
    first_name = session.get("enrollment_name", "Inconnu")
    role       = session.get("enrollment_role", "Autre")
    reason     = session.get("enrollment_reason", "")
    embedding  = session.get("pending_embedding")

    if embedding:
        user_id = str(uuid.uuid4())[:8]
        profile = profile_manager.enroll(user_id, first_name, role, reason, np.array(embedding))
        session["voice_profile"]   = {k: v for k, v in profile.items() if k != "embedding"}
        session["voice_confirmed"] = True

    for key in ["enrollment_step", "enrollment_name", "enrollment_role",
                "enrollment_reason", "pending_embedding"]:
        session.pop(key, None)

    access_label = ACCESS_LEVELS.get(
        session.get("voice_profile", {}).get("access_level", "guest"), {}
    ).get("label", "Invité")

    return {
        "response": f"Profil créé ! Bienvenue {first_name}, je vous reconnaitrai désormais. Niveau d'accès : **{access_label}**.",
        "has_realtime_data": False,
        "enrollment_complete": True,
        "user": {
            "first_name":   first_name,
            "access_level": session.get("voice_profile", {}).get("access_level", "guest"),
            "access_label": access_label
        }
    }

# ─── CHAT ─────────────────────────────────────────────────────────
@app.route("/api/chat", methods=["POST"])
def chat():
    if request.content_type and "multipart" in request.content_type:
        message    = request.form.get("message", "").strip()
        audio_file = request.files.get("audio")
    else:
        body       = request.json or {}
        message    = body.get("message", "").strip()
        audio_file = None

    if not message:
        return jsonify({"error": "Message vide"}), 400

    voice_profile = session.get("voice_profile")

    # ── Voice ID ──────────────────────────────────────────────────
    if audio_file:
        audio_bytes = audio_file.read()
        try:
            embedding = extract_embedding(audio_bytes)
            profile, score = profile_manager.identify(embedding)
            if profile:
                session["voice_profile"]   = {k: v for k, v in profile.items() if k != "embedding"}
                session["voice_confirmed"] = True
                session.pop("pending_embedding", None)
                session.pop("enrollment_step", None)
                voice_profile = session["voice_profile"]
            else:
                session["pending_embedding"] = embedding.tolist()
                session["voice_confirmed"]   = False
                if "enrollment_step" not in session:
                    session["enrollment_step"] = "ask_name"
        except Exception as e:
            print(f"Erreur voice ID: {e}")

    # ── Enrollment ────────────────────────────────────────────────
    enrollment_step = session.get("enrollment_step")
    if enrollment_step:
        return jsonify(_handle_enrollment(message, enrollment_step))

    msg_lower = message.lower()

    # ── Classification intention ──────────────────────────────────
    try:
        intent_result   = aria_classifier.classify(message)
        detected_intent = intent_result.get("intent", "conversation")
    except:
        detected_intent = "conversation"

    # ── Audit questionnaire en cours ──────────────────────────────
    if session.get("audit_active"):
        msg_clean = message.strip()
        if msg_clean in ["1", "2", "3", "4"]:
            sid    = session.get("session_id", "default")
            result = audit_engine.answer_question(sid, int(msg_clean) - 1)
            if result.get("status") == "completed":
                session["audit_active"] = False
            return jsonify({"response": result.get("message", ""),
                            "has_realtime_data": False, "audit": result})

    # ── Démarrage audit ───────────────────────────────────────────
    if detected_intent == "audit" or any(w in msg_lower for w in [
            "lancer audit", "démarrer audit", "commencer audit",
            "audit de sécurité", "faire un audit"]):
        sid = str(uuid.uuid4())[:8]
        session["session_id"] = sid
        result = audit_engine.start_audit(sid)
        session["audit_active"] = True
        return jsonify({
            "response": "🔍 **Audit lancé !** Répondez avec **1, 2, 3 ou 4**.\n\n" + result.get("message", ""),
            "has_realtime_data": False,
            "audit_started": True
        })

    # ── Self-repair ───────────────────────────────────────────────
    if detected_intent == "self_repair" or any(w in msg_lower for w in [
            "corrige", "répare", "fix", "debug", "erreur dans", "modifie"]):
        project_files = list_project_files()
        result = chat_engine.chat(
            message,
            user_profile=voice_profile,
            extra_context="Fichiers du projet :\n" +
                          "\n".join([f"  - {f['path']} ({f['lines']} lignes)"
                                     for f in project_files if f["exists"]])
        )
        return jsonify(result)

    # ── Auto-expand ───────────────────────────────────────────────
    if any(w in msg_lower for w in ["ajoute", "installe", "nouvelle fonctionnalité",
                                     "améliore toi", "développe", "tu peux faire"]):
        suggestions = expand_engine.propose_features(message)
        result      = chat_engine.chat(
            message,
            user_profile=voice_profile,
            extra_context="Fonctionnalités disponibles :\n" +
                          "\n".join([f"  - [{f['id']}] {f['name']} : {f['description']}"
                                     for f in suggestions])
        )
        result["suggestions"] = suggestions
        return jsonify(result)

    # ── Chat normal ───────────────────────────────────────────────
    result = chat_engine.chat(message, user_profile=voice_profile)
    result["intent"] = detected_intent

    # ── ARIA apprend de la conversation ───────────────────────────
    try:
        learner.learn_from_conversation(
            message,
            result.get("response", ""),
            result.get("intents_detected", [])
        )
    except:
        pass

    return jsonify(result)


@app.route("/api/chat/reset", methods=["POST"])
def reset_chat():
    chat_engine.reset()
    session.pop("audit_active", None)
    return jsonify({"status": "ok"})

# ─── LEARNING ─────────────────────────────────────────────────────
@app.route("/api/learn/feedback", methods=["POST"])
def learn_feedback():
    body     = request.json or {}
    question = body.get("question", "")
    response = body.get("response", "")
    positive = body.get("positive", True)
    user_id  = body.get("user_id", "anonymous")
    result   = learner.record_feedback(question, response, positive, user_id)
    auto_trainer.check_and_retrain()
    return jsonify(result)

@app.route("/api/learn/teach", methods=["POST"])
def learn_teach():
    body    = request.json or {}
    topic   = body.get("topic", "")
    content = body.get("content", "")
    if not topic or not content:
        return jsonify({"error": "topic et content requis"}), 400
    return jsonify(learner.teach(topic, content))

@app.route("/api/learn/stats")
def learn_stats():
    return jsonify(learner.get_stats())

# ─── NETWORK SCANNER ──────────────────────────────────────────────
@app.route("/api/network/scan", methods=["POST"])
def network_scan():
    try:
        result = net_scanner.full_scan()
        if result.get("security", {}).get("issues"):
            learner.auto_learn_threats(result["security"]["issues"])
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/network/last")
def network_last():
    scan = net_scanner.get_last_scan()
    if not scan:
        return jsonify({"error": "Aucun scan disponible"}), 404
    return jsonify(scan)

# ─── AUDIT AUTOMATIQUE ────────────────────────────────────────────
@app.route("/api/audit/run", methods=["POST"])
def run_audit():
    try:
        engine   = SecurityAuditEngine()
        results  = engine.run()
        warnings = []
        raw      = results.get("raw_data", {})
        if "cf_error"   in raw: warnings.append("⚠️ Cloudflare inaccessible")
        if "def_error"  in raw: warnings.append("⚠️ Microsoft Defender inaccessible")
        if "jira_error" in raw: warnings.append("⚠️ Jira inaccessible")
        if warnings:
            results["warnings"] = warnings
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/audit/pdf", methods=["POST"])
def audit_pdf():
    try:
        body    = request.json or {}
        results = body.get("results")
        if not results:
            engine  = SecurityAuditEngine()
            results = engine.run()
        company = body.get("company", "Lemonway")
        pdf     = generate_audit_pdf(results, company_name=company)
        return send_file(
            io.BytesIO(pdf),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"audit_securite_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/audit/start", methods=["POST"])
def audit_start():
    body      = request.json or {}
    framework = body.get("framework", "complet")
    sid       = session.get("session_id", "default")
    result    = audit_engine.start_audit(sid, framework)
    session["audit_active"] = True
    return jsonify(result)

@app.route("/api/audit/answer", methods=["POST"])
def audit_answer():
    body         = request.json or {}
    answer_index = int(body.get("answer", 0)) - 1
    sid          = session.get("session_id", "default")
    result       = audit_engine.answer_question(sid, answer_index)
    if result.get("status") == "completed":
        session["audit_active"] = False
        session["last_report"]  = result.get("report")
    return jsonify(result)

@app.route("/api/audit/status")
def audit_status():
    sid = session.get("session_id", "default")
    return jsonify(audit_engine.get_status(sid))

# ─── SELF-REPAIR ──────────────────────────────────────────────────
@app.route("/api/repair/files")
def repair_list_files():
    return jsonify({"files": list_project_files()})

@app.route("/api/repair/read", methods=["POST"])
def repair_read():
    body = request.json or {}
    return jsonify(read_file(body.get("path", "")))

@app.route("/api/repair/check", methods=["POST"])
def repair_check():
    body = request.json or {}
    return jsonify(check_syntax(body.get("code", ""), body.get("filename", "unknown.py")))

@app.route("/api/repair/write", methods=["POST"])
def repair_write():
    body    = request.json or {}
    path    = body.get("path", "")
    content = body.get("content", "")
    if not path or not content:
        return jsonify({"error": "path et content requis"}), 400
    return jsonify(write_file(path, content))

@app.route("/api/repair/patch", methods=["POST"])
def repair_patch():
    body = request.json or {}
    path = body.get("path", "")
    old  = body.get("old", "")
    new  = body.get("new", "")
    if not all([path, old, new]):
        return jsonify({"error": "path, old et new requis"}), 400
    return jsonify(apply_patch(path, old, new))

@app.route("/api/repair/backups")
def repair_backups():
    return jsonify({"backups": list_backups(request.args.get("path"))})

@app.route("/api/repair/restore", methods=["POST"])
def repair_restore():
    body = request.json or {}
    return jsonify(restore_backup(body.get("backup_path", ""), body.get("path", "")))

@app.route("/api/repair/restart", methods=["POST"])
def repair_restart():
    import threading, signal
    def _restart():
        import time; time.sleep(1)
        os.kill(os.getpid(), signal.SIGTERM)
    threading.Thread(target=_restart, daemon=True).start()
    return jsonify({"status": "ok", "message": "Redémarrage dans 1 seconde..."})

# ─── SELF-EXPAND ──────────────────────────────────────────────────
@app.route("/api/expand/list")
def expand_list():
    return jsonify({"features": expand_engine.list_available()})

@app.route("/api/expand/install", methods=["POST"])
def expand_install():
    body       = request.json or {}
    feature_id = body.get("feature_id", "")
    if not feature_id:
        return jsonify({"error": "feature_id requis"}), 400
    return jsonify(expand_engine.install_feature(feature_id))

@app.route("/api/expand/propose", methods=["POST"])
def expand_propose():
    body = request.json or {}
    return jsonify({"suggestions": expand_engine.propose_features(body.get("request", ""))})

# ─── AI MODEL ─────────────────────────────────────────────────────
@app.route("/api/model/classify", methods=["POST"])
def model_classify():
    body = request.json or {}
    return jsonify(aria_classifier.classify(body.get("text", "")))

@app.route("/api/model/retrain", methods=["POST"])
def model_retrain():
    body = request.json or {}
    return jsonify(aria_classifier.retrain(body.get("examples", [])))

@app.route("/api/model/info")
def model_info():
    return jsonify({
        "ai_provider": ai_engine.get_info(),
        "custom_model": {
            "trained":  aria_classifier.trained,
            "intents":  aria_classifier.INTENTS,
            "examples": len(aria_classifier.TRAINING_DATA)
        }
    })

@app.route("/api/model/switch", methods=["POST"])
def model_switch():
    body     = request.json or {}
    provider = body.get("provider", "")
    model    = body.get("model", "")
    if provider:
        os.environ["AI_PROVIDER"] = provider
    if model:
        os.environ[f"{provider.upper()}_MODEL"] = model
    return jsonify({"status": "ok",
                    "message": f"Provider changé → {provider} / {model}",
                    "restart_required": True})

# ─── OSINT ────────────────────────────────────────────────────────
@app.route("/api/osint/search", methods=["POST"])
def osint_search():
    body  = request.json or {}
    query = body.get("query", "").strip()
    if not query:
        return jsonify({"error": "Query requise"}), 400
    try:
        return jsonify(osint_engine.search_person(query))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─── VOICE ────────────────────────────────────────────────────────
@app.route("/api/voice/speak", methods=["POST"])
def voice_speak():
    body = request.json or {}
    text = body.get("text", "")
    if text:
        speak(text[:500])
    return jsonify({"status": "ok"})

@app.route("/api/voice/profiles", methods=["GET"])
def list_voice_profiles():
    return jsonify({"profiles": profile_manager.list_profiles()})

@app.route("/api/voice/profiles/<user_id>", methods=["DELETE"])
def delete_voice_profile(user_id):
    if profile_manager.delete_profile(user_id):
        return jsonify({"status": "deleted"})
    return jsonify({"error": "Profil introuvable"}), 404

# ─── CLOUDFLARE ───────────────────────────────────────────────────
@app.route("/api/cloudflare/events")
def cf_events():
    return jsonify(cloudflare.get_firewall_events())

@app.route("/api/cloudflare/ddos")
def cf_ddos():
    return jsonify(cloudflare.get_ddos_status())

@app.route("/api/cloudflare/analytics")
def cf_analytics():
    return jsonify(cloudflare.get_analytics())

@app.route("/api/cloudflare/waf")
def cf_waf():
    return jsonify(cloudflare.get_waf_rules())

# ─── DEFENDER ─────────────────────────────────────────────────────
@app.route("/api/defender/alerts")
def def_alerts():
    return jsonify(defender.get_alerts())

@app.route("/api/defender/score")
def def_score():
    return jsonify(defender.get_secure_score())

@app.route("/api/defender/vulnerabilities")
def def_vulns():
    return jsonify(defender.get_vulnerabilities())

# ─── JIRA ─────────────────────────────────────────────────────────
@app.route("/api/jira/tickets")
def jira_tickets():
    return jsonify(jira_client.get_security_tickets())

@app.route("/api/jira/create", methods=["POST"])
def jira_create():
    body = request.json or {}
    return jsonify(jira_client.create_security_incident(
        title=body.get("title", "Incident"),
        description=body.get("description", ""),
        severity=body.get("severity", "High")
    ))

@app.route("/api/jira/update/<ticket_id>", methods=["POST"])
def jira_update(ticket_id):
    body = request.json or {}
    return jsonify(jira_client.update_ticket(
        ticket_id,
        comment=body.get("comment", ""),
        transition=body.get("transition")
    ))

# ─── DASHBOARD ────────────────────────────────────────────────────
@app.route("/api/dashboard")
def dashboard():
    return jsonify({
        "cloudflare":     cloudflare.get_analytics(),
        "defender_score": defender.get_secure_score(),
        "alerts_count":   defender.get_alerts(5),
        "open_tickets":   jira_client.get_security_tickets(limit=5)
    })

# ─── ENTRYPOINT ───────────────────────────────────────────────────
if __name__ == "__main__":
    print("🛡️  ARIA CyberAI v3.0 démarré sur http://0.0.0.0:5000")
    print(f"🤖 Provider IA : {ai_engine.get_info()['provider']} / {ai_engine.get_info()['model']}")
    app.run(host="0.0.0.0", port=5000, debug=False)