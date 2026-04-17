import pyttsx3
import threading

_engine = None
_lock = threading.Lock()

def get_engine():
    global _engine
    if _engine is None:
        _engine = pyttsx3.init()
        _engine.setProperty("rate", 165)
        _engine.setProperty("volume", 0.9)
        # Voix française si disponible
        voices = _engine.getProperty("voices")
        for v in voices:
            if "french" in v.name.lower() or "fr" in v.id.lower():
                _engine.setProperty("voice", v.id)
                break
    return _engine

def speak(text: str):
    """Synthèse vocale (TTS) du texte."""
    def _run():
        with _lock:
            engine = get_engine()
            engine.say(text)
            engine.runAndWait()
    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return {"status": "speaking"}