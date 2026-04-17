import os
import requests

PROVIDER = os.getenv("AI_PROVIDER", "ollama")

class AIEngine:
    def __init__(self):
        self.provider = PROVIDER
        self.model    = self._get_model()

    def _get_model(self) -> str:
        defaults = {
            "ollama":    os.getenv("OLLAMA_MODEL",    "llama3.2:1b"),
            "openai":    os.getenv("OPENAI_MODEL",    "gpt-4o-mini"),
            "anthropic": os.getenv("ANTHROPIC_MODEL", "claude-3-5-haiku-20241022"),
            "mistral":   os.getenv("MISTRAL_MODEL",   "mistral-small-latest"),
            "groq":      os.getenv("GROQ_MODEL",      "llama-3.3-70b-versatile"),
        }
        return defaults.get(self.provider, "llama3.2:1b")

    def get_info(self) -> dict:
        return {"provider": self.provider, "model": self.model}

    def chat(self, messages: list) -> str:
        handlers = {
            "ollama":    self._call_ollama,
            "openai":    self._call_openai,
            "anthropic": self._call_anthropic,
            "mistral":   self._call_mistral,
            "groq":      self._call_groq,
        }
        fn = handlers.get(self.provider)
        if not fn:
            return f"❌ Provider inconnu : {self.provider}"
        return fn(messages)

    def _call_ollama(self, messages: list) -> str:
        host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        try:
            r = requests.post(f"{host}/api/chat", json={
                "model": self.model, "messages": messages, "stream": False,
                "options": {"num_predict": 1024, "temperature": 0.7, "num_ctx": 4096}
            }, timeout=120)
            d = r.json()
            return d.get("message", {}).get("content") or d.get("response", "Erreur Ollama")
        except requests.exceptions.ConnectionError:
            return "❌ Ollama non disponible. Lancez 'ollama serve'."
        except Exception as e:
            return f"❌ Ollama : {e}"

    def _call_openai(self, messages: list) -> str:
        api_key = os.getenv("OPENAI_API_KEY", "")
        if not api_key:
            return "❌ OPENAI_API_KEY manquante dans .env"
        try:
            r = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={"model": self.model, "messages": messages, "max_tokens": 1024, "temperature": 0.7},
                timeout=60
            )
            return r.json()["choices"][0]["message"]["content"]
        except Exception as e:
            return f"❌ OpenAI : {e}"

    def _call_anthropic(self, messages: list) -> str:
        api_key = os.getenv("ANTHROPIC_API_KEY", "")
        if not api_key:
            return "❌ ANTHROPIC_API_KEY manquante dans .env"
        try:
            system = next((m["content"] for m in messages if m["role"] == "system"), "")
            msgs   = [m for m in messages if m["role"] != "system"]
            r = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": api_key, "anthropic-version": "2023-06-01",
                         "Content-Type": "application/json"},
                json={"model": self.model, "system": system, "messages": msgs, "max_tokens": 1024},
                timeout=60
            )
            return r.json()["content"][0]["text"]
        except Exception as e:
            return f"❌ Anthropic : {e}"

    def _call_mistral(self, messages: list) -> str:
        api_key = os.getenv("MISTRAL_API_KEY", "")
        if not api_key:
            return "❌ MISTRAL_API_KEY manquante dans .env"
        try:
            r = requests.post(
                "https://api.mistral.ai/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={"model": self.model, "messages": messages, "max_tokens": 1024, "temperature": 0.7},
                timeout=60
            )
            return r.json()["choices"][0]["message"]["content"]
        except Exception as e:
            return f"❌ Mistral : {e}"

    def _call_groq(self, messages: list) -> str:
        api_key = os.getenv("GROQ_API_KEY", "")
        if not api_key:
            return "❌ GROQ_API_KEY manquante dans .env"
        try:
            r = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={"model": self.model, "messages": messages, "max_tokens": 1024, "temperature": 0.7},
                timeout=30
            )
            return r.json()["choices"][0]["message"]["content"]
        except Exception as e:
            return f"❌ Groq : {e}"