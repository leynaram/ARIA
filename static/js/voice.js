// ── TTS ──────────────────────────────────────────────────────────
function speakText(text) {
  if (!window.speechSynthesis) return;
  window.speechSynthesis.cancel();
  const utterance = new SpeechSynthesisUtterance(text.substring(0, 400));
  utterance.lang = "fr-FR"; utterance.rate = 1.0; utterance.pitch = 1.1;
  const voices = window.speechSynthesis.getVoices();
  const frVoice = voices.find(v => v.lang.startsWith("fr"));
  if (frVoice) utterance.voice = frVoice;
  utterance.onstart = () => setTalking(true);
  utterance.onend   = () => setTalking(false);
  window.speechSynthesis.speak(utterance);
}

// ── STT + enregistrement audio simultané ─────────────────────────
let recognition   = null;
let mediaRecorder = null;
let audioChunks   = [];
let isListening   = false;
let lastAudioBlob = null;  // stocke le dernier audio enregistré

function toggleMic() { isListening ? stopMic() : startMic(); }

async function startMic() {
  const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!SR) { alert("Utilisez Chrome pour la reconnaissance vocale."); return; }

  // Lance la reconnaissance vocale (pour le texte)
  recognition = new SR();
  recognition.lang = "fr-FR";
  recognition.continuous = false;
  recognition.interimResults = true;

  recognition.onstart = () => {
    isListening = true;
    document.getElementById("mic-btn").classList.add("listening");
    document.getElementById("mic-btn").textContent = "🔴";
  };

  recognition.onresult = (e) => {
    document.getElementById("chat-input").value =
      Array.from(e.results).map(r => r[0].transcript).join("");
  };

  recognition.onend = async () => {
    isListening = false;
    document.getElementById("mic-btn").classList.remove("listening");
    document.getElementById("mic-btn").textContent = "🎤";

    // Arrête l'enregistrement audio
    if (mediaRecorder && mediaRecorder.state !== "inactive") {
      mediaRecorder.stop();
    }

    const val = document.getElementById("chat-input").value.trim();
    if (val) {
      // Attend que l'audio soit prêt puis envoie
      setTimeout(() => sendMessage(), 300);
    }
  };

  // Lance aussi l'enregistrement audio (pour l'identification vocale)
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    audioChunks = [];
    mediaRecorder = new MediaRecorder(stream, { mimeType: "audio/webm" });
    mediaRecorder.ondataavailable = e => { if (e.data.size > 0) audioChunks.push(e.data); };
    mediaRecorder.onstop = () => {
      lastAudioBlob = new Blob(audioChunks, { type: "audio/webm" });
      stream.getTracks().forEach(t => t.stop());
    };
    mediaRecorder.start();
  } catch(e) {
    console.warn("Micro non disponible pour l'identification:", e.message);
  }

  recognition.start();
}

function stopMic() {
  if (recognition) recognition.stop();
  if (mediaRecorder && mediaRecorder.state !== "inactive") mediaRecorder.stop();
  isListening = false;
}

// ── Envoi du message avec audio si disponible ────────────────────
async function sendMessageWithVoice(message) {
  if (lastAudioBlob) {
    // Envoie avec FormData (texte + audio)
    const formData = new FormData();
    formData.append("message", message);
    formData.append("audio", lastAudioBlob, "voice.webm");
    lastAudioBlob = null; // reset après envoi

    const res = await fetch("/api/chat", { method: "POST", body: formData });
    return res.json();
  } else {
    // Envoie texte seul (sans audio)
    const res = await fetch("/api/chat", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ message })
    });
    return res.json();
  }
}