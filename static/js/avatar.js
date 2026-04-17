// static/js/avatar.js — Version CSS pure, sans canvas

// ─── TALKING ─────────────────────────────────────────────────────
function setTalking(active) {
  const mouth = document.getElementById("mouth");
  const eyes  = document.querySelectorAll(".eye");
  if (!mouth) return;

  if (active) {
    mouth.classList.add("talking");
    eyes.forEach(e => e.style.boxShadow = "0 0 20px var(--accent), 0 0 40px var(--accent)");
  } else {
    mouth.classList.remove("talking");
    eyes.forEach(e => e.style.boxShadow = "0 0 12px var(--accent)");
  }
}

// ─── SCAN LINE COULEUR ────────────────────────────────────────────
function setStatus(msg) {
  const statusEl = document.getElementById("status-text");
  if (statusEl) statusEl.textContent = msg;

  const scanLine = document.querySelector(".scan-line");
  if (!scanLine) return;
  if (msg.includes("réfléchit") || msg.includes("cours")) {
    scanLine.style.background = "rgba(255,200,0,0.25)";
    scanLine.style.animationDuration = "1s";
  } else {
    scanLine.style.background = "rgba(0,212,255,0.15)";
    scanLine.style.animationDuration = "3s";
  }
}

// ─── CLIGNOTEMENT ALÉATOIRE ───────────────────────────────────────
function randomBlink() {
  const eyes = document.querySelectorAll(".eye");
  eyes.forEach(e => {
    e.style.transform = "scaleY(0.05)";
    setTimeout(() => e.style.transform = "scaleY(1)", 120);
  });
  setTimeout(randomBlink, 3000 + Math.random() * 4000);
}

// ─── INIT ─────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  randomBlink();
});