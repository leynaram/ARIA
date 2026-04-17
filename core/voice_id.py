import numpy as np
import tempfile
import os
import librosa

def extract_embedding(audio_bytes: bytes, sample_rate: int = 16000) -> np.ndarray:
    """
    Extrait l'empreinte vocale via MFCC + caractéristiques spectrales.
    Fonctionne sans resemblyzer ni Visual C++.
    """
    with tempfile.NamedTemporaryFile(suffix=".webm", delete=False) as tmp:
        tmp.write(audio_bytes)
        tmp_path = tmp.name

    try:
        y, sr = librosa.load(tmp_path, sr=sample_rate, mono=True)

        # MFCC (timbre de la voix)
        mfcc = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=40)
        mfcc_mean = np.mean(mfcc, axis=1)
        mfcc_std  = np.std(mfcc, axis=1)

        # Chroma (hauteur tonale)
        chroma = librosa.feature.chroma_stft(y=y, sr=sr)
        chroma_mean = np.mean(chroma, axis=1)

        # Spectral contrast
        contrast = librosa.feature.spectral_contrast(y=y, sr=sr)
        contrast_mean = np.mean(contrast, axis=1)

        # Concatène toutes les features
        embedding = np.concatenate([mfcc_mean, mfcc_std, chroma_mean, contrast_mean])

        # Normalise pour la similarité cosinus
        embedding = embedding / (np.linalg.norm(embedding) + 1e-8)
        return embedding

    finally:
        os.unlink(tmp_path)


def compare_embeddings(emb1: np.ndarray, emb2: np.ndarray) -> float:
    """Similarité cosinus entre deux embeddings."""
    return float(np.dot(emb1, emb2) /
                (np.linalg.norm(emb1) * np.linalg.norm(emb2) + 1e-8))