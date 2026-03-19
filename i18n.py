"""
Lightweight JSON-based i18n.
French is the source language (no lookup needed).
English translations live in translations/en.json.
"""
import json
import os
import threading

_DIR = os.path.join(os.path.dirname(__file__), "translations")
_cache: dict[str, dict] = {}
_lock = threading.Lock()


def _load(lang: str) -> dict:
    path = os.path.join(_DIR, f"{lang}.json")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return {}


def _get(lang: str) -> dict:
    with _lock:
        if lang not in _cache:
            _cache[lang] = _load(lang)
        return _cache[lang]


def translate(text: str, lang: str = "fr") -> str:
    """Return translated string, falling back to source text."""
    if not text or lang == "fr":
        return text
    return _get(lang).get(text, text)
