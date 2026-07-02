import os
from typing import Optional


def get_api_key() -> Optional[str]:
    """Return the Gemini API key from environment variable GEMINI_API_KEY."""
    return os.getenv('GEMINI_API_KEY') or os.getenv('GOOGLE_API_KEY')


def get_model_name() -> str:
    """Default model name; can be overridden via GEMINI_MODEL env var."""
    return os.getenv('GEMINI_MODEL', 'gemini-1.5-flash')


def build_generation_config() -> dict:
    """Default generation parameters; override via env variables if needed."""
    def _float(name: str, default: float) -> float:
        try:
            return float(os.getenv(name, default))
        except Exception:
            return default

    def _int(name: str, default: int) -> int:
        try:
            return int(os.getenv(name, default))
        except Exception:
            return default

    return {
        'temperature': _float('GEMINI_TEMPERATURE', 0.2),
        'top_p': _float('GEMINI_TOP_P', 0.9),
        'top_k': _int('GEMINI_TOP_K', 40),
        'max_output_tokens': _int('GEMINI_MAX_TOKENS', 512),
    }
