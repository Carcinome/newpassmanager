"""
Internationalization bootstrap using gettext.
Source strings remain in English. Translation live under:
locales/<lang>/LC_MESSAGES/passmanager.mo
"""

from __future__ import annotations
import gettext
import locale
import os
from pathlib import Path

APP_NAME = "passmanager"
LOCALES_DIR = Path(__file__).parent / "locales"

def setup_language(lang_code: str | None = None):
    """
    Initialize gettext and return (_, resolved_lang_code).

    Args:
        lang_code: Optional language code (e.g., "en", "fr"). If None, detect from OS.

    Returns:
        (_: callable, resolved_lang_code: str)
    """
    if lang_code is None:
        system_locale, _ = locale.getdefaultlocale() or (None, None)
        lang_code = (system_locale or "en")[:2]

    try:
        translation = gettext.translation(
        APP_NAME,
        localedir=str(LOCALES_DIR),
        languages=[lang_code],
    )
        translation.install() # installs _() globally.
        _ = translation.gettext
    except FileNotFoundError:
        # Fallback to English (source strings) if translations are missing.
        gettext.install(APP_NAME)
        _ = gettext.gettext

    return _, lang_code