"""
Internationalization bootstrap using gettext.
Source strings remain in English. Translation live under:
locales/<lang>/LC_MESSAGES/passmanager.mo
"""

from __future__ import annotations

import builtins
import gettext
import locale
from collections.abc import Callable
from pathlib import Path

APP_NAME = "passmanager"
LOCALES_DIR = Path(__file__).parent / "locales"

# This variable will get always point to the current gettext function.
_current_gettext: Callable[[str], str] = gettext.gettext


class LazyTranslator:
    """
    Callable proxy that delegates to the current translator each call.
    """

    def __call__(self, message: str) -> str:
        # Each call is resolved using the current translator.
        return _current_gettext(message)


# Export a single instance. "from i18n import _" will import this.
_ = LazyTranslator()


def setup_language(lang_code: str | None = None):
    """
    Initialize gettext and return (_, resolved_lang_code).

    Args:
        lang_code: Optional language code (e.g., "en", "fr"). If None, detect from OS.

    Returns:
        (_: callable, resolved_lang_code: str)
    """
    global _current_gettext

    if lang_code is None:
        system_locale, _enc = locale.getdefaultlocale() or (None, None)
        lang_code = (system_locale or "en")[:2]

    try:
        translation = gettext.translation(
            APP_NAME,
            localedir=str(LOCALES_DIR),
            languages=[lang_code],
        )
        translator = translation.gettext
        translation.install()  # sets builtins._ as well.
    except FileNotFoundError:
        # Fallback to English (source strings) if translations are missing.
        translator = gettext.gettext
        gettext.install(APP_NAME)

    # update the current translator that the class LazyTranslator will call.
    _current_gettext = translator

    # Keep builtins._ in sync.
    builtins._ = translator

    return _, lang_code
