"""Wordlist cracking profiles for the Password Analysis module.

Each profile maps to a real SecLists file stored under
``src/cracker/wordlists/``.  High-level modules reference
profiles by their key string (``"quick"``, ``"common"``,
``"breach"``).  Never reference file paths outside this module.
"""

import os
from typing import Any

# Absolute path to the wordlists directory (sibling of this file)
_WORDLISTS_DIR = os.path.join(os.path.dirname(__file__), "wordlists")

# ── Profile definitions ────────────────────────────────────────────────

PROFILES: dict[str, dict[str, Any]] = {
    "quick": {
        "key":         "quick",
        "name":        "Quick Demo",
        "filename":    "500-worst-passwords.txt",
        "candidates":  499,          # actual line count
        "description": (
            "The 500 most notoriously weak passwords. Designed for "
            "instant cracking of extremely common credentials. If your "
            "password is here, it will crack in seconds."
        ),
        "runtime_hint": "~seconds",
        "color":        "green",
        "examples":     ["123456", "password", "qwerty", "admin123"],
    },
    "common": {
        "key":         "common",
        "name":        "Common Passwords",
        "filename":    "10k-most-common.txt",
        "candidates":  10000,
        "description": (
            "Top 10,000 passwords from real-world breach data. Covers "
            "the vast majority of consumer passwords. Simulates a "
            "realistic first-pass dictionary attack."
        ),
        "runtime_hint": "~seconds to a few minutes per account",
        "color":        "orange",
        "examples":     ["Password1", "Welcome123", "Summer2024"],
    },
    "breach": {
        "key":         "breach",
        "name":        "Real Breach Dataset",
        "filename":    "100k-most-used-passwords-NCSC.txt",
        "candidates":  99840,        # actual line count
        "description": (
            "100,000 passwords from real data breaches (NCSC). The "
            "most realistic simulation of an offline attack. Weak or "
            "common passwords will crack; strong unique ones survive."
        ),
        "runtime_hint": "several minutes per account (bcrypt cost=12)",
        "color":        "red",
        "examples":     ["Monday1!", "P@ssw0rd1", "Letmein1"],
    },
}

DEFAULT_PROFILE = "quick"


def profile_path(key: str) -> str:
    """Return the absolute path to a profile's wordlist file.

    Args:
        key: Profile key — one of ``"quick"``, ``"common"``,
             ``"breach"``.

    Returns:
        Absolute path string to the ``.txt`` file.

    Raises:
        KeyError:   If ``key`` is not a known profile.
        FileNotFoundError: If the wordlist file is missing on disk.
    """
    if key not in PROFILES:
        raise KeyError(
            f"Unknown profile '{key}'. "
            f"Valid profiles: {list(PROFILES)}"
        )
    filename = PROFILES[key]["filename"]
    path = os.path.join(_WORDLISTS_DIR, filename)
    if not os.path.isfile(path):
        raise FileNotFoundError(
            f"Wordlist file not found: {path}. "
            f"Ensure SecLists files are present in "
            f"src/cracker/wordlists/."
        )
    return path


def iter_wordlist(key: str):
    """Yield candidate passwords from a profile's wordlist file.

    Reads the file line-by-line (memory-efficient for 100k entries).
    Strips whitespace and skips blank lines and comment lines.

    Args:
        key: Profile key.

    Yields:
        Candidate password strings.

    Raises:
        KeyError:   If ``key`` is not a known profile.
        FileNotFoundError: If the wordlist file is missing.
    """
    path = profile_path(key)
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            candidate = line.rstrip("\n\r")
            if candidate and not candidate.startswith("#"):
                yield candidate


def count_wordlist(key: str) -> int:
    """Count actual non-empty, non-comment lines in a wordlist file.

    Args:
        key: Profile key.

    Returns:
        Integer line count.
    """
    return sum(1 for _ in iter_wordlist(key))


def profiles_metadata() -> list[dict[str, Any]]:
    """Return a JSON-serialisable list of all profile descriptors.

    Returns:
        List of dicts suitable for the ``/api/crack/profiles`` endpoint.
    """
    return [
        {
            "key":          p["key"],
            "name":         p["name"],
            "candidates":   p["candidates"],
            "description":  p["description"],
            "runtime_hint": p["runtime_hint"],
            "color":        p["color"],
            "examples":     p["examples"],
        }
        for p in PROFILES.values()
    ]
