"""Factory for CrackerPort implementations.

All callers obtain a CrackerPort through this module.
Never instantiate WordlistCracker directly outside this file.
"""

from src.cracker.base import CrackerPort
from src.cracker.wordlist_cracker import WordlistCracker


def create_cracker() -> CrackerPort:
    """Return the default CrackerPort implementation.

    Returns:
        A WordlistCracker instance wrapped as CrackerPort.
    """
    return WordlistCracker()
