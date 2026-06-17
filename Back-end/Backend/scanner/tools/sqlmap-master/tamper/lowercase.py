import re

from lib.core.data import kb
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):

    retVal = payload

    if payload:
        for match in re.finditer(r"\b[A-Za-z_]+\b", retVal):
            word = match.group()

            if word.upper() in kb.keywords:
                retVal = retVal.replace(word, word.lower())

    return retVal
