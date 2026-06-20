import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOWEST

def dependencies():
    pass

def tamper(payload, **kwargs):

    retVal = payload

    if payload:
        retVal = re.sub(r"(?i)\bAND\b", "%26%26", re.sub(r"(?i)\bOR\b", "%7C%7C", payload))

    return retVal
