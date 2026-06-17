import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):

    retVal = payload

    if payload:
        retVal = re.sub(r"\b(\w+)\(", r"\g<1>/**/(", retVal)

    return retVal
