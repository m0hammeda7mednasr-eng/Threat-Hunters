import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def tamper(payload, **kwargs):

    retVal = payload

    if payload:
        retVal = re.sub(r"(?i)(information_schema)\.", r"\g<1>/**/.", payload)

    return retVal
