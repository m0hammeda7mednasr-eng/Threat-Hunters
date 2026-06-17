import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
    pass

def tamper(payload, **kwargs):

    retVal = payload

    if payload:
        match = re.search(r"(?i)(\b(AND|OR)\b\s+)([^>]+?)\s*>\s*(\w+|'[^']+')", payload)

        if match:
            _ = "%sGREATEST(%s,%s+1)=%s" % (match.group(1), match.group(3), match.group(4), match.group(3))
            retVal = retVal.replace(match.group(0), _)

    return retVal
