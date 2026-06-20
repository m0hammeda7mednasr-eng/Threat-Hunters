from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def dependencies():
    pass

def tamper(payload, **kwargs):

    retVal = payload

    if payload:
        retVal = ""
        i = 0

        while i < len(payload):
            retVal += "&#x%s;" % format(ord(payload[i]), "x")
            i += 1

    return retVal
