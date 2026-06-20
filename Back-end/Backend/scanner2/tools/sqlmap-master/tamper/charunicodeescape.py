import string

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def tamper(payload, **kwargs):

    retVal = payload

    if payload:
        retVal = ""
        i = 0

        while i < len(payload):
            if payload[i] == '%' and (i < len(payload) - 2) and payload[i + 1:i + 2] in string.hexdigits and payload[i + 2:i + 3] in string.hexdigits:
                retVal += "\\u00%s" % payload[i + 1:i + 3]
                i += 3
            else:
                retVal += '\\u%.4X' % ord(payload[i])
                i += 1

    return retVal
