import string

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOWEST

def dependencies():
    pass

def tamper(payload, **kwargs):

    retVal = payload

    if payload:
        retVal = ""
        i = 0

        while i < len(payload):
            if payload[i] == '%' and (i < len(payload) - 2) and payload[i + 1:i + 2] in string.hexdigits and payload[i + 2:i + 3] in string.hexdigits:
                retVal += payload[i:i + 3]
                i += 3
            else:
                retVal += "%%%.2X%%%.2X" % (0xc0 + (ord(payload[i]) >> 6), 0x80 + (ord(payload[i]) & 0x3f))
                i += 1

    return retVal
