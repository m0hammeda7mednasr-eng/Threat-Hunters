from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
    pass

def tamper(payload, **kwargs):

    return payload.replace("UNION ALL SELECT", "UNION SELECT") if payload else payload
