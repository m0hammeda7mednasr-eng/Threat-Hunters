from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOWEST

def dependencies():
    pass

def tamper(payload, **kwargs):

    return payload.replace('\'', "%EF%BC%87") if payload else payload
