from lib.core.data import kb
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
    pass

def tamper(payload, **kwargs):

    if payload:
        payload = payload.replace("SLEEP(", "GET_LOCK('%s'," % kb.aliasName)

    return payload
