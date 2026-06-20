from lib.core.convert import encodeBase64
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def dependencies():
    pass

def tamper(payload, **kwargs):

    return encodeBase64(payload, binary=False) if payload else payload
