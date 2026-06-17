import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
    pass

def tamper(payload, **kwargs):

    return re.sub(r"(?i)(\d+)\s+(UNION )", r"\g<1>e0\g<2>", payload) if payload else payload
