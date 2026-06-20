import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
    pass

def tamper(payload, **kwargs):

    return re.sub(r"(?i)( FROM \w+)\.(\w+)", r"\g<1> 9.e.\g<2>", payload) if payload else payload
