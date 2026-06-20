import re

from lib.core.data import kb
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):

    def process(match):
        word = match.group('word')
        if word.upper() in kb.keywords:
            return match.group().replace(word, "%s%%09" % word)
        else:
            return match.group()

    retVal = payload

    if payload:
        retVal = re.sub(r"\b(?P<word>[A-Z_]+)(?=[^\w(]|\Z)", process, retVal)
        retVal = re.sub(r"\s*=\s*", " LIKE ", retVal)
        retVal = retVal.replace("%09 ", "%09")

    return retVal
