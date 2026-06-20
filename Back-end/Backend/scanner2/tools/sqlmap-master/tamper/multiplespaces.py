import random
import re

from lib.core.data import kb
from lib.core.datatype import OrderedSet
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):

    retVal = payload

    if payload:
        words = OrderedSet()

        for match in re.finditer(r"\b[A-Za-z_]+\b", payload):
            word = match.group()

            if word.upper() in kb.keywords:
                words.add(word)

        for word in words:
            retVal = re.sub(r"(?<=\W)%s(?=[^A-Za-z_(]|\Z)" % word, "%s%s%s" % (' ' * random.randint(1, 4), word, ' ' * random.randint(1, 4)), retVal)
            retVal = re.sub(r"(?<=\W)%s(?=[(])" % word, "%s%s" % (' ' * random.randint(1, 4), word), retVal)

    return retVal
