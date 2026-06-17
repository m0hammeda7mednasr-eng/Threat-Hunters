import re

from lib.core.common import randomRange
from lib.core.compat import xrange
from lib.core.data import kb
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):

    retVal = payload

    if payload:
        for match in re.finditer(r"\b[A-Za-z_]{2,}\b", retVal):
            word = match.group()

            if (word.upper() in kb.keywords and re.search(r"(?i)[`\"'\[]%s[`\"'\]]" % word, retVal) is None) or ("%s(" % word) in payload:
                while True:
                    _ = ""

                    for i in xrange(len(word)):
                        _ += word[i].upper() if randomRange(0, 1) else word[i].lower()

                    if len(_) > 1 and _ not in (_.lower(), _.upper()):
                        break

                retVal = retVal.replace(word, _)

    return retVal
