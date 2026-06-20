import os
import re

from lib.core.common import singleTimeWarnMessage
from lib.core.data import kb
from lib.core.enums import DBMS
from lib.core.enums import PRIORITY
from lib.core.settings import IGNORE_SPACE_AFFECTED_KEYWORDS

__priority__ = PRIORITY.HIGHER

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against %s < 5.1" % (os.path.basename(__file__).split(".")[0], DBMS.MYSQL))

def tamper(payload, **kwargs):

    def process(match):
        word = match.group('word')
        if word.upper() in kb.keywords and word.upper() not in IGNORE_SPACE_AFFECTED_KEYWORDS:
            return match.group().replace(word, "/*!0%s" % word)
        else:
            return match.group()

    retVal = payload

    if payload:
        retVal = re.sub(r"(?<=\W)(?P<word>[A-Za-z_]+)(?=\W|\Z)", process, retVal)
        retVal = retVal.replace(" /*!0", "/*!0")

    return retVal
