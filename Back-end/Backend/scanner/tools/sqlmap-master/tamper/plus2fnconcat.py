import os
import re

from lib.core.common import singleTimeWarnMessage
from lib.core.common import zeroDepthSearch
from lib.core.compat import xrange
from lib.core.enums import DBMS
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against %s" % (os.path.basename(__file__).split(".")[0], DBMS.MSSQL))

def tamper(payload, **kwargs):

    retVal = payload

    if payload:
        match = re.search(r"('[^']+'|CHAR\(\d+\))\+.*(?<=\+)('[^']+'|CHAR\(\d+\))", retVal)
        if match:
            old = match.group(0)
            parts = []
            last = 0

            for index in zeroDepthSearch(old, '+'):
                parts.append(old[last:index].strip('+'))
                last = index

            parts.append(old[last:].strip('+'))
            replacement = parts[0]

            for i in xrange(1, len(parts)):
                replacement = "{fn CONCAT(%s,%s)}" % (replacement, parts[i])

            retVal = retVal.replace(old, replacement)

    return retVal
