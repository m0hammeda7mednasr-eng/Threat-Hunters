import os
import re

from lib.core.common import singleTimeWarnMessage
from lib.core.common import zeroDepthSearch
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
            part = match.group(0)

            chars = [char for char in part]
            for index in zeroDepthSearch(part, '+'):
                chars[index] = ','

            replacement = "CONCAT(%s)" % "".join(chars)
            retVal = retVal.replace(part, replacement)

    return retVal
