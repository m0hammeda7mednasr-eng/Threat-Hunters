import os

from lib.core.common import randomInt
from lib.core.common import singleTimeWarnMessage
from lib.core.enums import DBMS
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHER

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against %s" % (os.path.basename(__file__).split(".")[0], DBMS.MYSQL))

def tamper(payload, **kwargs):

    retVal = payload

    if payload:
        postfix = ''
        for comment in ('#', '--', '/*'):
            if comment in payload:
                postfix = payload[payload.find(comment):]
                payload = payload[:payload.find(comment)]
                break
        if ' ' in payload:
            retVal = "%s /*!30%s%s*/%s" % (payload[:payload.find(' ')], randomInt(3), payload[payload.find(' ') + 1:], postfix)

    return retVal
