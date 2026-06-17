import random
import string

from lib.core.compat import xrange
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def tamper(payload, **kwargs):

    retVal = ""

    if payload:
        for i in xrange(len(payload)):
            if payload[i].isspace():
                randomStr = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in xrange(random.randint(6, 12)))
                retVal += "--%s%%0A" % randomStr
            elif payload[i] == '#' or payload[i:i + 3] == '-- ':
                retVal += payload[i:]
                break
            else:
                retVal += payload[i]

    return retVal
