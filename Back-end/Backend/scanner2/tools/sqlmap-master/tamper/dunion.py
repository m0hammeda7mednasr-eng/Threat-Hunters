import os
import re

from lib.core.common import singleTimeWarnMessage
from lib.core.enums import DBMS
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against %s" % (os.path.basename(__file__).split(".")[0], DBMS.ORACLE))

def tamper(payload, **kwargs):

    return re.sub(r"(?i)(\d+)\s+(UNION )", r"\g<1>D\g<2>", payload) if payload else payload
