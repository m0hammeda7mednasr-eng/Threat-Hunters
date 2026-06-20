import random
import string
import os

from lib.core.compat import xrange
from lib.core.common import singleTimeWarnMessage
from lib.core.enums import HINT
from lib.core.enums import PRIORITY
from lib.core.settings import DEFAULT_GET_POST_DELIMITER

__priority__ = PRIORITY.HIGHEST

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run on POST requests" % (os.path.basename(__file__).split(".")[0]))

def tamper(payload, **kwargs):

    hints = kwargs.get("hints", {})
    delimiter = kwargs.get("delimiter", DEFAULT_GET_POST_DELIMITER)

    hints[HINT.PREPEND] = delimiter.join("%s=" % "".join(random.sample(string.ascii_letters + string.digits, 2)) for _ in xrange(4194304))

    return payload
