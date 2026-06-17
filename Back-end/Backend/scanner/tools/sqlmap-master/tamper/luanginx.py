import random
import string

from lib.core.compat import xrange
from lib.core.enums import HINT
from lib.core.enums import PRIORITY
from lib.core.settings import DEFAULT_GET_POST_DELIMITER

__priority__ = PRIORITY.NORMAL

def tamper(payload, **kwargs):

    hints = kwargs.get("hints", {})
    delimiter = kwargs.get("delimiter", DEFAULT_GET_POST_DELIMITER)

    hints[HINT.PREPEND] = delimiter.join("%s=" % "".join(random.sample(string.ascii_letters + string.digits, 2)) for _ in xrange(500))

    return payload
