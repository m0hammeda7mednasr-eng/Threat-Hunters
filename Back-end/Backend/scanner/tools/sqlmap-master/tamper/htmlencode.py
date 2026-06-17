import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def dependencies():
    pass

def tamper(payload, **kwargs):

    if payload:
        payload = re.sub(r"&#(\d+);", lambda match: chr(int(match.group(1))), payload)      # NOTE: https://github.com/sqlmapproject/sqlmap/issues/5203
        payload = re.sub(r"[^\w]", lambda match: "&#%d;" % ord(match.group(0)), payload)

    return payload
