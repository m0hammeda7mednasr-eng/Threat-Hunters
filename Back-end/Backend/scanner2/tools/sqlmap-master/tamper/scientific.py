import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
    pass

def tamper(payload, **kwargs):

    if payload:
        payload = re.sub(r"[),.*^/|&]", r" 1.e\g<0>", payload)
        payload = re.sub(r"(\w+)\(", lambda match: "%s 1.e(" % match.group(1) if not re.search(r"(?i)\A(MID|CAST|FROM|COUNT)\Z", match.group(1)) else match.group(0), payload)     # NOTE: MID and CAST don't work for sure

    return payload
