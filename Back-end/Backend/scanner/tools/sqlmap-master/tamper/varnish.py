from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):

    headers = kwargs.get("headers", {})
    headers["X-originating-IP"] = "127.0.0.1"
    return payload
