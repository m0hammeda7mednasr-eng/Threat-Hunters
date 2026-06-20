from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGH

def tamper(payload, **kwargs):

    retVal = ""

    if payload:
        retVal = "%s%ssp_password" % (payload, "-- " if not any(_ if _ in payload else None for _ in ('#', "-- ")) else "")

    return retVal
