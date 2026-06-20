from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getRoles(self, *args, **kwargs):
        warnMsg = "on Vertica it is not possible to enumerate the user roles"
        logger.warning(warnMsg)

        return {}
