from lib.core.data import logger

from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getHostname(self):
        warnMsg = "on PostgreSQL it is not possible to enumerate the hostname"
        logger.warning(warnMsg)
