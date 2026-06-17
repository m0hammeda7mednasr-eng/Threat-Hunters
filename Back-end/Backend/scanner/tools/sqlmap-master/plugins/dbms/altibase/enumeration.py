from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getStatements(self):
        warnMsg = "on Altibase it is not possible to enumerate the SQL statements"
        logger.warning(warnMsg)

        return []

    def getHostname(self):
        warnMsg = "on Altibase it is not possible to enumerate the hostname"
        logger.warning(warnMsg)
