from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getPasswordHashes(self):
        warnMsg = "on ClickHouse it is not possible to enumerate the user password hashes"
        logger.warning(warnMsg)

        return {}

    def getRoles(self, *args, **kwargs):
        warnMsg = "on ClickHouse it is not possible to enumerate the user roles"
        logger.warning(warnMsg)

        return {}
