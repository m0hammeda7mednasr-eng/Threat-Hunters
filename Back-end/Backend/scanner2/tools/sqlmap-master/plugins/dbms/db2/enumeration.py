from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getPasswordHashes(self):
        warnMsg = "on IBM DB2 it is not possible to enumerate password hashes"
        logger.warning(warnMsg)

        return {}

    def getStatements(self):
        warnMsg = "on IBM DB2 it is not possible to enumerate the SQL statements"
        logger.warning(warnMsg)

        return []
