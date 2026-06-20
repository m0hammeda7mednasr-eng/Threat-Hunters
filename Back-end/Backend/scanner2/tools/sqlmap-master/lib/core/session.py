import re

from lib.core.common import Backend
from lib.core.common import Format
from lib.core.common import hashDBWrite
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import HASHDB_KEYS
from lib.core.enums import OS
from lib.core.settings import SUPPORTED_DBMS

def setDbms(dbms):

    hashDBWrite(HASHDB_KEYS.DBMS, dbms)

    _ = "(%s)" % ('|'.join(SUPPORTED_DBMS))
    _ = re.search(r"\A%s( |\Z)" % _, dbms, re.I)

    if _:
        dbms = _.group(1)

    Backend.setDbms(dbms)
    if kb.resolutionDbms:
        hashDBWrite(HASHDB_KEYS.DBMS, kb.resolutionDbms)

    logger.info("the back-end DBMS is %s" % Backend.getDbms())

def setOs():

    infoMsg = ""

    if not kb.bannerFp:
        return

    if "type" in kb.bannerFp:
        Backend.setOs(Format.humanize(kb.bannerFp["type"]))
        infoMsg = "the back-end DBMS operating system is %s" % Backend.getOs()

    if "distrib" in kb.bannerFp:
        kb.osVersion = Format.humanize(kb.bannerFp["distrib"])
        infoMsg += " %s" % kb.osVersion

    if "sp" in kb.bannerFp:
        kb.osSP = int(Format.humanize(kb.bannerFp["sp"]).replace("Service Pack ", ""))

    elif "sp" not in kb.bannerFp and Backend.isOs(OS.WINDOWS):
        kb.osSP = 0

    if Backend.getOs() and kb.osVersion and kb.osSP:
        infoMsg += " Service Pack %d" % kb.osSP

    if infoMsg:
        logger.info(infoMsg)

    hashDBWrite(HASHDB_KEYS.OS, Backend.getOs())
