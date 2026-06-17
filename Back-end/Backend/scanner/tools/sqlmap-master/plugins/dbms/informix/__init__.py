from lib.core.enums import DBMS
from lib.core.settings import INFORMIX_SYSTEM_DBS
from lib.core.unescaper import unescaper

from plugins.dbms.informix.enumeration import Enumeration
from plugins.dbms.informix.filesystem import Filesystem
from plugins.dbms.informix.fingerprint import Fingerprint
from plugins.dbms.informix.syntax import Syntax
from plugins.dbms.informix.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class InformixMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):

    def __init__(self):
        self.excludeDbsList = INFORMIX_SYSTEM_DBS

        for cls in self.__class__.__bases__:
            cls.__init__(self)

    unescaper[DBMS.INFORMIX] = Syntax.escape
