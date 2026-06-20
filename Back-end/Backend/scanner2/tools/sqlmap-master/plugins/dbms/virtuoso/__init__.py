from lib.core.enums import DBMS
from lib.core.settings import VIRTUOSO_SYSTEM_DBS
from lib.core.unescaper import unescaper
from plugins.dbms.virtuoso.enumeration import Enumeration
from plugins.dbms.virtuoso.filesystem import Filesystem
from plugins.dbms.virtuoso.fingerprint import Fingerprint
from plugins.dbms.virtuoso.syntax import Syntax
from plugins.dbms.virtuoso.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class VirtuosoMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):

    def __init__(self):
        self.excludeDbsList = VIRTUOSO_SYSTEM_DBS

        for cls in self.__class__.__bases__:
            cls.__init__(self)

    unescaper[DBMS.VIRTUOSO] = Syntax.escape
