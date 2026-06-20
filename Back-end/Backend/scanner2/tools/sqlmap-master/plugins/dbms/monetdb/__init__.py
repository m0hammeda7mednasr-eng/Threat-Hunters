from lib.core.enums import DBMS
from lib.core.settings import MONETDB_SYSTEM_DBS
from lib.core.unescaper import unescaper

from plugins.dbms.monetdb.enumeration import Enumeration
from plugins.dbms.monetdb.filesystem import Filesystem
from plugins.dbms.monetdb.fingerprint import Fingerprint
from plugins.dbms.monetdb.syntax import Syntax
from plugins.dbms.monetdb.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class MonetDBMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):

    def __init__(self):
        self.excludeDbsList = MONETDB_SYSTEM_DBS

        for cls in self.__class__.__bases__:
            cls.__init__(self)

    unescaper[DBMS.MONETDB] = Syntax.escape
