from lib.core.enums import DBMS
from lib.core.settings import CUBRID_SYSTEM_DBS
from lib.core.unescaper import unescaper

from plugins.dbms.cubrid.enumeration import Enumeration
from plugins.dbms.cubrid.filesystem import Filesystem
from plugins.dbms.cubrid.fingerprint import Fingerprint
from plugins.dbms.cubrid.syntax import Syntax
from plugins.dbms.cubrid.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class CubridMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):

    def __init__(self):
        self.excludeDbsList = CUBRID_SYSTEM_DBS

        for cls in self.__class__.__bases__:
            cls.__init__(self)

    unescaper[DBMS.CUBRID] = Syntax.escape
