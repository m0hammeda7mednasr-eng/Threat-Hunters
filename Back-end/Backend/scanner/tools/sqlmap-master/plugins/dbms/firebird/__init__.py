from lib.core.enums import DBMS
from lib.core.settings import FIREBIRD_SYSTEM_DBS
from lib.core.unescaper import unescaper
from plugins.dbms.firebird.enumeration import Enumeration
from plugins.dbms.firebird.filesystem import Filesystem
from plugins.dbms.firebird.fingerprint import Fingerprint
from plugins.dbms.firebird.syntax import Syntax
from plugins.dbms.firebird.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class FirebirdMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):

    def __init__(self):
        self.excludeDbsList = FIREBIRD_SYSTEM_DBS

        for cls in self.__class__.__bases__:
            cls.__init__(self)

    unescaper[DBMS.FIREBIRD] = Syntax.escape
