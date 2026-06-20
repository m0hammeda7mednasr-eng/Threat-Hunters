from lib.core.enums import DBMS
from lib.core.settings import ACCESS_SYSTEM_DBS
from lib.core.unescaper import unescaper
from plugins.dbms.access.enumeration import Enumeration
from plugins.dbms.access.filesystem import Filesystem
from plugins.dbms.access.fingerprint import Fingerprint
from plugins.dbms.access.syntax import Syntax
from plugins.dbms.access.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class AccessMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):

    def __init__(self):
        self.excludeDbsList = ACCESS_SYSTEM_DBS

        for cls in self.__class__.__bases__:
            cls.__init__(self)

    unescaper[DBMS.ACCESS] = Syntax.escape
