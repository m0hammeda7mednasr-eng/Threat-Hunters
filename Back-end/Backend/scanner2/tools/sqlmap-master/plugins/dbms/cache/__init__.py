from lib.core.enums import DBMS
from lib.core.settings import CACHE_SYSTEM_DBS
from lib.core.unescaper import unescaper

from plugins.dbms.cache.enumeration import Enumeration
from plugins.dbms.cache.filesystem import Filesystem
from plugins.dbms.cache.fingerprint import Fingerprint
from plugins.dbms.cache.syntax import Syntax
from plugins.dbms.cache.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class CacheMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):

    def __init__(self):
        self.excludeDbsList = CACHE_SYSTEM_DBS

        for cls in self.__class__.__bases__:
            cls.__init__(self)

    unescaper[DBMS.CACHE] = Syntax.escape
