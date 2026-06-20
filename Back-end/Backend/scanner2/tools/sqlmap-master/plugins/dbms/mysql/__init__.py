from lib.core.enums import DBMS
from lib.core.settings import MYSQL_SYSTEM_DBS
from lib.core.unescaper import unescaper
from plugins.dbms.mysql.enumeration import Enumeration
from plugins.dbms.mysql.filesystem import Filesystem
from plugins.dbms.mysql.fingerprint import Fingerprint
from plugins.dbms.mysql.syntax import Syntax
from plugins.dbms.mysql.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class MySQLMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):

    def __init__(self):
        self.excludeDbsList = MYSQL_SYSTEM_DBS
        self.sysUdfs = {
            "sys_exec": {"return": "int"},
            "sys_eval": {"return": "string"},
            "sys_bineval": {"return": "int"}
        }

        for cls in self.__class__.__bases__:
            cls.__init__(self)

    unescaper[DBMS.MYSQL] = Syntax.escape
