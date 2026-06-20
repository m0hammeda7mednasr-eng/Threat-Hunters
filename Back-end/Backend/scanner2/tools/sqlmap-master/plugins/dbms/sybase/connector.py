try:
    import _mssql
    import pymssql
except:
    pass

import logging

from lib.core.common import getSafeExString
from lib.core.convert import getText
from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import SqlmapConnectionException
from plugins.generic.connector import Connector as GenericConnector

class Connector(GenericConnector):

    def connect(self):
        self.initConnection()

        try:
            self.connector = pymssql.connect(host="%s:%d" % (self.hostname, self.port), user=self.user, password=self.password, database=self.db, login_timeout=conf.timeout, timeout=conf.timeout)
        except (pymssql.Error, _mssql.MssqlDatabaseException) as ex:
            raise SqlmapConnectionException(ex)
        except ValueError:
            raise SqlmapConnectionException

        self.initCursor()
        self.printConnected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except (pymssql.Error, _mssql.MssqlDatabaseException) as ex:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) '%s'" % getSafeExString(ex).replace("\n", " "))
            return None

    def execute(self, query):
        retVal = False

        try:
            self.cursor.execute(getText(query))
            retVal = True
        except (pymssql.OperationalError, pymssql.ProgrammingError) as ex:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) '%s'" % getSafeExString(ex).replace("\n", " "))
        except pymssql.InternalError as ex:
            raise SqlmapConnectionException(getSafeExString(ex))

        return retVal

    def select(self, query):
        retVal = None

        if self.execute(query):
            retVal = self.fetchall()

            try:
                self.connector.commit()
            except pymssql.OperationalError:
                pass

        return retVal
