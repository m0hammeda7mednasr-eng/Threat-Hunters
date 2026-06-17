try:
    import CUBRIDdb
except:
    pass

import logging

from lib.core.common import getSafeExString
from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import SqlmapConnectionException
from plugins.generic.connector import Connector as GenericConnector

class Connector(GenericConnector):

    def connect(self):
        self.initConnection()

        try:
            self.connector = CUBRIDdb.connect(hostname=self.hostname, username=self.user, password=self.password, database=self.db, port=self.port, connect_timeout=conf.timeout)
        except CUBRIDdb.DatabaseError as ex:
            raise SqlmapConnectionException(getSafeExString(ex))

        self.initCursor()
        self.printConnected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except CUBRIDdb.DatabaseError as ex:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % getSafeExString(ex))
            return None

    def execute(self, query):
        try:
            self.cursor.execute(query)
        except CUBRIDdb.DatabaseError as ex:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % getSafeExString(ex))
        except CUBRIDdb.Error as ex:
            raise SqlmapConnectionException(getSafeExString(ex))

        self.connector.commit()

    def select(self, query):
        self.execute(query)
        return self.fetchall()
