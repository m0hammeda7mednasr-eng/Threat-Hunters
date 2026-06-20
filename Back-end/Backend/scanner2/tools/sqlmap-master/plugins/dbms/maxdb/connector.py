from lib.core.exception import SqlmapUnsupportedFeatureException
from plugins.generic.connector import Connector as GenericConnector

class Connector(GenericConnector):
    def connect(self):
        errMsg = "on SAP MaxDB it is not (currently) possible to establish a "
        errMsg += "direct connection"
        raise SqlmapUnsupportedFeatureException(errMsg)
