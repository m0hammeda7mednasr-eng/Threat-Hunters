from lib.core.exception import SqlmapUnsupportedFeatureException
from plugins.generic.takeover import Takeover as GenericTakeover

class Takeover(GenericTakeover):
    def osCmd(self):
        errMsg = "on eXtremeDB it is not possible to execute commands"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osShell(self):
        errMsg = "on eXtremeDB it is not possible to execute commands"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osPwn(self):
        errMsg = "on eXtremeDB it is not possible to establish an "
        errMsg += "out-of-band connection"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osSmb(self):
        errMsg = "on eXtremeDB it is not possible to establish an "
        errMsg += "out-of-band connection"
        raise SqlmapUnsupportedFeatureException(errMsg)
