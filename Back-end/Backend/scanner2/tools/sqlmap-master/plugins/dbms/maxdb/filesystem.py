from lib.core.exception import SqlmapUnsupportedFeatureException
from plugins.generic.filesystem import Filesystem as GenericFilesystem

class Filesystem(GenericFilesystem):
    def readFile(self, remoteFile):
        errMsg = "on SAP MaxDB reading of files is not supported"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def writeFile(self, localFile, remoteFile, fileType=None, forceCheck=False):
        errMsg = "on SAP MaxDB writing of files is not supported"
        raise SqlmapUnsupportedFeatureException(errMsg)
