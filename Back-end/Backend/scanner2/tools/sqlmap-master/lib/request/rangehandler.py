from lib.core.exception import SqlmapConnectionException
from thirdparty.six.moves import urllib as _urllib

class HTTPRangeHandler(_urllib.request.BaseHandler):

    def http_error_206(self, req, fp, code, msg, hdrs):
        r = _urllib.response.addinfourl(fp, hdrs, req.get_full_url())
        r.code = code
        r.msg = msg
        return r

    def http_error_416(self, req, fp, code, msg, hdrs):
        errMsg = "there was a problem while connecting "
        errMsg += "target ('416 - Range Not Satisfiable')"
        raise SqlmapConnectionException(errMsg)
