from thirdparty.six.moves import urllib as _urllib

class SmartHTTPBasicAuthHandler(_urllib.request.HTTPBasicAuthHandler):

    def __init__(self, *args, **kwargs):
        _urllib.request.HTTPBasicAuthHandler.__init__(self, *args, **kwargs)
        self.retried_req = set()
        self.retried_count = 0

    def reset_retry_count(self):
        pass

    def http_error_auth_reqed(self, auth_header, host, req, headers):
        if hash(req) not in self.retried_req:
            self.retried_req.add(hash(req))
            self.retried_count = 0
        else:
            if self.retried_count > 5:
                raise _urllib.error.HTTPError(req.get_full_url(), 401, "basic auth failed", headers, None)
            else:
                self.retried_count += 1

        return _urllib.request.HTTPBasicAuthHandler.http_error_auth_reqed(self, auth_header, host, req, headers)
