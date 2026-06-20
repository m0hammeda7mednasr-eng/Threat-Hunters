from lib.core.convert import getText
from thirdparty.six.moves import urllib as _urllib

class MethodRequest(_urllib.request.Request):

    def set_method(self, method):
        self.method = getText(method.upper())  # Dirty hack for Python3 (may it rot in hell!)

    def get_method(self):
        return getattr(self, 'method', _urllib.request.Request.get_method(self))
