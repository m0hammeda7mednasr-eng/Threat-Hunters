import binascii

from lib.core.convert import getBytes
from lib.core.convert import getOrds
from lib.core.convert import getUnicode
from plugins.generic.syntax import Syntax as GenericSyntax

class Syntax(GenericSyntax):
    @staticmethod
    def escape(expression, quote=True):

        def escaper(value):
            if all(_ < 128 for _ in getOrds(value)):
                return "0x%s" % getUnicode(binascii.hexlify(getBytes(value)))
            else:
                return "CONVERT(0x%s USING utf8)" % getUnicode(binascii.hexlify(getBytes(value, "utf8")))

        return Syntax._escape(expression, quote, escaper)
