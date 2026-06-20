from lib.core.common import isDBMSVersionAtLeast
from lib.core.convert import getOrds
from plugins.generic.syntax import Syntax as GenericSyntax

class Syntax(GenericSyntax):
    @staticmethod
    def escape(expression, quote=True):

        def escaper(value):
            return "||".join("ASCII_CHAR(%d)" % _ for _ in getOrds(value))

        retVal = expression

        if isDBMSVersionAtLeast("2.1"):
            retVal = Syntax._escape(expression, quote, escaper)

        return retVal
