from lib.core.convert import getOrds
from plugins.generic.syntax import Syntax as GenericSyntax

class Syntax(GenericSyntax):
    @staticmethod
    def escape(expression, quote=True):

        def escaper(value):
            return "+".join("%s(%d)" % ("CHAR" if _ < 128 else "NCHAR", _) for _ in getOrds(value))

        return Syntax._escape(expression, quote, escaper)
