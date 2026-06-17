from lib.core.convert import getOrds
from plugins.generic.syntax import Syntax as GenericSyntax

class Syntax(GenericSyntax):
    @staticmethod
    def escape(expression, quote=True):

        def escaper(value):
            return "CODE_POINTS_TO_STRING([%s])" % ", ".join(str(_) for _ in getOrds(value))

        return Syntax._escape(expression, quote, escaper)
