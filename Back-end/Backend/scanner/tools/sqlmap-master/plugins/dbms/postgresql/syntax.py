from lib.core.convert import getOrds
from plugins.generic.syntax import Syntax as GenericSyntax

class Syntax(GenericSyntax):
    @staticmethod
    def escape(expression, quote=True):

        def escaper(value):
            return "(%s)" % "||".join("CHR(%d)" % _ for _ in getOrds(value))  # Postgres CHR() function already accepts Unicode code point of character(s)

        return Syntax._escape(expression, quote, escaper)
