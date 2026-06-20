import re

from lib.core.common import isDBMSVersionAtLeast
from lib.core.common import randomStr
from lib.core.convert import getOrds
from plugins.generic.syntax import Syntax as GenericSyntax

class Syntax(GenericSyntax):
    @staticmethod
    def escape(expression, quote=True):

        def escaper(value):
            return "||".join("CHR(%d)" % _ for _ in getOrds(value))

        retVal = expression

        if isDBMSVersionAtLeast("11.70"):
            excluded = {}
            for _ in re.findall(r"DBINFO\([^)]+\)", expression):
                excluded[_] = randomStr()
                expression = expression.replace(_, excluded[_])

            retVal = Syntax._escape(expression, quote, escaper)

            for _ in excluded.items():
                retVal = retVal.replace(_[1], _[0])

        return retVal
